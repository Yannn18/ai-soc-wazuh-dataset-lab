#!/usr/bin/env python3
import argparse
import hashlib
import ipaddress
import json
import os
import random
import shlex
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

def now_utc():
	return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def load_json(path):
	return json.loads(Path(path).read_text(encoding="utf-8"))

def write_jsonl(path, record):
	p = Path(path)
	p.parent.mkdir(parents=True, exist_ok=True)
	with p.open("a", encoding="utf-8") as f:
		f.write(json.dumps(record, ensure_ascii=False) + "\n")

def append_text(path, text):
	p = Path(path)
	p.parent.mkdir(parents=True, exist_ok=True)
	with p.open("a", encoding="utf-8") as f:
		f.write(text)

def parse_multi_value(value):
	"""Parse comma-separated values into a list, stripping whitespace."""
	if not value:
		return []
	return [v.strip() for v in str(value).split(",") if v.strip()]

def safe_target_check(config):
	lab_cidrs = parse_multi_value(config["lab"].get("lab_cidr", ""))
	target_ips = parse_multi_value(config["lab"].get("target_ip", ""))

	# Validate each target is within at least one lab CIDR
	for target in target_ips:
		try:
			ip = ipaddress.ip_address(target)
			in_cidr = any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in lab_cidrs)
			if not in_cidr and lab_cidrs:
				raise SystemExit(f"[BLOCKED] Target {target} not in any lab CIDR: {lab_cidrs}")
			if not ip.is_private:
				print(f"[WARN] Target {target} is not private IP (use --allow-public-ip if needed)")
		except ValueError:
			raise SystemExit(f"[BLOCKED] Invalid target IP: {target}")

	# Also validate wazuh_server if present
	wazuh_server = config["lab"].get("wazuh_server")
	if wazuh_server:
		try:
			ip = ipaddress.ip_address(wazuh_server)
			if not ip.is_private:
				print(f"[WARN] Wazuh server {wazuh_server} is not private IP")
		except ValueError:
			pass  # Could be hostname

def run_command(command, run_dir, timeout):
	start = now_utc()
	t0 = time.time()

	proc = subprocess.run(
		command,
		shell=True,
		text=True,
		capture_output=True,
		timeout=timeout
	)

	end = now_utc()
	elapsed = round(time.time() - t0, 3)

	append_text(run_dir / "stdout.log", f"\n\n===== COMMAND =====\n{command}\n===== STDOUT =====\n{proc.stdout}\n")
	append_text(run_dir / "stderr.log", f"\n\n===== COMMAND =====\n{command}\n===== STDERR =====\n{proc.stderr}\n")

	return {
		"start_time": start,
		"end_time": end,
		"elapsed_seconds": elapsed,
		"return_code": proc.returncode
	}

def make_run_id():
	stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
	return f"run-{stamp}-{uuid.uuid4().hex[:8]}"

def file_sha256(path):
	p = Path(path)
	if not p.exists():
		return None
	h = hashlib.sha256()
	with p.open("rb") as f:
		for chunk in iter(lambda: f.read(1024 * 1024), b""):
			h.update(chunk)
	return h.hexdigest()

def main():
	parser = argparse.ArgumentParser(description="AI SOC Wazuh dataset orchestrator")
	parser.add_argument("--config", default="configs/orchestrator.json")
	parser.add_argument("--run-root", default="runs")
	parser.add_argument("--shuffle", action="store_true")
	parser.add_argument("--dry-run", action="store_true")
	args = parser.parse_args()

	config = load_json(args.config)
	safe_target_check(config)

	seed = int(config["runtime"].get("seed", 20260624))
	random.seed(seed)

	run_id = make_run_id()
	run_dir = Path(args.run_root) / run_id
	run_dir.mkdir(parents=True, exist_ok=False)

	summary = {
		"run_id": run_id,
		"created_at": now_utc(),
		"config": args.config,
		"seed": seed,
		"dry_run": args.dry_run,
		"status": "running",
		"scenarios": []
	}

	(run_dir / "config_snapshot.json").write_text(
		json.dumps(config, indent=2, ensure_ascii=False),
		encoding="utf-8"
	)

	scenarios = [s for s in config["scenarios"] if s.get("enabled")]
	if args.shuffle:
		random.shuffle(scenarios)

	max_scenarios = int(config["runtime"].get("max_scenarios", 20))
	scenarios = scenarios[:max_scenarios]

	timeout = int(config["runtime"].get("command_timeout_seconds", 300))
	cooldown = int(config["runtime"].get("cooldown_seconds", 30))

	# Parse target IPs for ground truth
	target_ips = parse_multi_value(config["lab"].get("target_ip", ""))
	default_target = target_ips[0] if target_ips else config["lab"].get("target_ip", "")

	for index, scenario in enumerate(scenarios, start=1):
		command = scenario["command"]
		append_text(run_dir / "commands.log", f"{now_utc()} | {scenario['name']} | {command}\n")

		# Determine target host for this scenario
		scenario_target = scenario.get("target") or default_target

		gt = {
			"timestamp": now_utc(),
			"run_id": run_id,
			"scenario_id": scenario["name"],
			"attack_type": scenario["type"],
			"target_host": scenario_target,
			"target_port": "mixed",
			"tool": "orchestrator",
			"payload_id": "from_scenario",
			"intensity": "controlled",
			"expected_label": "benign" if scenario["type"] == "benign" else "malicious",
			"success_status": "dry_run" if args.dry_run else "started",
			"command": command
		}

		write_jsonl(run_dir / "ground_truth.jsonl", gt)

		if args.dry_run:
			result = {
				"start_time": now_utc(),
				"end_time": now_utc(),
				"elapsed_seconds": 0,
				"return_code": 0
			}
		else:
			try:
				result = run_command(command, run_dir, timeout)

			except subprocess.TimeoutExpired:
				result = {
					"start_time": gt["timestamp"],
					"end_time": now_utc(),
					"elapsed_seconds": timeout,
					"return_code": 124,
					"error": "timeout"
				}
				append_text(run_dir / "stderr.log", f"\nTIMEOUT: {command}\n")

		scenario_result = {
			"index": index,
			"name": scenario["name"],
			"type": scenario["type"],
			"command": command,
			"result": result
		}
		summary["scenarios"].append(scenario_result)

		write_jsonl(run_dir / "execution_results.jsonl", scenario_result)

		if result["return_code"] != 0:
			append_text(run_dir / "stderr.log", f"\n[WARN] command returned {result['return_code']}: {command}\n")

		if index < len(scenarios):
			time.sleep(cooldown)

	summary["status"] = "finished"
	summary["finished_at"] = now_utc()

	(run_dir / "summary.json").write_text(
		json.dumps(summary, indent=2, ensure_ascii=False),
		encoding="utf-8"
	)

	md = [
		f"# Evidence Summary",
		"",
		f"- Run ID: `{run_id}`",
		f"- Created at: `{summary['created_at']}`",
		f"- Finished at: `{summary['finished_at']}`",
		f"- Dry run: `{args.dry_run}`",
		f"- Scenario count: `{len(summary['scenarios'])}`",
		"",
		"## Scenario Results"
	]

	for s in summary["scenarios"]:
		md.append(f"- `{s['name']}` → return code `{s['result']['return_code']}`")

	(run_dir / "summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")

	print(json.dumps({
		"run_id": run_id,
		"run_dir": str(run_dir),
		"status": summary["status"]
	}, indent=2, ensure_ascii=False))

if __name__ == "__main__":
	main()

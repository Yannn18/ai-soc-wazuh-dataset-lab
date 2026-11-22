#!/usr/bin/env python3
import argparse
import ipaddress
import json
import os
import shlex
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

LAB_CIDR_DEFAULT = "192.168.56.0/24"

PROFILES = {
	"nmap_light": {
		"tool": "nmap",
		"intensity": "low",
		"expected_label": "recon",
		"command": ["nmap", "-Pn", "--top-ports", "20",
	"-T2"]
	},
	"nmap_service": {
		"tool": "nmap",
		"intensity": "medium",
		"expected_label": "recon",
		"command": ["nmap", "-Pn", "-sV", "--version-light",
		"-T2", "-p", "22,80,443,3000,8080"]
	},
	"nmap_specific_ports": {
		"tool": "nmap",
		"intensity": "low",
		"expected_label": "recon",
		"command": ["nmap", "-Pn", "-p",
		"22,80,443,3000,8080"]
	},
	"nmap_slow": {
		"tool": "nmap",
		"intensity": "low_and_slow",
		"expected_label": "recon",
		"command": ["nmap", "-Pn", "-T1", "--scan-delay",
		"500ms", "-p", "22,80,443,3000,8080"]
	},
	"nmap_noisy_lab": {
		"tool": "nmap",
		"intensity": "noisy_lab",
		"expected_label": "recon",
		"command": ["nmap", "-Pn", "-T3", "--max-retries",
		"2", "-p", "1-1024"]
	},
	"curl_header": {
		"tool": "curl",
		"intensity": "low",
		"expected_label": "web_fingerprint",
		"command": ["curl", "-sS", "-I"]
	},
	"whatweb_light": {
		"tool": "whatweb",
		"intensity": "low",
		"expected_label": "web_fingerprint",
		"command": ["whatweb", "-a", "1"]
	},
	"nikto_light": {
		"tool": "nikto",
		"intensity": "medium",
		"expected_label": "vuln_scan_light",
		"command": ["nikto", "-nointeractive", "-h"]
	},
	"nuclei_info_low": {
		"tool": "nuclei",
		"intensity": "low",
		"expected_label": "vuln_scan_light",
		"command": ["nuclei", "-severity", "info,low",
		"-jsonl", "-u"]
	}
}
def now_utc():
	return datetime.now(timezone.utc).isoformat()

def ensure_private_lab_target(target, lab_cidr):
	parsed = urlparse(target)
	host = parsed.hostname if parsed.hostname else target

	try:
		ip = ipaddress.ip_address(host)
	except ValueError:
		raise SystemExit(f"[BLOCKED] Target harus IP lab, bukan hostname/domain: {target}") 

	network = ipaddress.ip_network(lab_cidr, strict=False)

	if ip not in network:
		raise SystemExit(f"[BLOCKED] Target {ip} di luar LAB_CIDR {lab_cidr}")

	if not ip.is_private:
		raise SystemExit(f"[BLOCKED] Target {ip} bukan private IP")

	return str(ip)

def run_command(cmd, cwd, timeout):
	start = now_utc()
	t0 = time.time()

	proc = subprocess.run(
		cmd,
		cwd=cwd,
		text=True,
		capture_output=True,
		timeout=timeout
	)

	end = now_utc()
	elapsed = round(time.time() - t0, 3)

	return {
		"start_time": start,
		"end_time": end,
		"elapsed_seconds": elapsed,
		"return_code": proc.returncode,
		"stdout": proc.stdout,
		"stderr": proc.stderr
	}

def main():
	parser = argparse.ArgumentParser(description="Safe recon runner for AI SOC Wazuh dataset lab")
	parser.add_argument("--profile", required=True, choices=sorted(PROFILES.keys()))
	parser.add_argument("--target", required=True, help="Target IP or lab URL, e.g. 192.168.56.30 or http://192.168.56.30:3000")
	parser.add_argument("--lab-cidr", default=os.environ.get("LAB_CIDR", LAB_CIDR_DEFAULT))
	parser.add_argument("--output-root", default="logs/recon")
	parser.add_argument("--ground-truth", default="ground-truth/recon.jsonl")
	parser.add_argument("--timeout", type=int, default=300)
	args = parser.parse_args()

	target_ip = ensure_private_lab_target(args.target, args.lab_cidr)
	profile = PROFILES[args.profile]
	run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{args.profile}-{uuid.uuid4().hex[:8]}"
	run_dir = Path(args.output_root) / run_id
	run_dir.mkdir(parents=True, exist_ok=True)

	cmd = list(profile["command"])

	if profile["tool"] == "nmap":
		output_base = run_dir / args.profile
		cmd = cmd + [target_ip, "-oA", str(output_base)]
	elif profile["tool"] == "curl":
		header_file = run_dir / "headers.txt"
		cmd = cmd + [args.target, "-D", str(header_file), "-o", "/dev/null"]
	elif profile["tool"] == "whatweb":
		out_file = run_dir / "whatweb.json"
		cmd = cmd + [args.target, f"--log-json={out_file}"]
	elif profile["tool"] == "nikto":
		out_file = run_dir / "nikto.json"
		cmd = cmd + [args.target, "-o", str(out_file), "-Format", "json"]
	elif profile["tool"] == "nuclei":
		out_file = run_dir / "nuclei.jsonl"
		cmd = cmd + [args.target, "-o", str(out_file)]

	command_text = " ".join(shlex.quote(x) for x in cmd)

	print(f"[RUN] {run_id}")
	print(f"[CMD] {command_text}")

	result = run_command(cmd, cwd=".", timeout=args.timeout)

	(run_dir / "stdout.log").write_text(result["stdout"], encoding="utf-8")
	(run_dir / "stderr.log").write_text(result["stderr"], encoding="utf-8")
	(run_dir / "command.txt").write_text(command_text + "\n", encoding="utf-8")

	record = {
		"run_id": run_id,
		"scenario_id": args.profile,
		"tool": profile["tool"],
		"target": args.target,
		"target_ip": target_ip,
		"lab_cidr": args.lab_cidr,
		"command_profile": args.profile,
		"command": command_text,
		"intensity": profile["intensity"],
		"expected_label": profile["expected_label"],
		"start_time": result["start_time"],
		"end_time": result["end_time"],
		"elapsed_seconds": result["elapsed_seconds"],
		"return_code": result["return_code"],
		"output_path": str(run_dir)
	}

	gt_path = Path(args.ground_truth)
	gt_path.parent.mkdir(parents=True, exist_ok=True)

	with gt_path.open("a", encoding="utf-8") as f:
		f.write(json.dumps(record, ensure_ascii=False) + "\n")

	(run_dir / "ground_truth.json").write_text(
		json.dumps(record, indent=2, ensure_ascii=False),
		encoding="utf-8"
	)

	print(json.dumps(record, indent=2, ensure_ascii=False))

	if result["return_code"] != 0:
		raise SystemExit(result["return_code"])

if __name__ == "__main__":
	main()

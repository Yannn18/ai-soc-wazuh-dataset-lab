#!/usr/bin/env python3
import argparse
import ipaddress
import json
import shutil
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

def now_utc():
	return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def require_lab_ip(target, lab_cidr):
	ip = ipaddress.ip_address(target)
	net = ipaddress.ip_network(lab_cidr, strict=False)
	if ip not in net:
		raise SystemExit(f"[BLOCKED] Target {target} di luar LAB_CIDR {lab_cidr}")
	if not ip.is_private:
		raise SystemExit(f"[BLOCKED] Target {target} bukan private IP")
	return str(ip)

def read_lines(path):
	return [
		x.strip()
		for x in Path(path).read_text(encoding="utf-8").splitlines()
		if x.strip() and not x.strip().startswith("#")
	]

def write_jsonl(path, record):
	p = Path(path)
	p.parent.mkdir(parents=True, exist_ok=True)
	with p.open("a", encoding="utf-8") as f:
		f.write(json.dumps(record, ensure_ascii=False) + "\n")

def main():
	parser = argparse.ArgumentParser(description="Controlled SSH login failure simulator for Wazuh dataset lab")
	parser.add_argument("--target", required=True)
	parser.add_argument("--lab-cidr", default="192.168.56.0/24")
	parser.add_argument("--users", default="payloads/dummy_users.txt")
	parser.add_argument("--passwords", default="payloads/dummy_passwords.txt")
	parser.add_argument("--max-attempts", type=int, default=5)
	parser.add_argument("--interval", type=float, default=3.0)
	parser.add_argument("--timeout", type=int, default=6)
	parser.add_argument("--execute", action="store_true", help="Tanpa flag ini hanya dry-run")
	parser.add_argument("--ground-truth", default="ground-truth/chapter5_auth.jsonl")
	parser.add_argument("--log-dir", default="logs/auth")
	args = parser.parse_args()

	target = require_lab_ip(args.target, args.lab_cidr)

	if args.max_attempts < 1 or args.max_attempts > 10:
		raise SystemExit("[BLOCKED] max-attempts harus 1..10")
	if args.interval < 2:
		raise SystemExit("[BLOCKED] interval minimal 2 detik")
	if shutil.which("sshpass") is None:
		raise SystemExit("[ERROR] sshpass tidak ditemukan. Install: sudo apt install -y sshpass")

	users = read_lines(args.users)
	passwords = read_lines(args.passwords)

	run_id = "run-" + uuid.uuid4().hex[:12]
	outdir = Path(args.log_dir) / run_id
	outdir.mkdir(parents=True, exist_ok=True)

	attempts = []
	count = 0

	for user in users:
		for password in passwords:
			if count >= args.max_attempts:
				break
			count += 1
			start = now_utc()

			cmd = [
				"sshpass", "-p", password,
				"ssh",
				"-o", "PreferredAuthentications=password",
				"-o", "PubkeyAuthentication=no",
				"-o", "StrictHostKeyChecking=no",
				"-o", f"ConnectTimeout={args.timeout}",
				f"{user}@{target}",
				"true"
			]

			record = {
				"timestamp": start,
				"run_id": run_id,
				"scenario_id": "auth_ssh_login_failure",
				"attack_type": "auth_attack",
				"mitre_tactic": "Credential Access",
				"mitre_technique": "Brute Force",
				"target_host": target,
				"target_port": 22,
				"tool": "sshpass+ssh",
				"payload_id": f"dummy_ssh_{count}",
				"intensity": "low" if args.max_attempts <= 5 else
				"burst",
				"expected_label": "malicious",
				"success_status": "unknown",
				"username": user,
				"password_type": "dummy_lab_only",
				"attempt_number": count,
				"dry_run": not args.execute
			}

			if args.execute:
				proc = subprocess.run(cmd, text=True, capture_output=True, timeout=args.timeout + 3)
				record["success_status"] = "failed" if proc.returncode != 0 else "unexpected_success"
				record["return_code"] = proc.returncode
				(outdir / f"attempt-{count:03d}.stderr.log").write_text(proc.stderr, encoding="utf-8", errors="replace")
				(outdir / f"attempt-{count:03d}.stdout.log").write_text(proc.stdout, encoding="utf-8", errors="replace")
			else:
				record["success_status"] = "dry_run"

			write_jsonl(args.ground_truth, record)
			attempts.append(record)
			print(json.dumps(record, ensure_ascii=False))

			if count < args.max_attempts:
				time.sleep(args.interval)

			if count >= args.max_attempts:
				break
	summary = {
		"run_id": run_id,
		"target": target,
		"attempts": len(attempts),
		"execute": args.execute,
		"ground_truth": args.ground_truth,
		"log_dir": str(outdir)
	}
	(outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

if __name__ == "__main__":
	main()

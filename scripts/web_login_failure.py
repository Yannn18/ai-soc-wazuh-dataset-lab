#!/usr/bin/env python3
import argparse
import ipaddress
import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
import requests

def now_utc():
	return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def require_lab_url(url, lab_cidr):
	parsed = urlparse(url)
	if parsed.scheme not in ("http", "https"):
		raise SystemExit("[BLOCKED] URL harus http/https")
	if not parsed.hostname:
		raise SystemExit("[BLOCKED] URL tidak memiliki hostname")
	try:
		ip = ipaddress.ip_address(parsed.hostname)
	except ValueError:
		raise SystemExit("[BLOCKED] Gunakan IP lab, bukan domain publik")
	net = ipaddress.ip_network(lab_cidr, strict=False)
	if ip not in net or not ip.is_private:
		raise SystemExit(f"[BLOCKED] Host {ip} bukan IP lab valid")
	return parsed.hostname

def write_jsonl(path, record):
	p = Path(path)
	p.parent.mkdir(parents=True, exist_ok=True)
	with p.open("a", encoding="utf-8") as f:
		f.write(json.dumps(record, ensure_ascii=False) + "\n")

def main():
	parser = argparse.ArgumentParser(description="Controlled web login failure simulator")
	parser.add_argument("--url", required=True, help="Contoh: http://192.168.56.30:3000/login")
	parser.add_argument("--lab-cidr", default="192.168.56.0/24")
	parser.add_argument("--username-field", default="username")
	parser.add_argument("--password-field", default="password")
	parser.add_argument("--user-prefix", default="dummyuser")
	parser.add_argument("--max-attempts", type=int, default=5)
	parser.add_argument("--interval", type=float, default=2.0)
	parser.add_argument("--execute", action="store_true")
	parser.add_argument("--ground-truth", default="ground-truth/chapter5_web_login.jsonl")
	parser.add_argument("--log-dir", default="logs/web")
	args = parser.parse_args()

	target_host = require_lab_url(args.url, args.lab_cidr)

	if args.max_attempts < 1 or args.max_attempts > 20:
		raise SystemExit("[BLOCKED] max-attempts harus 1..20")
	if args.interval < 1:
		raise SystemExit("[BLOCKED] interval minimal 1 detik")

	run_id = "run-" + uuid.uuid4().hex[:12]
	outdir = Path(args.log_dir) / run_id
	outdir.mkdir(parents=True, exist_ok=True)

	session = requests.Session()

	for i in range(1, args.max_attempts + 1):
		username = f"{args.user_prefix}{i}"
		data = {
			args.username_field: username,
			args.password_field: f"DummyWrongPassword{i}!"
		}
		record = {
			"timestamp": now_utc(),
			"run_id": run_id,
			"scenario_id": "web_login_failure",
			"attack_type": "auth_attack",
			"mitre_tactic": "Credential Access",
			"mitre_technique": "Brute Force",
			"target_host": target_host,
			"target_port": urlparse(args.url).port or 80,
			"tool": "python_requests",
			"payload_id": f"dummy_web_login_{i}",
			"intensity": "low" if args.max_attempts <= 5 else "burst",
			"expected_label": "malicious",
			"success_status": "dry_run",
			"username": username,
			"endpoint": args.url,
			"attempt_number": i,
			"dry_run": not args.execute
		}

		if args.execute:
			try:
				r = session.post(args.url, data=data, timeout=8, allow_redirects=False)
				record["status_code"] = r.status_code
				record["success_status"] = "failed_login_request_sent"
				record["response_length"] = len(r.text) 
			except Exception as e:
				record["success_status"] = "request_error"
				record["error"] = str(e)

		write_jsonl(args.ground_truth, record)
		print(json.dumps(record, ensure_ascii=False))

		if i < args.max_attempts:
			time.sleep(args.interval)
	summary = {
		"run_id": run_id,
		"url": args.url,
		"attempts": args.max_attempts,
		"execute": args.execute
	}
	(outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

if __name__ == "__main__":
	main()

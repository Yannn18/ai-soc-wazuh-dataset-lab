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
	try:
		ip = ipaddress.ip_address(parsed.hostname)
	except Exception:
		raise SystemExit("[BLOCKED] Gunakan IP lab, bukan domain")
	net = ipaddress.ip_network(lab_cidr, strict=False)
	if ip not in net or not ip.is_private:
		raise SystemExit(f"[BLOCKED] Host {ip} bukan IP lab")
	return parsed.hostname

def read_payloads(path):
	rows = []
	for line in Path(path).read_text(encoding="utf-8").splitlines():
		if line.strip():
			rows.append(json.loads(line))
	return rows

def write_jsonl(path, record):
	p = Path(path)
	p.parent.mkdir(parents=True, exist_ok=True)
	with p.open("a", encoding="utf-8") as f:
		f.write(json.dumps(record, ensure_ascii=False) + "\n")
def main():
	parser = argparse.ArgumentParser(description="Controlled web input attack pattern simulator")
	parser.add_argument("--url", required=True, help="Contoh: http://192.168.56.20:3000/search")
	parser.add_argument("--param", default="q")
	parser.add_argument("--method", choices=["GET", "POST"], default="GET")
	parser.add_argument("--payloads", default="payloads/web_input_dummy.jsonl")
	parser.add_argument("--lab-cidr", default="192.168.56.0/24")
	parser.add_argument("--max-requests", type=int, default=5)
	parser.add_argument("--interval", type=float, default=2.0)
	parser.add_argument("--execute", action="store_true")
	parser.add_argument("--ground-truth",
	default="ground-truth/chapter5_web_input.jsonl")
	args = parser.parse_args()

	target_host = require_lab_url(args.url, args.lab_cidr)

	if args.max_requests < 1 or args.max_requests > 20:
		raise SystemExit("[BLOCKED] max-requests harus 1..20")
	if args.interval < 1:
		raise SystemExit("[BLOCKED] interval minimal 1 detik")
	payloads = read_payloads(args.payloads)[:args.max_requests]
	run_id = "run-" + uuid.uuid4().hex[:12]

	for i, payload in enumerate(payloads, start=1):
		record = {
			"timestamp": now_utc(),
			"run_id": run_id,
			"scenario_id": "web_input_attack_pattern",
			"attack_type": "web_attack",
			"mitre_tactic": "Initial Access",
			"mitre_technique": "Exploit Public-Facing Application",
			"target_host": target_host,
			"target_port": urlparse(args.url).port or 80,
			"tool": "python_requests",
			"payload_id": payload["payload_id"],
			"payload_category": payload["category"],
			"intensity": "low",
			"expected_label": "malicious",
			"success_status": "dry_run",
			"endpoint": args.url,
			"http_method": args.method,
			"param": args.param,
			"request_number": i,
			"dry_run": not args.execute
		}

		if args.execute:
			try:
				if args.method == "GET":
					r = requests.get(args.url, params={args.param: payload["payload"]}, timeout=8)
				else:
					r = requests.post(args.url, data={args.param: payload["payload"]}, timeout=8)
				record["status_code"] = r.status_code
				record["response_length"] = len(r.text)
				record["success_status"] = "request_sent"
			except Exception as e:
				record["success_status"] = "request_error"
				record["error"] = str(e)

		write_jsonl(args.ground_truth, record)
		print(json.dumps(record, ensure_ascii=False))

		if i < len(payloads):
			time.sleep(args.interval)

if __name__ == "__main__":
	main()

#!/usr/bin/env python3
import argparse
import json
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path

def now_utc():
	return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def read_json(path):
	return json.loads(Path(path).read_text(encoding="utf-8"))

def read_jsonl(path):
	p = Path(path)
	if not p.exists():
		return []
	rows = []
	for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
		if line.strip():
			rows.append(json.loads(line))
	return rows

def write_jsonl(path, rows):
	p = Path(path)
	p.parent.mkdir(parents=True, exist_ok=True)
	with p.open("w", encoding="utf-8") as f:
		for row in rows:
			f.write(json.dumps(row, ensure_ascii=False) + "\n")

def main():
	parser = argparse.ArgumentParser(description="Build reproducible mixed benign/suspicious scenarios")
	parser.add_argument("--payload-catalog", default="payloads/payload_catalog.jsonl")
	parser.add_argument("--wordlist", default="payloads/wordlist_dummy.json")
	parser.add_argument("--target-host", default="192.168.56.30")
	parser.add_argument("--target-web", default="http://192.168.56.30:3000")
	parser.add_argument("--seed", type=int, default=202606)
	parser.add_argument("--count", type=int, default=30)
	parser.add_argument("--output", default="payloads/scenario_plan.jsonl")
	args = parser.parse_args()

	if args.count < 1 or args.count > 200:
		raise SystemExit("[BLOCKED] count harus 1..200")

	random.seed(args.seed)
	wordlist = read_json(args.wordlist)
	payloads = read_jsonl(args.payload_catalog)

	scenario_types = [
		"benign_web_access",
		"benign_login_attempt",
		"web_attack_dummy",
		"auth_attack_dummy",
		"suspicious_path_dummy",
		"incomplete_scan_dummy"
	]

	intensities = ["benign", "low", "medium", "low_and_slow", "burst"]
	rows = []

	for i in range(1, args.count + 1):
		scenario_type = random.choice(scenario_types)
		intensity = random.choice(intensities)

		payload = random.choice(payloads) if payloads else {
			"payload_id": "manual_none",
			"payload_category": "none",
			"payload_text": ""
		}

		if scenario_type.startswith("benign"):
			label = "benign"
			attack_type = "benign"
		elif scenario_type == "auth_attack_dummy":
			label = "malicious"
			attack_type = "auth_attack"
		elif scenario_type == "web_attack_dummy":
			label = "malicious"
			attack_type = "web_attack"
		else:
			label = "suspicious"
			attack_type = "network_anomaly"
		row = {
			"plan_id": "plan-" + uuid.uuid4().hex[:12],
			"created_at": now_utc(),
			"seed": args.seed,
			"sequence": i,
			"scenario_type": scenario_type,
			"attack_type": attack_type,
			"target_host": args.target_host,
			"target_web": args.target_web,
			"username": random.choice(wordlist["users"]),
			"password_id": "dummy_password_only",
			"path": random.choice(wordlist["paths"]),
			"user_agent": random.choice(wordlist["user_agents"]),
			"payload_id": payload.get("payload_id"),
			"payload_category": payload.get("payload_category"),
			"payload_text": payload.get("payload_text"),
			"intensity": intensity,
			"expected_label": label,
			"safety_status": "planned_lab_only"
		}

		rows.append(row)

	write_jsonl(args.output, rows)

	print(json.dumps({
		"output": args.output,
		"count": len(rows),
		"seed": args.seed
	}, indent=2, ensure_ascii=False))

if __name__ == "__main__":
	main()

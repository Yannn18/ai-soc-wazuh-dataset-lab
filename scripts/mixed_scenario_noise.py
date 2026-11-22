#!/usr/bin/env python3
import argparse
import json
import random
import uuid
from datetime import datetime, timezone
from pathlib import Path

def now_utc():
	return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def write_jsonl(path, rows):
	p = Path(path)
	p.parent.mkdir(parents=True, exist_ok=True)
	with p.open("w", encoding="utf-8") as f:
		for row in rows:
			f.write(json.dumps(row, ensure_ascii=False) + "\n")

def main():
	parser = argparse.ArgumentParser(description="Generate mixed normal and suspicious scenario plan")
	parser.add_argument("--seed", type=int, default=20260624)
	parser.add_argument("--count", type=int, default=50)
	parser.add_argument("--output",	default="payloads/mixed_scenario_noise.jsonl")
	args = parser.parse_args()

	if args.count < 1 or args.count > 500:
		raise SystemExit("[BLOCKED] count harus 1..500")

	random.seed(args.seed)

	templates = [
	{
		"scenario_type": "normal_web_access",
		"attack_type": "benign",
		"expected_label": "benign",
		"noise_type": "normal"
	},
	{
		"scenario_type": "typo_login",
		"attack_type": "benign",
		"expected_label": "benign",
		"noise_type": "human_error"
	},
	{
		"scenario_type": "failed_attack_dummy",
		"attack_type": "web_attack",
		"expected_label": "malicious",
		"noise_type": "failed_attack"
	},
	{
		"scenario_type": "low_and_slow_recon",
		"attack_type": "recon",
		"expected_label": "malicious",
		"noise_type": "low_signal"
	},
	{
		"scenario_type": "duplicate_alert_candidate",
		"attack_type": "auth_attack",
		"expected_label": "malicious",
		"noise_type": "duplicate_candidate"
	},
	{
		"scenario_type": "event_without_alert_candidate",
		"attack_type": "suspicious_command",
		"expected_label": "suspicious",
		"noise_type": "no_alert_expected"
	}
	]
	rows = []
	for i in range(1, args.count + 1):
		t = random.choice(templates)
		row = {
			"plan_id": "noise-" + uuid.uuid4().hex[:12],
			"created_at": now_utc(),
			"seed": args.seed,
			"sequence": i,
			"scenario_type": t["scenario_type"],
			"attack_type": t["attack_type"],
			"expected_label": t["expected_label"],
			"noise_type": t["noise_type"],
			"intensity": random.choice(["benign", "low", "medium", "low_and_slow", "burst"]),
			"expected_detection": random.choice(["alert_expected", "archive_only_possible", "no_alert_possible"]),
			"notes": "Generated for realistic AI SOC dataset variation"
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

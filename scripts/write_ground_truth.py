#!/usr/bin/env python3
import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

def now_utc():
	return
datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def main():
	parser = argparse.ArgumentParser(description="Write one ground truth event as JSONL")
	parser.add_argument("--scenario-id", required=True)
	parser.add_argument("--attack-type", required=True)
	parser.add_argument("--mitre-tactic", required=True)
	parser.add_argument("--mitre-technique", required=True)
	parser.add_argument("--target-host", required=True)
	parser.add_argument("--target-port", required=True)
	parser.add_argument("--tool", required=True)
	parser.add_argument("--payload-id", default="none")
	parser.add_argument("--intensity", required=True)
	parser.add_argument("--expected-label", required=True,
choices=["benign", "malicious"])
	parser.add_argument("--success-status", required=True,
choices=["success", "failed", "timeout", "partial", "unknown"])
	parser.add_argument("--output", default="ground-truth/ground_truth.jsonl")
	args = parser.parse_args()

	record = {
		"timestamp": now_utc(),
		"scenario_id": args.scenario_id,
		"run_id": "run-" + uuid.uuid4().hex[:12],
		"attack_type": args.attack_type,
		"mitre_tactic": args.mitre_tactic,
		"mitre_technique": args.mitre_technique,
		"target_host": args.target_host,
		"target_port": args.target_port,
		"tool": args.tool,
		"payload_id": args.payload_id,
		"intensity": args.intensity,
		"expected_label": args.expected_label,
		"success_status": args.success_status
	}

	out = Path(args.output)
	out.parent.mkdir(parents=True, exist_ok=True)

	with out.open("a", encoding="utf-8") as f:
		f.write(json.dumps(record, ensure_ascii=False) + "\n")

	print(json.dumps(record, indent=2, ensure_ascii=False))

if __name__ == "__main__":
	main()

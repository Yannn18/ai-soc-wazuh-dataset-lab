#!/usr/bin/env python3
import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

def now():
	return datetime.now(timezone.utc).isoformat()

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--activity", required=True)
	parser.add_argument("--target", required=True)
	parser.add_argument("--label", default="benign")
	parser.add_argument("--notes", default="")
	parser.add_argument("--output",
default="ground-truth/baseline-normal.jsonl")
	args = parser.parse_args()

	record = {
		"timestamp": now(),
		"run_id": str(uuid.uuid4()),
		"scenario_id": "baseline_normal",
		"activity": args.activity,
		"target": args.target,
		"expected_label": args.label,
		"notes": args.notes
		}

	out = Path(args.output)
	out.parent.mkdir(parents=True, exist_ok=True)

	with out.open("a", encoding="utf-8") as f:
		f.write(json.dumps(record, ensure_ascii=False) +"\n")

	print(json.dumps(record, indent=2, ensure_ascii=False))

if __name__ == "__main__":
	main()

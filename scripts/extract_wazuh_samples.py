#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

def read_jsonl(path, limit):
	rows = []
	p = Path(path)
	if not p.exists():
		return rows

	with p.open("r", encoding="utf-8", errors="replace") as f:
		for line in f:
			line = line.strip()
			if not line:
				continue
			try:
				rows.append(json.loads(line))
			except json.JSONDecodeError:
				continue
	return rows[-limit:]

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--alerts", default="wazuh-export/chapter7/alerts-before-custom-rule.jsonl")
	parser.add_argument("--archives", default="wazuh-export/chapter7/archives-before-custom-rule.jsonl")
	parser.add_argument("--limit", type=int, default=20)
	parser.add_argument("--output", default="samples/logtest/wazuh_samples.jsonl")
	args = parser.parse_args()

	rows = []

	for source_name, path in [("alerts", args.alerts), ("archives", args.archives)]:
		for r in read_jsonl(path, args.limit):
			rows.append({
				"source": source_name,
				"timestamp": r.get("timestamp"),
				"location": r.get("location"),
				"agent": r.get("agent", {}).get("name"),
				"rule": r.get("rule", {}),
				"full_log": r.get("full_log", ""),
				"raw": r
			})

	out = Path(args.output)
	out.parent.mkdir(parents=True, exist_ok=True)

	with out.open("w", encoding="utf-8") as f:
		for r in rows:
			f.write(json.dumps(r, ensure_ascii=False) + "\n")

	print(json.dumps({
		"output": args.output,
		"records": len(rows)
	}, indent=2, ensure_ascii=False))

if __name__ == "__main__":
	main()

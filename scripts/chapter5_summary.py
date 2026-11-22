#!/usr/bin/env python3
import json
from collections import Counter
from pathlib import Path

FILES = [
	"ground-truth/chapter5_auth.jsonl",
	"ground-truth/chapter5_web_login.jsonl",
	"ground-truth/chapter5_web_input.jsonl",
	"ground-truth/chapter5_fim.jsonl",
	"ground-truth/chapter5_commands.jsonl"
]

def read_jsonl(path):
	p = Path(path)
	if not p.exists():
		return []
	rows = []
	for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
		if line.strip():
			try:
				rows.append(json.loads(line))
			except json.JSONDecodeError:
				pass
	return rows

def main():
	rows = []
	for f in FILES:
		rows.extend(read_jsonl(f))
	by_attack_type = Counter(r.get("attack_type", "unknown") for r in rows)
	by_label = Counter(r.get("expected_label", "unknown") for r in rows)
	by_scenario = Counter(r.get("scenario_id", "unknown") for r in rows)
	dry_runs = sum(1 for r in rows if r.get("dry_run") is True)
	print("# Chapter 5 Dataset Summary")

	print()
	print(f"Total ground truth records: {len(rows)}")
	print(f"Dry-run records: {dry_runs}")
	print()
	print("## By attack_type")
	for k, v in by_attack_type.items():
		print(f"- {k}: {v}")
	print()
	print("## By expected_label")
	for k, v in by_label.items():
		print(f"- {k}: {v}")
	print()
	print("## By scenario_id")
	for k, v in by_scenario.items():
		print(f"- {k}: {v}")

if __name__ == "__main__":
	main()

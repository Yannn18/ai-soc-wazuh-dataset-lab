#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

REQUIRED_FILES = [
	"ground_truth.jsonl",
	"commands.log",
	"stdout.log",
	"stderr.log",
	"summary.md"
]

def count_lines(path):
	p = Path(path)
	if not p.exists():
		return 0
	return sum(1 for _ in p.open("r", encoding="utf-8", errors="replace"))

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--run-dir", required=True)
	args = parser.parse_args()

	run_dir = Path(args.run_dir)
	errors = []

	for name in REQUIRED_FILES:
		if not (run_dir / name).exists():
			errors.append(f"missing: {name}")

	if count_lines(run_dir / "ground_truth.jsonl") == 0:
		errors.append("ground_truth kosong")

	if (run_dir / "wazuh_alerts.jsonl").exists() and count_lines(run_dir / "wazuh_alerts.jsonl") == 0:
		errors.append("wazuh_alerts kosong")

	report = {
		"run_dir": str(run_dir),
		"valid": len(errors) == 0,
		"errors": errors,
		"line_counts": {
			"ground_truth": count_lines(run_dir / "ground_truth.jsonl"),
			"wazuh_alerts": count_lines(run_dir / "wazuh_alerts.jsonl"),
			"dataset_candidate": count_lines(run_dir / "dataset_candidate.jsonl")
		}
	}
	out = run_dir / "validation_report.json"
	out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

	print(json.dumps(report, indent=2, ensure_ascii=False))

	if errors:
		raise SystemExit(1)

if __name__ == "__main__":
	main()

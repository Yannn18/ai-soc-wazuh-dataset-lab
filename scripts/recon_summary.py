#!/usr/bin/env python3
import json
from collections import Counter
from pathlib import Path

GT = Path("ground-truth/recon.jsonl")
REPORT = Path("reports/recon/correlation-report.json")

def read_jsonl(path):
	rows = []
	if not path.exists():
		return rows
	for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
		if line.strip():
			try:
				rows.append(json.loads(line))
			except json.JSONDecodeError:
				pass
	return rows

def main():
	gt = read_jsonl(GT)

	by_profile = Counter(r.get("scenario_id", "unknown") for r in gt)
	by_tool = Counter(r.get("tool", "unknown") for r in gt)
	by_intensity = Counter(r.get("intensity", "unknown") for r in gt)

	print("# Recon Dataset Summary")
	print()
	print(f"Ground truth records: {len(gt)}")
	print()
	print("## By Profile")
	for k, v in by_profile.items():
		print(f"- {k}: {v}")
	print()
	print("## By Tool")
	for k, v in by_tool.items():
		print(f"- {k}: {v}")
	print()
	print("## By Intensity")
	for k, v in by_intensity.items():
		print(f"- {k}: {v}")

	if REPORT.exists():
		report = json.loads(REPORT.read_text(encoding="utf-8"))
		print()
		print("## Wazuh Correlation")
		print(f"- Alert count: {report.get('alert_count')}")
		print(f"- Runs with alert: {report.get('runs_with_alert')}")
		print(f"- Runs without alert: {report.get('runs_without_alert')}")

if __name__ == "__main__":
	main()

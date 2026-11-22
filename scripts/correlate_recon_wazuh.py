#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from collections import Counter

def parse_time(value):
	if not value:
		return None
	value = value.replace("Z", "+00:00")
	try:
		return datetime.fromisoformat(value)
	except ValueError:
		return None

def read_jsonl(path):
	records = []
	p = Path(path)
	if not p.exists():
		return records

	with p.open("r", encoding="utf-8", errors="replace") as f:
		for line in f:
			line = line.strip()
			if not line:
				continue
			try:
				records.append(json.loads(line))
			except json.JSONDecodeError:
				continue
	return records

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--ground-truth", default="ground-truth/recon.jsonl")
	parser.add_argument("--alerts", default="wazuh-export/recon/alerts-recon.jsonl")
	parser.add_argument("--window-seconds", type=int, default=180)
	parser.add_argument("--output", default="reports/recon/correlation-report.json")
	args = parser.parse_args()

	gt_records = read_jsonl(args.ground_truth)
	alerts = read_jsonl(args.alerts)

	parsed_alerts = []
	for alert in alerts:
		ts = parse_time(alert.get("timestamp"))
		if ts:
			parsed_alerts.append((ts, alert))

	results = []

	for gt in gt_records:
		start = parse_time(gt.get("start_time"))
		end = parse_time(gt.get("end_time"))
		target_ip = gt.get("target_ip")

		if not start or not end:
			continue
		start_w = start - timedelta(seconds=args.window_seconds)
		end_w = end + timedelta(seconds=args.window_seconds)

		matched = []
		for ts, alert in parsed_alerts:
			if start_w <= ts <= end_w:
				raw = json.dumps(alert, ensure_ascii=False)
				if target_ip and target_ip in raw:
					matched.append(alert)

		rules = Counter()
		levels = Counter()

		for alert in matched:
			rule = alert.get("rule", {})
			rules[str(rule.get("id", "unknown")) + " | " + str(rule.get("description", "unknown"))] += 1
			levels[str(rule.get("level", "unknown"))] += 1

		results.append({
			"run_id": gt.get("run_id"),
			"scenario_id": gt.get("scenario_id"),
			"tool": gt.get("tool"),
			"target_ip": target_ip,
			"intensity": gt.get("intensity"),
			"expected_label": gt.get("expected_label"),
			"start_time": gt.get("start_time"),
			"end_time": gt.get("end_time"),
			"matched_alert_count": len(matched),
			"matched_rules": dict(rules),
			"matched_levels": dict(levels),
			"status": "alert_found" if matched else "no_alert_found"
		})

	summary = {
		"ground_truth_count": len(gt_records),
		"alert_count": len(alerts),
		"correlated_runs": len(results),
		"runs_with_alert": sum(1 for r in results if
		r["matched_alert_count"] > 0),
		"runs_without_alert": sum(1 for r in results if
		r["matched_alert_count"] == 0),
		"results": results
	}

	out = Path(args.output)
	out.parent.mkdir(parents=True, exist_ok=True)
	out.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

	print(json.dumps(summary, indent=2, ensure_ascii=False))

if __name__ == "__main__":
	main()

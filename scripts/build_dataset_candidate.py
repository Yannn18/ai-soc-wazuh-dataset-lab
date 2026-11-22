#!/usr/bin/env python3
import argparse
import hashlib
import json
from datetime import datetime
from pathlib import Path

def read_jsonl(path):
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
	return rows

def make_event_id(run_id, row, index):
	raw = json.dumps(row, sort_keys=True, ensure_ascii=False)
	h = hashlib.sha256(f"{run_id}|{index}|{raw}".encode()).hexdigest()[:16]
	return "evt-" + h

def main():
	parser = argparse.ArgumentParser(description="Build dataset candidate from evidence run")
	parser.add_argument("--run-dir", required=True)
	parser.add_argument("--output-name", default="dataset_candidate.jsonl")
	args = parser.parse_args()

	run_dir = Path(args.run_dir)
	run_id = run_dir.name

	ground_truth = read_jsonl(run_dir / "ground_truth.jsonl")
	execution = read_jsonl(run_dir / "execution_results.jsonl")
	alerts = read_jsonl(run_dir / "wazuh_alerts.jsonl")

	rows = []

	for i, gt in enumerate(ground_truth, start=1):
		row = {
			"event_id": make_event_id(run_id, gt, i),
			"run_id": run_id,
			"timestamp": gt.get("timestamp"),
			"source": "ground_truth",
			"scenario_id": gt.get("scenario_id"),
			"attack_type": gt.get("attack_type"),
			"target_host": gt.get("target_host"),
			"target_port": gt.get("target_port"),
			"tool": gt.get("tool"),
			"payload_id": gt.get("payload_id"),
			"intensity": gt.get("intensity"),
			"label": gt.get("expected_label"),
			"confidence": 1.0,
			"raw_event": json.dumps(gt, ensure_ascii=False)
		}
		rows.append(row)
	for i, alert in enumerate(alerts, start=1):
		rule = alert.get("rule", {}) if isinstance(alert.get("rule"), dict) else {}
		agent = alert.get("agent", {}) if isinstance(alert.get("agent"), dict) else {}

		row = {
			"event_id": make_event_id(run_id, alert, i),
			"run_id": run_id,
			"timestamp": alert.get("timestamp"),
			"source": "wazuh_alert",
			"scenario_id": "unmatched",
			"attack_type": "unknown",
			"agent_name": agent.get("name"),
			"rule_id": str(rule.get("id", "")),
			"rule_level": rule.get("level"),
			"rule_description": rule.get("description", ""),
			"label": "unlabeled",
			"confidence": 0.0,
			"raw_event": json.dumps(alert, ensure_ascii=False)
		}
		rows.append(row)

	out = run_dir / args.output_name
	with out.open("w", encoding="utf-8") as f:
		for row in rows:
			f.write(json.dumps(row, ensure_ascii=False) + "\n")

	print(json.dumps({
		"run_dir": str(run_dir),
		"output": str(out),
		"ground_truth_records": len(ground_truth),
		"alert_records": len(alerts),
		"dataset_candidate_records": len(rows)
	}, indent=2, ensure_ascii=False))

if __name__ == "__main__":
	main()

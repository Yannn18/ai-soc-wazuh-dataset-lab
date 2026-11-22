#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path


def read_jsonl(path):
	rows = []
	p = Path(path)
	if not p.exists():
		return rows

	with p.open("r", encoding="utf-8", errors="replace") as f:
		for line_no, line in enumerate(f, start=1):
			line = line.strip()
			if not line:
				continue
			try:
				rows.append(json.loads(line))
			except json.JSONDecodeError:
				pass
	return rows


def write_jsonl(path, records):
	p = Path(path)
	p.parent.mkdir(parents=True, exist_ok=True)
	with p.open("w", encoding="utf-8") as f:
		for r in records:
			f.write(json.dumps(r, ensure_ascii=False) + "\n")


def parse_time(value):
	if not value:
		return None

	value = str(value).replace("Z", "+00:00")

	try:
		dt = datetime.fromisoformat(value)
	except ValueError:
		return None

	if dt.tzinfo is None:
		dt = dt.replace(tzinfo=timezone.utc)
	return dt.astimezone(timezone.utc)


def get_nested(obj, path, default=None):
	cur = obj
	for part in path.split("."):
		if not isinstance(cur, dict):
			return default
		cur = cur.get(part)
		if cur is None:
			return default
	return cur


def stable_id(prefix, *parts):
	text = "|".join(str(p) for p in parts)
	return prefix + hashlib.sha256(text.encode()).hexdigest()[:16]


def normalize_alert(alert):
	"""Normalize both raw Wazuh alerts and already-normalized alerts"""
	# Check if already normalized (has top-level agent_name)
	if "agent_name" in alert and "rule_id" in alert:
		# Already normalized format - use directly
		return {
			"event_id": alert.get("event_id", stable_id("evt-", alert.get("timestamp"), alert.get("agent_name"), alert.get("rule_id"), alert.get("full_log", "")[:200])),
			"timestamp": alert.get("timestamp"),
			"agent_name": alert.get("agent_name", "unknown"),
			"source_ip": alert.get("source_ip"),
			"destination_ip": alert.get("destination_ip"),
			"rule_id": alert.get("rule_id", ""),
			"rule_level": alert.get("rule_level"),
			"rule_description": alert.get("rule_description", ""),
			"rule_groups": alert.get("rule_groups", []),
			"rule_mitre_id": alert.get("rule_mitre_id", []),
			"location": alert.get("location", ""),
			"full_log": alert.get("full_log", ""),
			"raw_alert": json.dumps(alert, ensure_ascii=False)
		}

	# Raw Wazuh alert format
	rule = alert.get("rule", {}) if isinstance(alert.get("rule"), dict) else {}
	agent = alert.get("agent", {}) if isinstance(alert.get("agent"), dict) else {}
	data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}

	full_log = alert.get("full_log", "")
	raw = json.dumps(alert, ensure_ascii=False)

	source_ip = (
		data.get("srcip")
		or data.get("src_ip")
		or data.get("source_ip")
		or extract_first_ip(full_log)
		or extract_first_ip(raw)
	)

	destination_ip = (
		data.get("dstip")
		or data.get("dst_ip")
		or data.get("destination_ip")
	)

	mitre = rule.get("mitre", {}) if isinstance(rule.get("mitre"), dict) else {}
	return {
		"event_id": stable_id("evt-", alert.get("timestamp"), agent.get("name"), rule.get("id"), full_log[:200]),
		"timestamp": alert.get("timestamp"),
		"agent_name": agent.get("name", "unknown"),
		"source_ip": source_ip,
		"destination_ip": destination_ip,
		"rule_id": str(rule.get("id", "")),
		"rule_level": rule.get("level"),
		"rule_description": rule.get("description", ""),
		"rule_groups": rule.get("groups", []),
		"rule_mitre_id": mitre.get("id", []),
		"location": alert.get("location", ""),
		"full_log": full_log,
		"raw_alert": raw
	}


def extract_first_ip(text):
	if not text:
		return None
	m = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(text))
	return m.group(0) if m else None


def text_contains_any(text, values):
	if not text:
		return False
	text = str(text)
	for v in values:
		if v and str(v) in text:
			return True
	return False


def correlate(gt_rows, alert_rows, window_seconds, agent_names=None):
	normalized_alerts = []
	for alert in alert_rows:
		na = normalize_alert(alert)
		na["_text"] = json.dumps(na, ensure_ascii=False)   # before _dt exists
		na["_dt"] = parse_time(na["timestamp"])
		normalized_alerts.append(na)

	final_rows = []
	matched_alert_ids = set()

	for gt_idx, gt in enumerate(gt_rows):
		gt_time = parse_time(
			gt.get("timestamp")
			or gt.get("start_time")
			or gt.get("created_at")
		)
		if not gt_time:
			continue
		start_w = gt_time - timedelta(seconds=window_seconds)
		end_w = gt_time + timedelta(seconds=window_seconds)

		target_values = [
			gt.get("target_host"),
			gt.get("target"),
			gt.get("target_ip"),
			gt.get("target_web"),
			gt.get("payload_id"),
			gt.get("scenario_id"),
			gt.get("run_id"),
			gt.get("pivot_target"),  # for lateral movement
			gt.get("source"),  # for lateral movement
		]

		# Add agent names to target values if provided
		if agent_names:
			for an in agent_names:
				target_values.append(an)

		candidates = []
		for alert in normalized_alerts:
			adt = alert.get("_dt")
			if not adt:
				continue

			if not (start_w <= adt <= end_w):
				continue

			# Skip already matched alerts
			if alert["event_id"] in matched_alert_ids:
				continue

			alert_text = alert["_text"]
			score = 0

			if text_contains_any(alert_text, target_values):
				score += 2

			if gt.get("attack_type") and gt.get("attack_type") in alert_text:
				score += 2

			if gt.get("scenario_id") and gt.get("scenario_id") in alert_text:
				score += 3

			if gt.get("payload_id") and gt.get("payload_id") != "none" and gt.get("payload_id") in alert_text:
				score += 3

			if score > 0:
				candidates.append((score, alert))

		if candidates:
			candidates.sort(key=lambda x: x[0], reverse=True)
			best_score, best_alert = candidates[0]
			matched_alert_ids.add(best_alert["event_id"])
			confidence = 1.0 if best_score >= 5 else 0.8
			final_rows.append({
			"event_id": stable_id("final-",
			gt.get("run_id"), gt.get("scenario_id"),
			best_alert["event_id"]),
			"timestamp": best_alert.get("timestamp"),
			"agent_name": best_alert.get("agent_name"),
			"source_ip": best_alert.get("source_ip"),
			"destination_ip":
			best_alert.get("destination_ip"),
			"rule_id": best_alert.get("rule_id"),
			"rule_level": best_alert.get("rule_level"),
			"rule_description":
			best_alert.get("rule_description"),
			"full_log": best_alert.get("full_log"),
			"scenario_id": gt.get("scenario_id",
			"unknown"),
			"run_id": gt.get("run_id", "unknown"),
			"attack_type": gt.get("attack_type",
			"unknown"),
			"mitre_tactic": gt.get("mitre_tactic",
			"unknown"),
			"mitre_technique": gt.get("mitre_technique",
			"unknown"),
			"label": gt.get("expected_label",
			"unlabeled"),
			"confidence": confidence,
			"ground_truth_source":
			"ground_truth_correlated",
			"correlation_status": "matched_alert",
			"raw_alert": best_alert.get("raw_alert")
			})
		else:
			final_rows.append({
				"event_id": stable_id("final-", gt.get("run_id"), gt.get("scenario_id"), gt_time.isoformat(), gt_idx),
				"timestamp": gt_time.isoformat(),
				"agent_name": "unknown",
				"source_ip": None,
				"destination_ip": gt.get("target_host") or gt.get("target_ip"),
				"rule_id": None,
				"rule_level": None,
				"rule_description": None,
				"full_log": json.dumps(gt, ensure_ascii=False),
				"scenario_id": gt.get("scenario_id", "unknown"),
				"run_id": gt.get("run_id", "unknown"),
				"attack_type": gt.get("attack_type", "unknown"),
				"mitre_tactic": gt.get("mitre_tactic", "unknown"),
				"mitre_technique": gt.get("mitre_technique", "unknown"),
				"label": gt.get("expected_label", "unlabeled"),
				"confidence": 1.0,
				"ground_truth_source": "ground_truth_only",
				"correlation_status": "ground_truth_without_alert",
				"raw_alert": None
			})

	for alert in normalized_alerts:
		if alert["event_id"] not in matched_alert_ids:
			final_rows.append({
				"event_id": stable_id("final-unmatched-", alert["event_id"]),
				"timestamp": alert.get("timestamp"),
				"agent_name": alert.get("agent_name"),
				"source_ip": alert.get("source_ip"),
				"destination_ip": alert.get("destination_ip"),
				"rule_id": alert.get("rule_id"),
				"rule_level": alert.get("rule_level"),
				"rule_description": alert.get("rule_description"),
				"full_log": alert.get("full_log"),
				"scenario_id": "unmatched",
				"run_id": "unknown",
				"attack_type": "unknown",
				"mitre_tactic": "unknown",
				"mitre_technique": "unknown",
				"label": "unlabeled",
				"confidence": 0.0,
				"ground_truth_source": "wazuh_alert_only",
				"correlation_status": "alert_without_ground_truth",
				"raw_alert": alert.get("raw_alert")
			})
	return final_rows


def main():
	parser = argparse.ArgumentParser(description="Correlate ground truth and Wazuh alerts")
	parser.add_argument("--ground-truth", action="append", required=True, help="Ground truth JSONL file(s) - can specify multiple")
	parser.add_argument("--alerts", required=True)
	parser.add_argument("--output", default="datasets/final/correlated_dataset.jsonl")
	parser.add_argument("--window-seconds", type=int, default=180)
	parser.add_argument("--agent-names", nargs="+", help="Wazuh agent name(s) to add to target_values for matching (e.g., owasp_juice_server cwp-hosting)")
	args = parser.parse_args()

	# Read and merge all ground truth files
	gt_rows = []
	for gt_path in args.ground_truth:
		gt_rows.extend(read_jsonl(gt_path))

	alert_rows = read_jsonl(args.alerts)

	final_rows = correlate(gt_rows, alert_rows, args.window_seconds, args.agent_names)
	write_jsonl(args.output, final_rows)

	print(json.dumps({
		"ground_truth_files": args.ground_truth,
		"ground_truth_records": len(gt_rows),
		"alert_records": len(alert_rows),
		"final_records": len(final_rows),
		"output": args.output
	}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
	main()
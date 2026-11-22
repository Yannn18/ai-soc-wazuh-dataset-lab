#!/usr/bin/env python3
import argparse
import json
import shutil
from collections import deque
from pathlib import Path


def tail_file(src, dst, max_lines, agent_id=None, agent_name=None, rule_groups=None):
	src = Path(src)
	dst = Path(dst)
	dst.parent.mkdir(parents=True, exist_ok=True)

	if not src.exists():
		dst.write_text("", encoding="utf-8")
		return 0

	selected = deque(maxlen=max_lines)  # keeps only the last N matches

	# Normalize rule_groups to list
	if rule_groups:
		if isinstance(rule_groups, str):
			rule_groups = [g.strip() for g in rule_groups.split(",")]
	else:
		rule_groups = []

	with src.open("r", encoding="utf-8", errors="replace") as f:
		for line in f:
			line = line.strip()
			if not line:
				continue

			try:
				obj = json.loads(line)
			except json.JSONDecodeError:
				continue

			# Filter by agent_id
			if agent_id:
				agent = obj.get("agent") if isinstance(obj, dict) else None
				if not isinstance(agent, dict) or agent.get("id") != agent_id:
					continue

			# Filter by agent_name
			if agent_name:
				agent = obj.get("agent") if isinstance(obj, dict) else None
				if not isinstance(agent, dict) or agent.get("name") != agent_name:
					continue

			# Filter by rule.groups
			if rule_groups:
				alert_rule = obj.get("rule") if isinstance(obj, dict) else None
				if not isinstance(alert_rule, dict):
					continue
				alert_groups = alert_rule.get("groups", [])
				if isinstance(alert_groups, str):
					alert_groups = [alert_groups]
				# Check if any of the required groups are in the alert's groups
				if not any(g in alert_groups for g in rule_groups):
					continue

			selected.append(line)

	dst.write_text("\n".join(selected) + ("\n" if selected else ""), encoding="utf-8")
	return len(selected)


def main():
	parser = argparse.ArgumentParser(description="Export Wazuh alert/archive files into run evidence")
	parser.add_argument("--run-dir", required=True)
	parser.add_argument("--alerts", default="/var/ossec/logs/alerts/alerts.json")
	parser.add_argument("--archives", default="/var/ossec/logs/archives/archives.json")
	parser.add_argument("--max-lines", type=int, default=5000)
	parser.add_argument("--agent-id", help="Only export events from this agent ID, e.g. 016")
	parser.add_argument("--agent-name", help="Optional: also require this agent name")
	parser.add_argument("--rule-groups", help="Optional: comma-separated list of rule groups to filter by (e.g., sshd,authentication_failed)")
	parser.add_argument("--output-dir", help="Optional: custom output directory for exported files")
	args = parser.parse_args()

	# Wazuh agent IDs are zero-padded to 3 digits ("16" -> "016")
	agent_id = args.agent_id.zfill(3) if args.agent_id else None

	run_dir = Path(args.run_dir)

	# Determine output directory
	if args.output_dir:
		out_dir = Path(args.output_dir)
		out_dir.mkdir(parents=True, exist_ok=True)
		alert_out = out_dir / "alerts.jsonl"
		archive_out = out_dir / "archives_sample.jsonl"
	else:
		alert_out = run_dir / "wazuh_alerts.jsonl"
		archive_out = run_dir / "wazuh_archives_sample.jsonl"

	alert_count = tail_file(args.alerts, alert_out, args.max_lines, agent_id, args.agent_name, args.rule_groups)
	archive_count = tail_file(args.archives, archive_out, args.max_lines, agent_id, args.agent_name, args.rule_groups)

	result = {
		"run_dir": str(run_dir),
		"agent_id": agent_id,
		"rule_groups_filter": args.rule_groups,
		"alert_lines": alert_count,
		"archive_lines": archive_count,
		"alert_output": str(alert_out),
		"archive_output": str(archive_out)
	}
	print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
	main()
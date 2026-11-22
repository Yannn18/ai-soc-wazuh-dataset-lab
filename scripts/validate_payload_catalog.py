#!/usr/bin/env python3
import argparse
import json
import re
from collections import Counter
from pathlib import Path

BLOCKLIST = [
	"rm -rf",
	"mkfs",
	"dd if=",
	":(){",
	"nc -e",
	"netcat -e",
	"reverse shell",
	"meterpreter",
	"mimikatz",
	"token=",
	"api_key",
	"secret_access_key",
	"-----BEGIN PRIVATE KEY-----"
]

ALLOWED_CATEGORIES = {
	"sql_injection_pattern_dummy",
	"xss_pattern_dummy",
	"path_pattern_dummy",
	"command_pattern_dummy_non_destructive",
	"username_dummy",
	"password_dummy",
	"user_agent_dummy",
	"benign_path",
	"suspicious_path_dummy",
	"none"
}

def validate_row(row, line_no):
	errors = []

	required = [
		"payload_id",
		"payload_category",
		"payload_text",
		"created_by",
		"created_at",
		"safety_status",
		"scenario_mapping",
		"expected_label"
	]

	for key in required:
		if key not in row:
			errors.append(f"missing field: {key}")

	category = row.get("payload_category")
	if category not in ALLOWED_CATEGORIES:
		errors.append(f"category not allowed: {category}")

	payload = str(row.get("payload_text", ""))

	for bad in BLOCKLIST:
		if bad.lower() in payload.lower():
			errors.append(f"blocked keyword: {bad}")
	if re.search(r"https?://(?!192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|localhost|127\.0\.0\.1)", payload, re.I):
		errors.append("public URL detected")

	if row.get("safety_status") not in ("approved", "planned_lab_only", "manual_review"):
		errors.append("invalid safety_status")
	return errors

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--input", default="payloads/payload_catalog.jsonl")
	parser.add_argument("--report", default="reports/chapter6/payload_validation_report.json")
	args = parser.parse_args()

	rows = []
	errors = []

	with Path(args.input).open("r", encoding="utf-8", errors="replace") as f:
		for line_no, line in enumerate(f, start=1):
			line = line.strip()
			if not line:
				continue
			try:
				row = json.loads(line)
				row_errors = validate_row(row, line_no)
				if row_errors:
					errors.append({
						"line": line_no,
						"payload_id": row.get("payload_id"),
						"errors": row_errors
					})
				rows.append(row)
			except json.JSONDecodeError as e:
				errors.append({
					"line": line_no,
					"errors": [f"invalid JSON: {e}"]
				})

	category_count = Counter(r.get("payload_category", "unknown") for r in rows)
	label_count = Counter(r.get("expected_label", "unknown") for r in rows)

	report = {
		"input": args.input,
		"total_payloads": len(rows),
		"valid": len(errors) == 0,
		"error_count": len(errors),
		"category_distribution": dict(category_count),
		"label_distribution": dict(label_count),
		"errors": errors
	}

	out = Path(args.report)
	out.parent.mkdir(parents=True, exist_ok=True)

	out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

	print(json.dumps(report, indent=2, ensure_ascii=False))

	if errors:
		raise SystemExit(1)

if __name__ == "__main__":
	main()

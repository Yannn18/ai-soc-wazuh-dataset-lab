#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False

SENSITIVE_PATTERNS = [
	(re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*[^\\s,;&]+"), r"\1=<MASKED_PASSWORD>"),
	(re.compile(r"(?i)(token|api_key|apikey|secret)\s*[:=]\s*[^\\s,;&]+"), r"\1=<MASKED_SECRET>"),
	(re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z]+PRIVATE KEY-----", re.S), "<MASKED_PRIVATE_KEY>")
	]

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
				pass
	return rows

def write_jsonl(path, rows):
	p = Path(path)
	p.parent.mkdir(parents=True, exist_ok=True)
	with p.open("w", encoding="utf-8") as f:
		for r in rows:
			f.write(json.dumps(r, ensure_ascii=False) + "\n")

def normalize_timestamp(value):
	if not value:
		return None

	v = str(value).replace("Z", "+00:00")
	try:
		dt = datetime.fromisoformat(v)
	except ValueError:
		return None
	if dt.tzinfo is None:
		dt = dt.replace(tzinfo=timezone.utc)

	return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def mask_ip(ip):
	if not ip:
		return None

	ip = str(ip)
	m = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$", ip)
	if not m:
		return ip
	return f"{m.group(1)}.{m.group(2)}.{m.group(3)}.X"

def sanitize_text(text):
	if text is None:
		return ""

	text = str(text)

	for pattern, repl in SENSITIVE_PATTERNS:
		text = pattern.sub(repl, text)

	text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", lambda m: mask_ip(m.group(0)), text)

	return text

def row_fingerprint(row):
	key = {
		"timestamp": row.get("timestamp"),
		"agent_name": row.get("agent_name"),
		"rule_id": row.get("rule_id"),
		"scenario_id": row.get("scenario_id"),
		"full_log": row.get("full_log", "")[:300]
	}

	raw = json.dumps(key, sort_keys=True, ensure_ascii=False)
	return hashlib.sha256(raw.encode()).hexdigest()

def clean_row(row):
	cleaned = dict(row)

	cleaned["timestamp"] = normalize_timestamp(cleaned.get("timestamp"))
	cleaned["agent_name"] = cleaned.get("agent_name") or "unknown"
	cleaned["source_ip"] = mask_ip(cleaned.get("source_ip"))
	cleaned["destination_ip"] = mask_ip(cleaned.get("destination_ip"))

	try:
		cleaned["rule_level"] = int(cleaned["rule_level"]) if cleaned.get("rule_level") is not None else None
	except ValueError:
		cleaned["rule_level"] = None

	cleaned["rule_id"] = str(cleaned.get("rule_id") or "")
	cleaned["rule_description"] = sanitize_text(cleaned.get("rule_description"))
	cleaned["full_log"] = sanitize_text(cleaned.get("full_log"))

	cleaned["scenario_id"] = cleaned.get("scenario_id") or "unknown"
	cleaned["attack_type"] = cleaned.get("attack_type") or "unknown"
	cleaned["mitre_tactic"] = cleaned.get("mitre_tactic") or "unknown"
	cleaned["mitre_technique"] = cleaned.get("mitre_technique") or "unknown"
	cleaned["label"] = cleaned.get("label") or "unlabeled"

	try:
		cleaned["confidence"] = float(cleaned.get("confidence", 0.0))
	except ValueError:
		cleaned["confidence"] = 0.0

	cleaned.pop("raw_alert", None)

	return cleaned


def load_schema(schema_path="schemas/dataset.schema.json"):
	"""Load JSON schema for validation."""
	p = Path(schema_path)
	if not p.exists():
		return None
	with p.open("r", encoding="utf-8") as f:
		return json.load(f)


def validate_record(record, schema):
	"""Validate a single record against the schema."""
	if not HAS_JSONSCHEMA:
		return True, "jsonschema not installed"
	if schema is None:
		return True, "no schema loaded"
	try:
		jsonschema.validate(instance=record, schema=schema)
		return True, None
	except jsonschema.ValidationError as e:
		return False, str(e)


def verify_sanitization(record):
	"""Verify that sensitive data has been properly sanitized."""
	issues = []

	# Check for unmasked IPs (not ending with .X)
	for field in ["source_ip", "destination_ip"]:
		ip = record.get(field)
		if ip and isinstance(ip, str):
			# Check if it's an IPv4 pattern but not masked
			if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
				if not ip.endswith(".X"):
					issues.append(f"Unmasked IP in {field}: {ip}")

	# Check full_log for unmasked IPs
	full_log = record.get("full_log", "")
	if full_log:
		# Look for IPv4 addresses not ending with .X
		ips = re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", full_log)
		for ip in ips:
			if not ip.endswith(".X"):
				issues.append(f"Unmasked IP in full_log: {ip}")

	# Check for passwords/secrets patterns in full_log (actual values, not field names)
	# Look for patterns like password=value, "password": "value", pwd=value, etc.
	sensitive_patterns = [
		r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?[^"\',\s}]+',  # password=value or "password": "value"
		r'(?i)(token|api[_-]?key|secret)\s*[:=]\s*["\']?[^"\',\s}]+',  # token=value or "token": "value"
	]
	for pattern in sensitive_patterns:
		if re.search(pattern, full_log):
			# Check if it's already masked
			match = re.search(pattern, full_log)
			if match and "MASKED" not in match.group(0) and "<masked" not in match.group(0).lower():
				issues.append(f"Potential secret leak in full_log: {match.group(0)[:50]}")

	return len(issues) == 0, issues


def main():
	parser = argparse.ArgumentParser(description="Clean AI SOC dataset")
	parser.add_argument("--input", default="datasets/final/correlated_dataset.jsonl")
	parser.add_argument("--output", default="datasets/final/dataset_clean.jsonl")
	parser.add_argument("--dedup", action="store_true")
	parser.add_argument("--schema", default="schemas/clean_dataset.schema.json", help="JSON schema file for output validation")
	parser.add_argument("--validate", action="store_true", help="Validate output records against schema")
	parser.add_argument("--verify-sanitization", action="store_true", help="Verify sanitization of sensitive data")
	args = parser.parse_args()

	schema = load_schema(args.schema) if args.validate else None
	if args.validate and schema is None:
		print(json.dumps({"error": f"Schema file not found: {args.schema}"}, indent=2))
		return
	if args.validate and not HAS_JSONSCHEMA:
		print(json.dumps({"error": "jsonschema package not installed. Run: pip install jsonschema"}, indent=2))
		return

	rows = read_jsonl(args.input)
	cleaned_rows = []
	seen = set()
	duplicates = 0
	validation_errors = 0
	sanitization_issues = 0

	for row in rows:
		cleaned = clean_row(row)
		fp = row_fingerprint(cleaned)
		if args.dedup and fp in seen:
			duplicates += 1
			continue

		if args.validate:
			valid, error = validate_record(cleaned, schema)
			if not valid:
				validation_errors += 1
				print(json.dumps({
					"validation_error": error,
					"record": cleaned
				}, indent=2), file=__import__('sys').stderr)
				continue

		if args.verify_sanitization:
			sanitized, issues = verify_sanitization(cleaned)
			if not sanitized:
				sanitization_issues += 1
				for issue in issues:
					print(json.dumps({
						"sanitization_issue": issue,
						"record": cleaned
					}, indent=2), file=__import__('sys').stderr)

		seen.add(fp)
		cleaned_rows.append(cleaned)

	write_jsonl(args.output, cleaned_rows)

	result = {
		"input_records": len(rows),
		"output_records": len(cleaned_rows),
		"duplicates_removed": duplicates,
		"output": args.output
	}
	if args.validate:
		result["validation_errors"] = validation_errors
	if args.verify_sanitization:
		result["sanitization_issues"] = sanitization_issues
	print(json.dumps(result, indent=2, ensure_ascii=False))

if __name__ == "__main__":
	main()

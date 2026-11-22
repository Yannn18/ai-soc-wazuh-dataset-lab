#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


def get_nested(obj, path, default=None):
	cur = obj
	for part in path.split("."):
		if not isinstance(cur, dict):
			return default
		cur = cur.get(part)
		if cur is None:
			return default
	return cur


def make_event_id(record):
	base = "|".join([
		str(record.get("timestamp", "")),
		str(record.get("agent_name", "")),
		str(record.get("rule_id", "")),
		str(record.get("raw_event", ""))[:200]
	])
	return "evt-" + hashlib.sha256(base.encode()).hexdigest()[:16]


def is_custom_ai_soc_alert(alert):
	"""Check if alert is from custom ai-soc-pentest decoder"""
	decoded_as = get_nested(alert, "rule.decoded_as", "")
	program_name = get_nested(alert, "data.program_name", "")
	return decoded_as == "ai-soc-pentest" or program_name == "ai-soc-pentest"


def is_builtin_ssh_alert(alert):
	"""Check if alert is from Wazuh built-in SSH/sshd rules"""
	rule_groups = get_nested(alert, "rule.groups", [])
	if isinstance(rule_groups, str):
		rule_groups = [rule_groups]
	rule_id = get_nested(alert, "rule.id", 0)
	try:
		rule_id = int(rule_id)
	except (ValueError, TypeError):
		rule_id = 0
	# Wazuh built-in SSH rules are in 5700-5799 range
	ssh_rule_range = 5700 <= rule_id <= 5799
	ssh_groups = any(g in ["sshd", "authentication_failed", "authentication_success",
						   "invalid_login", "system_errors"] for g in rule_groups)
	return ssh_rule_range or ssh_groups


def extract_ssh_fields(alert):
	"""Extract fields specific to built-in SSH alerts"""
	data = alert.get("data", {}) if isinstance(alert.get("data", {}), dict) else {}
	return {
		"srcip": data.get("srcip") or data.get("src_ip") or data.get("source_ip"),
		"dstip": data.get("dstip") or data.get("dst_ip") or data.get("destination_ip"),
		"user": data.get("user") or data.get("username") or data.get("dstuser"),
		"srcport": data.get("srcport") or data.get("src_port"),
		"dstport": data.get("dstport") or data.get("dst_port"),
		"protocol": data.get("protocol"),
	}


def extract_custom_fields(alert):
	"""Extract fields from custom ai-soc-pentest alerts"""
	data = alert.get("data", {}) if isinstance(alert.get("data", {}), dict) else {}
	return {
		"scenario_id": data.get("scenario_id"),
		"attack_type": data.get("attack_type"),
		"mitre_tactic": data.get("mitre_tactic"),
		"mitre_technique": data.get("mitre_technique"),
		"payload_id": data.get("payload_id"),
		"tool": data.get("tool"),
		"intensity": data.get("intensity"),
	}


def map_builtin_rule_to_attack(rule_id, rule_groups):
	"""Map Wazuh built-in SSH rule IDs to attack types and MITRE"""
	rule_id = int(rule_id) if rule_id else 0
	groups = rule_groups if isinstance(rule_groups, list) else [rule_groups]

	# Authentication failed rules
	if rule_id in [5710, 5712, 5716] or "authentication_failed" in groups:
		return {
			"attack_type": "ssh_brute_force",
			"mitre_tactic": "Credential Access",
			"mitre_technique": "T1110.001"
		}
	# Successful authentication
	elif rule_id == 5715 or "authentication_success" in groups:
		return {
			"attack_type": "ssh_auth_success",
			"mitre_tactic": "Lateral Movement",
			"mitre_technique": "T1021.004"
		}
	# Privilege escalation (sudo)
	elif rule_id in [5718, 5760] or "privilege_escalation" in groups:
		return {
			"attack_type": "ssh_priv_esc",
			"mitre_tactic": "Privilege Escalation",
			"mitre_technique": "T1548.003"
		}
	# Invalid login / other
	elif rule_id in [5700, 5702, 5704, 5706, 5708]:
		return {
			"attack_type": "ssh_anomaly",
			"mitre_tactic": "Credential Access",
			"mitre_technique": "T1110"
		}
	return {
		"attack_type": "ssh_unknown",
		"mitre_tactic": "unknown",
		"mitre_technique": "unknown"
	}


def normalize(alert):
	data = alert.get("data", {}) if isinstance(alert.get("data", {}), dict) else {}

	source_ip = (
		data.get("srcip")
		or data.get("src_ip")
		or data.get("src")
		or data.get("source_ip")
	)

	destination_ip = (
		data.get("dstip")
		or data.get("dst_ip")
		or data.get("destination_ip")
	)

	rule_level = get_nested(alert, "rule.level")
	try:
		rule_level = int(rule_level) if rule_level is not None else None
	except ValueError:
		rule_level = None

	rule_id = get_nested(alert, "rule.id", "")
	rule_description = get_nested(alert, "rule.description", "")
	rule_groups = get_nested(alert, "rule.groups", [])

	# Determine alert source and extract appropriate fields
	is_custom = is_custom_ai_soc_alert(alert)
	is_builtin = is_builtin_ssh_alert(alert)

	agent_name = get_nested(alert, "agent.name", "unknown")
	agent_ip = get_nested(alert, "agent.ip", "")

	# Initialize record with defaults
	record = {
		"event_id": "",
		"timestamp": alert.get("timestamp"),
		"agent_name": agent_name,
		"agent_ip": agent_ip,
		"source_ip": source_ip,
		"destination_ip": destination_ip,
		"rule_id": str(rule_id),
		"rule_level": rule_level,
		"rule_description": rule_description,
		"rule_groups": rule_groups if isinstance(rule_groups, list) else [rule_groups] if rule_groups else [],
		"raw_event": alert.get("full_log", json.dumps(alert, ensure_ascii=False)),
		"scenario_id": "unmatched",
		"attack_type": "unknown",
		"mitre_tactic": "unknown",
		"mitre_technique": "unknown",
		"label": "unlabeled",
		"confidence": 0.0,
		"ground_truth_source": "none",
		"alert_source": "unknown"
	}

	if is_custom:
		record["alert_source"] = "custom_ai_soc"
		custom_fields = extract_custom_fields(alert)
		record.update({
			"scenario_id": custom_fields.get("scenario_id", "unmatched"),
			"attack_type": custom_fields.get("attack_type", "unknown"),
			"mitre_tactic": custom_fields.get("mitre_tactic", "unknown"),
			"mitre_technique": custom_fields.get("mitre_technique", "unknown"),
			"payload_id": custom_fields.get("payload_id"),
			"tool": custom_fields.get("tool"),
			"intensity": custom_fields.get("intensity"),
		})
	elif is_builtin:
		record["alert_source"] = "builtin_ssh"
		ssh_fields = extract_ssh_fields(alert)
		attack_info = map_builtin_rule_to_attack(rule_id, rule_groups)
		record.update({
			"source_ip": ssh_fields.get("srcip") or source_ip,
			"destination_ip": ssh_fields.get("dstip") or destination_ip,
			"ssh_user": ssh_fields.get("user"),
			"ssh_srcport": ssh_fields.get("srcport"),
			"ssh_dstport": ssh_fields.get("dstport"),
			"ssh_protocol": ssh_fields.get("protocol"),
			"attack_type": attack_info["attack_type"],
			"mitre_tactic": attack_info["mitre_tactic"],
			"mitre_technique": attack_info["mitre_technique"],
			"scenario_id": f"builtin_{attack_info['attack_type']}",
		})
	else:
		record["alert_source"] = "other"

	record["event_id"] = make_event_id(record)
	return record


def load_schema(schema_path="schemas/normalized_alert.schema.json"):
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


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--input", action="append", required=True, help="Wazuh alerts.json JSONL file(s) - can specify multiple")
	parser.add_argument("--output", default="datasets/normalized_alerts.jsonl")
	parser.add_argument("--schema", default="schemas/normalized_alert.schema.json", help="JSON schema file for output validation")
	parser.add_argument("--validate", action="store_true", help="Validate output records against schema")
	args = parser.parse_args()

	schema = load_schema(args.schema) if args.validate else None
	if args.validate and schema is None:
		print(json.dumps({"error": f"Schema file not found: {args.schema}"}, indent=2))
		return
	if args.validate and not HAS_JSONSCHEMA:
		print(json.dumps({"error": "jsonschema package not installed. Run: pip install jsonschema"}, indent=2))
		return

	out_path = Path(args.output)
	out_path.parent.mkdir(parents=True, exist_ok=True)

	total = 0
	written = 0
	validation_errors = 0

	with out_path.open("w", encoding="utf-8") as fout:
		for in_file in args.input:
			in_path = Path(in_file)
			with in_path.open("r", encoding="utf-8", errors="replace") as fin:
				for line in fin:
					total += 1
					line = line.strip()
					if not line:
						continue

					try:
						alert = json.loads(line)
					except json.JSONDecodeError:
						continue

					record = normalize(alert)

					if args.validate:
						valid, error = validate_record(record, schema)
						if not valid:
							validation_errors += 1
							print(json.dumps({
								"validation_error": error,
								"record": record
							}, indent=2), file=__import__('sys').stderr)
							continue

					fout.write(json.dumps(record, ensure_ascii=False) + "\n")
					written += 1

	result = {
		"inputs": args.input,
		"output": str(out_path),
		"total_lines": total,
		"written_records": written
	}
	if args.validate:
		result["validation_errors"] = validation_errors
	print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
	main()
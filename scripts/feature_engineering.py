#!/usr/bin/env python3
import argparse
import json
import math
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


def read_jsonl(path):
    rows = []
    p = Path(path)
    if not p.exists():
        return rows

    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_jsonl(path, rows):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    ent = 0.0

    for count in counts.values():
        p = count / total
        ent -= p * math.log2(p)

    return round(ent, 4)


def minute_bucket(timestamp):
    if not timestamp:
        return "unknown"

    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%dT%H:%MZ")
    except Exception:
        return "unknown"


def extract_status_code(text):
    if not text:
        return None

    m = re.search(r"\b(status|status_code)[=: ]+(\d{3})\b", str(text), re.I)
    if m:
        return int(m.group(2))

    return None


def user_agent_category(text):
    if not text:
        return "unknown"

    t = text.lower()

    if "curl" in t:
        return "curl"
    if "python" in t or "requests" in t:
        return "python_requests"
    if "mozilla" in t:
        return "browser"
    if "bot" in t:
        return "bot"
    return "other"


def derive_binary_label(label, confidence, ground_truth_source):
    """Derive binary label from base label and confidence."""
    if label == "benign":
        return "benign"
    if label == "malicious":
        return "malicious"
    if label in ["recon", "web_fingerprint", "vuln_scan_light"]:
        # Reconnaissance activities are considered malicious in binary classification
        return "malicious"
    if label in ["auth_attack", "web_attack"]:
        return "malicious"
    # Default for unlabeled/unknown
    return "unlabeled"


def derive_multi_class_label(label, attack_type, mitre_technique):
    """Derive multi-class label from label, attack_type, and MITRE technique."""
    # Map label/attack_type to multi-class enum values
    if label == "benign":
        return "benign"
    if label in ["recon", "web_fingerprint", "vuln_scan_light"]:
        return "recon"
    if attack_type in ["ssh_brute_force", "ssh_anomaly", "ssh_unknown"]:
        return "ssh_brute_force"
    if attack_type == "ssh_auth_success":
        return "ssh_auth_success"
    if attack_type == "ssh_priv_esc":
        return "ssh_priv_esc"
    if attack_type == "ssh_lateral":
        return "ssh_lateral"
    if attack_type == "web_login_failure":
        return "auth_attack"
    if attack_type == "web_input_attack":
        return "web_attack"
    if attack_type == "web_recon":
        return "recon"
    if attack_type == "fim_event":
        return "fim_event"
    if attack_type == "suspicious_command":
        return "suspicious_command"
    if attack_type == "benign_admin":
        return "benign"
    if attack_type == "auth_attack":
        return "auth_attack"
    if attack_type == "web_attack":
        return "web_attack"
    if attack_type == "unknown" and mitre_technique not in [None, "", "unknown", "none"]:
        # Has MITRE but unknown attack type
        if "T1110" in str(mitre_technique):
            return "ssh_brute_force"
        if "T1021" in str(mitre_technique):
            return "ssh_lateral"
        if "T1548" in str(mitre_technique):
            return "ssh_priv_esc"
    return "unknown"


def derive_source_of_truth(ground_truth_source, correlation_status):
    """Derive source of truth from ground truth source and correlation status."""
    if ground_truth_source == "ground_truth_correlated":
        return "ground_truth_correlated"
    if ground_truth_source == "ground_truth_only":
        return "ground_truth_only"
    if ground_truth_source == "wazuh_alert_only":
        return "wazuh_alert_only"
    if correlation_status == "matched_alert":
        return "ground_truth_correlated"
    if correlation_status == "ground_truth_without_alert":
        return "ground_truth_only"
    if correlation_status == "alert_without_ground_truth":
        return "wazuh_alert_only"
    return "ground_truth_only"


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


def main():
    parser = argparse.ArgumentParser(description="Add engineered features to AI SOC dataset")
    parser.add_argument("--input", default="datasets/final/dataset_clean.jsonl")
    parser.add_argument("--output", default="datasets/final/dataset_features.jsonl")
    parser.add_argument("--schema", default="schemas/dataset.schema.json", help="JSON schema file for output validation")
    parser.add_argument("--validate", action="store_true", help="Validate output records against schema")
    args = parser.parse_args()

    schema = load_schema(args.schema) if args.validate else None
    if args.validate and schema is None:
        print(json.dumps({"error": f"Schema file not found: {args.schema}"}, indent=2))
        return
    if args.validate and not HAS_JSONSCHEMA:
        print(json.dumps({"error": "jsonschema package not installed. Run: pip install jsonschema"}, indent=2))
        return

    rows = read_jsonl(args.input)

    count_per_source_ip = Counter(r.get("source_ip") or "unknown" for r in rows)
    count_per_agent = Counter(r.get("agent_name") or "unknown" for r in rows)
    count_per_rule = Counter(r.get("rule_id") or "unknown" for r in rows)
    count_per_minute = Counter(minute_bucket(r.get("timestamp")) for r in rows)

    enriched = []
    validation_errors = 0

    for r in rows:
        row = dict(r)

        full_log = row.get("full_log", "")
        source_ip = row.get("source_ip") or "unknown"
        agent_name = row.get("agent_name") or "unknown"
        rule_id = row.get("rule_id") or "unknown"
        bucket = minute_bucket(row.get("timestamp"))

        row["feature_full_log_length"] = len(full_log)
        row["feature_full_log_entropy"] = entropy(full_log)
        row["feature_event_count_source_ip"] = count_per_source_ip[source_ip]
        row["feature_event_count_agent"] = count_per_agent[agent_name]
        row["feature_event_count_rule"] = count_per_rule[rule_id]
        row["feature_event_count_minute"] = count_per_minute[bucket]
        row["feature_minute_bucket"] = bucket
        row["feature_status_code"] = extract_status_code(full_log)
        row["feature_user_agent_category"] = user_agent_category(full_log)
        try:
            row["feature_rule_level"] = int(row["rule_level"]) if row.get("rule_level") is not None else 0
        except ValueError:
            row["feature_rule_level"] = 0

        # High severity threshold is 7 per schema
        row["feature_is_high_severity"] = 1 if row["feature_rule_level"] >= 7 else 0
        row["feature_has_mitre"] = 0 if row.get("mitre_tactic") in (None, "", "unknown", "none") else 1

        # Derive label fields
        row["binary_label"] = derive_binary_label(
            row.get("label", "unlabeled"),
            row.get("confidence", 0.0),
            row.get("ground_truth_source", "none")
        )
        row["multi_class_label"] = derive_multi_class_label(
            row.get("label", "unlabeled"),
            row.get("attack_type", "unknown"),
            row.get("mitre_technique", "unknown")
        )
        row["source_of_truth"] = derive_source_of_truth(
            row.get("ground_truth_source", "none"),
            row.get("correlation_status")
        )

        if args.validate:
            valid, error = validate_record(row, schema)
            if not valid:
                validation_errors += 1
                print(json.dumps({
                    "validation_error": error,
                    "record": row
                }, indent=2), file=__import__('sys').stderr)
                continue

        enriched.append(row)

    write_jsonl(args.output, enriched)

    result = {
        "input_records": len(rows),
        "output_records": len(enriched),
        "output": args.output
    }
    if args.validate:
        result["validation_errors"] = validation_errors
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
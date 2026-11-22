#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


VALID_BINARY = {"benign", "malicious", "unlabeled"}
VALID_MULTI_CLASS = {
    "unknown",
    "benign",
    "recon",
    "auth_attack",
    "web_attack",
    "suspicious_command",
    "fim_event",
    "ssh_brute_force",
    "ssh_auth_success",
    "ssh_priv_esc",
    "ssh_lateral"
}
VALID_SOURCE_OF_TRUTH = {"ground_truth_correlated", "ground_truth_only", "wazuh_alert_only"}


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


def calibrate_confidence(confidence, correlation_status, ground_truth_source, rule_level, mitre_technique):
    """
    Calibrate confidence based on multiple factors.

    Factors that increase confidence:
    - Matched alert + ground truth (ground_truth_correlated)
    - Higher rule severity
    - Known MITRE technique
    - Ground truth only with high confidence

    Factors that decrease confidence:
    - Alert without ground truth
    - Unknown MITRE technique
    - Low rule severity
    """
    calibrated = float(confidence)

    # Base adjustment by correlation status
    if correlation_status == "matched_alert":
        calibrated = max(calibrated, 0.9)
    elif correlation_status == "ground_truth_without_alert":
        calibrated = max(calibrated, 0.8)
    elif correlation_status == "alert_without_ground_truth":
        calibrated = min(calibrated, 0.5)

    # Adjust by rule level (0-16 scale)
    if rule_level is not None:
        try:
            rl = int(rule_level)
            if rl >= 10:
                calibrated = min(1.0, calibrated + 0.1)
            elif rl >= 7:
                calibrated = min(1.0, calibrated + 0.05)
            elif rl <= 3:
                calibrated = max(0.0, calibrated - 0.1)
        except (ValueError, TypeError):
            pass

    # Adjust by MITRE technique
    if mitre_technique and mitre_technique not in ["unknown", "none", ""]:
        calibrated = min(1.0, calibrated + 0.05)

    # Ground truth source adjustment
    if ground_truth_source == "ground_truth_correlated":
        calibrated = min(1.0, calibrated + 0.05)
    elif ground_truth_source == "wazuh_alert_only":
        calibrated = max(0.0, calibrated - 0.1)

    return round(max(0.0, min(1.0, calibrated)), 2)


def final_label(row):
    label = row.get("label", "unlabeled")
    attack_type = row.get("attack_type", "unknown")
    mitre_technique = row.get("mitre_technique", "unknown")
    correlation_status = row.get("correlation_status")
    ground_truth_source = row.get("ground_truth_source", "none")
    rule_level = row.get("rule_level")

    # Ensure label is in valid set
    if label not in VALID_BINARY:
        if attack_type == "benign" or label == "benign":
            label = "benign"
        elif attack_type in VALID_MULTI_CLASS and attack_type not in ("unknown", "benign"):
            label = "malicious"
        elif label in ["recon", "web_fingerprint", "vuln_scan_light", "auth_attack", "web_attack"]:
            label = "malicious"
        else:
            label = "unlabeled"

    # Ensure multi_class_label is in valid set
    multi_class = row.get("multi_class_label", attack_type)
    if multi_class not in VALID_MULTI_CLASS:
        # Map attack_type to multi_class
        if attack_type in ["ssh_brute_force", "ssh_anomaly", "ssh_unknown"]:
            multi_class = "ssh_brute_force"
        elif attack_type == "ssh_auth_success":
            multi_class = "ssh_auth_success"
        elif attack_type == "ssh_priv_esc":
            multi_class = "ssh_priv_esc"
        elif attack_type == "ssh_lateral":
            multi_class = "ssh_lateral"
        elif attack_type in ["web_login_failure", "auth_attack"]:
            multi_class = "auth_attack"
        elif attack_type in ["web_input_attack", "web_attack"]:
            multi_class = "web_attack"
        elif attack_type == "web_recon":
            multi_class = "recon"
        elif attack_type == "fim_event":
            multi_class = "fim_event"
        elif attack_type == "suspicious_command":
            multi_class = "suspicious_command"
        elif attack_type in ["benign", "benign_admin"]:
            multi_class = "benign"
        elif label in ["recon", "web_fingerprint", "vuln_scan_light"]:
            multi_class = "recon"
        else:
            multi_class = "unknown"

    # Ensure source_of_truth is in valid set
    source = row.get("source_of_truth")
    if source not in VALID_SOURCE_OF_TRUTH:
        if correlation_status == "matched_alert":
            source = "ground_truth_correlated"
        elif correlation_status == "ground_truth_without_alert":
            source = "ground_truth_only"
        elif correlation_status == "alert_without_ground_truth":
            source = "wazuh_alert_only"
        elif ground_truth_source in VALID_SOURCE_OF_TRUTH:
            source = ground_truth_source
        else:
            source = "ground_truth_only"

    # Calibrate confidence
    confidence = row.get("confidence", 0.0)
    calibrated_confidence = calibrate_confidence(
        confidence, correlation_status, ground_truth_source, rule_level, mitre_technique
    )

    row["binary_label"] = label
    row["multi_class_label"] = multi_class
    row["source_of_truth"] = source
    row["confidence"] = calibrated_confidence

    return row


def main():
    parser = argparse.ArgumentParser(description="Finalize labels for AI SOC dataset")
    parser.add_argument("--input", default="datasets/featured_combined.jsonl")
    parser.add_argument("--output", default="datasets/final/dataset_final.jsonl")
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
    labeled = []
    validation_errors = 0

    for r in rows:
        labeled_row = final_label(r)

        if args.validate:
            valid, error = validate_record(labeled_row, schema)
            if not valid:
                validation_errors += 1
                print(json.dumps({
                    "validation_error": error,
                    "record": labeled_row
                }, indent=2), file=__import__('sys').stderr)
                continue

        labeled.append(labeled_row)

    write_jsonl(args.output, labeled)

    result = {
        "input_records": len(rows),
        "output_records": len(labeled),
        "output": args.output
    }
    if args.validate:
        result["validation_errors"] = validation_errors
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
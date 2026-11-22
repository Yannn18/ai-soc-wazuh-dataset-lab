#!/usr/bin/env python3
import argparse
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd

try:
    import jsonschema
    HAS_JSONSCHEMA = True
except ImportError:
    HAS_JSONSCHEMA = False


def now_utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git_commit():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        return "unknown"


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


def quality_gates(df):
    """Run quality gates on the dataset and return (passed, issues)."""
    issues = []

    # Gate 1: Minimum record count
    if len(df) < 100:
        issues.append(f"Gate 1 FAILED: Too few records ({len(df)} < 100)")

    # Gate 2: Binary label distribution - no class should be > 95% or < 5% (unless very small dataset)
    if "binary_label" in df.columns:
        label_counts = df["binary_label"].value_counts()
        total = len(df)
        for label, count in label_counts.items():
            pct = (count / total) * 100
            if total >= 1000 and (pct > 95 or pct < 5):
                issues.append(f"Gate 2 FAILED: Binary label '{label}' is {pct:.1f}% of dataset (expected 5-95%)")

    # Gate 3: Multi-class label distribution - at least 3 classes represented
    if "multi_class_label" in df.columns:
        class_counts = df["multi_class_label"].value_counts()
        if len(class_counts) < 3:
            issues.append(f"Gate 3 FAILED: Only {len(class_counts)} multi-class labels (expected >= 3)")

    # Gate 4: No null timestamps
    null_timestamps = df["timestamp"].isna().sum() if "timestamp" in df.columns else 0
    if null_timestamps > 0:
        issues.append(f"Gate 4 FAILED: {null_timestamps} records with null timestamp")

    # Gate 5: All records have event_id
    null_event_id = df["event_id"].isna().sum() if "event_id" in df.columns else 0
    if null_event_id > 0:
        issues.append(f"Gate 5 FAILED: {null_event_id} records with null event_id")

    # Gate 6: Confidence scores in range [0, 1]
    if "confidence" in df.columns:
        invalid_conf = ((df["confidence"] < 0) | (df["confidence"] > 1)).sum()
        if invalid_conf > 0:
            issues.append(f"Gate 6 FAILED: {invalid_conf} records with confidence outside [0, 1]")

    # Gate 7: Feature columns present
    required_features = [
        "feature_full_log_length", "feature_full_log_entropy",
        "feature_event_count_source_ip", "feature_event_count_agent",
        "feature_event_count_rule", "feature_event_count_minute",
        "feature_minute_bucket", "feature_rule_level",
        "feature_is_high_severity", "feature_has_mitre"
    ]
    missing_features = [f for f in required_features if f not in df.columns]
    if missing_features:
        issues.append(f"Gate 7 FAILED: Missing feature columns: {missing_features}")

    # Gate 8: Sanitization check - no unmasked IPs
    ip_columns = ["source_ip", "destination_ip"]
    for col in ip_columns:
        if col in df.columns:
            unmasked = df[col].dropna().apply(lambda x: isinstance(x, str) and x.count('.') == 3 and not x.endswith('.X')).sum()
            if unmasked > 0:
                issues.append(f"Gate 8 FAILED: {unmasked} records with potentially unmasked IP in {col}")

    # Gate 9: Label fields present
    required_labels = ["binary_label", "multi_class_label", "source_of_truth"]
    for label_col in required_labels:
        if label_col not in df.columns:
            issues.append(f"Gate 9 FAILED: Missing required label column: {label_col}")

    # Gate 10: No duplicate event_ids
    if "event_id" in df.columns:
        dup_count = df["event_id"].duplicated().sum()
        if dup_count > 0:
            issues.append(f"Gate 10 FAILED: {dup_count} duplicate event_ids")

    return len(issues) == 0, issues


def main():
    parser = argparse.ArgumentParser(description="Export final AI SOC dataset")
    parser.add_argument("--input", default="datasets/final/dataset_final.jsonl")
    parser.add_argument("--output-dir", default="datasets/final")
    parser.add_argument("--version", default="v0.1.0")
    parser.add_argument("--schema", default="schemas/dataset.schema.json", help="JSON schema file for validation")
    parser.add_argument("--validate", action="store_true", help="Validate records against schema")
    parser.add_argument("--quality-gates", action="store_true", help="Run quality gates")
    args = parser.parse_args()

    schema = load_schema(args.schema) if args.validate else None
    if args.validate and schema is None:
        print(json.dumps({"error": f"Schema file not found: {args.schema}"}, indent=2))
        return
    if args.validate and not HAS_JSONSCHEMA:
        print(json.dumps({"error": "jsonschema package not installed. Run: pip install jsonschema"}, indent=2))
        return

    rows = read_jsonl(args.input)
    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Validate records if requested
    validation_errors = 0
    if args.validate:
        valid_rows = []
        for row in rows:
            valid, error = validate_record(row, schema)
            if not valid:
                validation_errors += 1
                print(json.dumps({
                    "validation_error": error,
                    "record": row
                }, indent=2), file=__import__('sys').stderr)
            else:
                valid_rows.append(row)
        rows = valid_rows

    df = pd.DataFrame(rows)

    # Run quality gates
    gates_passed = True
    quality_issues = []
    if args.quality_gates:
        gates_passed, quality_issues = quality_gates(df)
        if not gates_passed:
            print(json.dumps({
                "quality_gates": "FAILED",
                "issues": quality_issues
            }, indent=2), file=__import__('sys').stderr)
            return
        else:
            print(json.dumps({
                "quality_gates": "PASSED",
                "issues": []
            }, indent=2))

    jsonl_out = outdir / "dataset.jsonl"
    csv_out = outdir / "dataset.csv"
    parquet_out = outdir / "dataset.parquet"
    schema_out = outdir / "schema.json"
    readme_out = outdir / "README_dataset.md"
    card_out = outdir / "DATASET_CARD.json"

    df.to_json(jsonl_out, orient="records", lines=True, force_ascii=False)
    df.to_csv(csv_out, index=False)
    df.to_parquet(parquet_out, index=False)

    # Generate schema from data
    inferred_schema = {
        "fields": {
            k: [type(v).__name__ for v in df[k].dropna().unique()[:10]]
            for k in sorted(df.columns)
        }
    }
    inferred_schema["dataset_version"] = args.version
    inferred_schema["generated_at"] = now_utc()
    inferred_schema["git_commit"] = git_commit()
    schema_out.write_text(json.dumps(inferred_schema, indent=2, ensure_ascii=False), encoding="utf-8")

    label_dist = df["binary_label"].value_counts(dropna=False).to_dict() if "binary_label" in df else {}
    class_dist = df["multi_class_label"].value_counts(dropna=False).to_dict() if "multi_class_label" in df else {}

    card = {
        "dataset_name": "ai-soc-wazuh-dataset",
        "version": args.version,
        "generated_at": now_utc(),
        "git_commit": git_commit(),
        "source": "Wazuh lab evidence pack + ground truth",
        "total_records": len(df),
        "label_distribution": label_dist,
        "multi_class_distribution": class_dist,
        "formats": {
            "jsonl": str(jsonl_out),
            "csv": str(csv_out),
            "parquet": str(parquet_out),
            "schema": str(schema_out)
        },
        "intended_use": [
            "AI SOC training",
            "ML baseline",
            "LLM-assisted SOC experiment",
            "CEH/SOC lab portfolio"
        ],
        "not_for": [
            "attacking public systems",
            "training offensive malware generation",
            "production deployment without validation"
        ],
        "known_limitations": [
            "lab-generated dataset",
            "requires review before publication",
            "sanitized IP and sensitive fields",
            "class balance depends on scenario mix"
        ]
    }
    card_out.write_text(json.dumps(card, indent=2, ensure_ascii=False), encoding="utf-8")

    readme = f"""# AI SOC Wazuh Dataset

## Version
{args.version}

## Generated
{card['generated_at']}

## Git Commit
{card['git_commit']}

## Source
Dataset dibuat dari evidence pack lab Wazuh:
- ground truth JSONL
- Wazuh alerts
- archive sample
- script execution log
- correlation pipeline

## Files
- `dataset.jsonl` untuk LLM dan pipeline streaming
- `dataset.csv` untuk eksplorasi cepat
- `dataset.parquet` untuk efisiensi analitik
- `schema.json` untuk struktur field
- `DATASET_CARD.json` untuk metadata dataset

## Label
Binary label:
{json.dumps(label_dist, indent=2, ensure_ascii=False)}

Multi-class label:
{json.dumps(class_dist, indent=2, ensure_ascii=False)}

## Quality Gates
{"PASSED" if gates_passed else "FAILED"}
{f"Issues: {quality_issues}" if quality_issues else "All gates passed"}

## Ethical Use
Dataset ini hanya untuk edukasi, riset defensif, AI SOC, dan lab legal. Tidak untuk menyerang sistem publik.

## Known Limitations
- Dataset berasal dari lab tertutup.
- Distribusi kelas bergantung pada skenario.
- Field tertentu dapat kosong jika alert Wazuh tidak menyediakan data tersebut.
- Data perlu review sebelum publikasi eksternal.

## Leakage Warning
Jangan gunakan `run_id`, `scenario_id`, `payload_id`,
`label`, `binary_label`, atau `multi_class_label` sebagai
fitur input training langsung.
"""
    readme_out.write_text(readme, encoding="utf-8")

    result = {
        "records": len(df),
        "jsonl": str(jsonl_out),
        "csv": str(csv_out),
        "parquet": str(parquet_out),
        "schema": str(schema_out),
        "dataset_card": str(card_out),
        "readme": str(readme_out)
    }
    if args.validate:
        result["validation_errors"] = validation_errors
    if args.quality_gates:
        result["quality_gates_passed"] = gates_passed
        if not gates_passed:
            result["quality_issues"] = quality_issues
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
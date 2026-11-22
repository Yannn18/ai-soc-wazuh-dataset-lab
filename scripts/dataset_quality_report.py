#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from pathlib import Path

LEAKAGE_FIELDS = {
	"expected_label",
	"label",
	"binary_label",
	"multi_class_label",
	"scenario_id",
	"run_id",
	"payload_id"
}

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

def duplicate_count(rows):
	seen = set()
	dup = 0
	for r in rows:
		key = (
			r.get("timestamp"),
			r.get("agent_name"),
			r.get("rule_id"),
			r.get("full_log")
		)
		if key in seen:
			dup += 1
		else:
			seen.add(key)
	return dup

def missing_count(rows, field):
	return sum(1 for r in rows if r.get(field) in (None, "", "unknown"))

def main():
	parser = argparse.ArgumentParser(description="Generate AI SOC dataset quality report")
	parser.add_argument("--input", default="datasets/final/dataset_final.jsonl")
	parser.add_argument("--report-json", default="reports/chapter9/dataset_quality_report.json")
	parser.add_argument("--report-md", default="reports/chapter9/dataset_quality_report.md")
	args = parser.parse_args()

	rows = read_jsonl(args.input)

	label_dist = Counter(r.get("binary_label", "unknown") for r in rows)
	class_dist = Counter(r.get("multi_class_label", "unknown") for r in rows)
	scenario_dist = Counter(r.get("scenario_id", "unknown") for r in rows)
	correlation_dist = Counter(r.get("correlation_status", "unknown") for r in rows)
	source_truth_dist = Counter(r.get("source_of_truth", "unknown") for r in rows)

	total = len(rows)

	report = {
		"dataset": args.input,
		"total_records": total,
		"label_distribution": dict(label_dist),
		"multi_class_distribution": dict(class_dist),
		"scenario_distribution": dict(scenario_dist),
		"correlation_status_distribution": dict(correlation_dist),
		"source_of_truth_distribution": dict(source_truth_dist),
		"duplicate_count": duplicate_count(rows),
		"missing": {
			"timestamp": missing_count(rows, "timestamp"),
			"agent_name": missing_count(rows, "agent_name"),
			"rule_id": missing_count(rows, "rule_id"),
			"full_log": missing_count(rows, "full_log"),
			"binary_label": missing_count(rows, "binary_label"),
			"multi_class_label": missing_count(rows,
			"multi_class_label")
			},
			"leakage_warning": [
				"Jangan gunakan expected_label, label, binary_label, multi_class_label, scenario_id, run_id, payload_id sebagai fitur training langsung.",
				"Pisahkan kolom fitur, label, dan metadata sebelum training."
			],
			"known_limitations": [
				"Dataset berasal dari lab tertutup.",
				"Distribusi kelas mungkin belum mewakili produksi.",
				"Unmatched alert perlu review analis.",
				"Ground truth without alert bukan error; itu sinyal coverage gap.",
				"Feature sederhana belum menggantikan analisis mendalam."
		]
	}
	out_json = Path(args.report_json)
	out_json.parent.mkdir(parents=True, exist_ok=True)
	out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

	md = []
	md.append("# Dataset Quality Report")
	md.append("")
	md.append(f"- Dataset: `{args.input}`")
	md.append(f"- Total records: `{total}`")
	md.append("")
	md.append("## Label Distribution")
	for k, v in label_dist.items():
		md.append(f"- {k}: {v}")
	md.append("")
	md.append("## Multi-Class Distribution")
	for k, v in class_dist.items():
		md.append(f"- {k}: {v}")
	md.append("")
	md.append("## Correlation Status")
	for k, v in correlation_dist.items():
		md.append(f"- {k}: {v}")
	md.append("")
	md.append("## Source of Truth")
	for k, v in source_truth_dist.items():
		md.append(f"- {k}: {v}")
	md.append("")
	md.append("## Data Quality")
	md.append(f"- Duplicate count: {report['duplicate_count']}")
	for k, v in report["missing"].items():
		md.append(f"- Missing {k}: {v}")
	md.append("")
	md.append("## Leakage Warning")
	for item in report["leakage_warning"]:
		md.append(f"- {item}")
	md.append("")
	md.append("## Known Limitations")
	for item in report["known_limitations"]:
		md.append(f"- {item}")

	out_md = Path(args.report_md)
	out_md.parent.mkdir(parents=True, exist_ok=True)
	out_md.write_text("\n".join(md) + "\n", encoding="utf-8")

	print(json.dumps(report, indent=2, ensure_ascii=False))

if __name__ == "__main__":
	main()

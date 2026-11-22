#!/usr/bin/env python3
import argparse
import json
from pathlib import Path

def fmt_float(x):
	if x is None:
		return "N/A"
	try:
		return f"{float(x):.4f}"
	except Exception:
		return str(x)

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--input", default="reports/final/model_baseline_report.json")
	parser.add_argument("--output", default="reports/final/model_baseline_report.md")
	args = parser.parse_args()

	data = json.loads(Path(args.input).read_text(encoding="utf-8"))

	lines = []
	lines.append("# Model Baseline Report")
	lines.append("")
	lines.append(f"- Dataset: `{data.get('dataset')}`")
	lines.append(f"- Records used: `{data.get('records_used')}`")
	lines.append("")
	lines.append("## Label Distribution")
	for k, v in data.get("label_distribution", {}).items():
		lines.append(f"- {k}: {v}")

	lines.append("")
	lines.append("## Supervised Models")
	for name, result in data.get("supervised_models", {}).items():
		lines.append("")
		lines.append(f"### {name}")
		lines.append("")
		lines.append(f"- Train records: {result.get('train_records')}")
		lines.append(f"- Test records: {result.get('test_records')}")
		lines.append(f"- False Positive Rate: {fmt_float(result.get('false_positive_rate'))}")
		lines.append(f"- False Negative Rate: {fmt_float(result.get('false_negative_rate'))}")
		lines.append(f"- Confusion Matrix: `{result.get('confusion_matrix')}`")

		report = result.get("classification_report", {})
		lines.append("")
		lines.append("| Class | Precision | Recall | F1-score | Support |")
		lines.append("|---|---:|---:|---:|---:|")
		for cls in ["benign", "malicious"]:
			r = report.get(cls, {})
			lines.append(
				f"| {cls} | {fmt_float(r.get('precision'))} | "
				f"{fmt_float(r.get('recall'))} | "
				f"{fmt_float(r.get('f1-score'))} | "
				f"{r.get('support', 0)} |"
			)

	lines.append("")
	lines.append("## Isolation Forest")
	iso = data.get("isolation_forest", {})
	for k, v in iso.items():
		lines.append(f"- {k}: {v}")

	lines.append("")
	lines.append("## Rule-Based Baseline")
	rb = data.get("rule_based_baseline", {})
	lines.append(f"- Rule: `{rb.get('rule')}`")
	lines.append(f"- False Positive Rate: {fmt_float(rb.get('false_positive_rate'))}")
	lines.append(f"- False Negative Rate: {fmt_float(rb.get('false_negative_rate'))}")
	lines.append(f"- Confusion Matrix: `{rb.get('confusion_matrix')}`")
	lines.append("")
	lines.append("## Catatan Kritis")
	lines.append("- Jangan membaca akurasi sendirian.")
	lines.append("- Perhatikan false negative untuk malicious event.")
	lines.append("- Perhatikan false positive untuk beban analis SOC.")
	lines.append("- Bandingkan model ML dengan baseline rule-based.")
	lines.append("- Jika dataset kecil, hasil hanya bukti pipeline, bukan klaim performa produksi.")

	out = Path(args.output)
	out.parent.mkdir(parents=True, exist_ok=True)
	out.write_text("\n".join(lines) + "\n", encoding="utf-8")

	print(f"Report written to {out}")

if __name__ == "__main__":
	main()

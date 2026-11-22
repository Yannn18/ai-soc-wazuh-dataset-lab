#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

DANGEROUS_PATTERNS = {
	"private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
	"password_assignment": r"(?i)(password|passwd|pwd)\s*[:=]\s*[^\\s,]+",
	"api_key": r"(?i)(api_key|apikey|token|secret)\s*[:=]\s*[^\\s,]+",
	"public_ip": r"\b(?!10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)(?:\d{1,3}\ .){3}\d{1,3}\b",
	"email": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
	"internal_domain_hint": r"(?i)\b(corp|internal|intranet|prod|production)\.[A-Za-z0-9.-]+"
}

def scan_file(path):
	text = Path(path).read_text(encoding="utf-8", errors="replace")
	findings = []

	for name, pattern in DANGEROUS_PATTERNS.items():
		matches = re.findall(pattern, text)
		if matches:
			findings.append({
				"type": name,
				"count": len(matches)
			})
	return findings

def main():
	parser = argparse.ArgumentParser(description="Check dataset before public release")
	parser.add_argument("--paths", nargs="+", default=[
		"datasets/final/dataset.jsonl",
		"datasets/final/dataset.csv",
		"datasets/final/README_dataset.md",
		"datasets/final/DATASET_CARD.json"
	])
	parser.add_argument("--report", default="reports/final/public_release_check.json")
	args = parser.parse_args()

	results = []
	total_findings = 0

	for path in args.paths:
		p = Path(path)
		if not p.exists():
			results.append({
				"path": path,
				"exists": False,
				"findings": []
			})
			continue

		findings = scan_file(p)
		total_findings += len(findings)

		results.append({
			"path": path,
			"exists": True,
			"findings": findings
		})

	report = {
		"safe_to_publish": total_findings == 0,
		"results": results,
		"recommendation": "Publish only if safe_to_publish is true and human review is complete."
	}

	out = Path(args.report)
	out.parent.mkdir(parents=True, exist_ok=True)
	out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

	print(json.dumps(report, indent=2, ensure_ascii=False))

	if total_findings:
		raise SystemExit(1)

if __name__ == "__main__":
	main()

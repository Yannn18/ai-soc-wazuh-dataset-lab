#!/usr/bin/env python3
import argparse
import json
from collections import Counter
from pathlib import Path

def read_jsonl(path):
	rows = []
	p = Path(path)
	if not p.exists():
		return rows
	for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
		if line.strip():
			rows.append(json.loads(line))
	return rows

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--input", default="payloads/payload_catalog_merged.jsonl")
	parser.add_argument("--output", default="reports/chapter6/payload_catalog_summary.md")
	args = parser.parse_args()

	rows = read_jsonl(args.input)

	by_category = Counter(r.get("payload_category", "unknown") for r in rows)
	by_creator = Counter(r.get("created_by", "unknown") for r in rows)
	by_label = Counter(r.get("expected_label", "unknown") for r in rows)
	by_safety = Counter(r.get("safety_status", "unknown") for r in rows)

	lines = []
	lines.append("# Payload Catalog Summary")
	lines.append("")
	lines.append(f"Total payload: {len(rows)}")
	lines.append("")
	lines.append("## By Category")
	for k, v in by_category.items():
		lines.append(f"- {k}: {v}")
	lines.append("")
	lines.append("## By Creator")
	for k, v in by_creator.items():
		lines.append(f"- {k}: {v}")
	lines.append("")
	lines.append("## By Expected Label")
	for k, v in by_label.items():
		lines.append(f"- {k}: {v}")
	lines.append("")
	lines.append("## By Safety Status")
	for k, v in by_safety.items():
		lines.append(f"- {k}: {v}")

	out = Path(args.output)
	out.parent.mkdir(parents=True, exist_ok=True)
	out.write_text("\n".join(lines) + "\n", encoding="utf-8")

	print("\n".join(lines))

if __name__ == "__main__":
	main()

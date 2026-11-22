#!/usr/bin/env python3
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

def now_utc():
	return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def count_lines(path):
	p = Path(path)
	if not p.exists():
		return 0
	return sum(1 for _ in p.open("r", encoding="utf-8", errors="replace"))

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--run-dir", required=True)
	args = parser.parse_args()

	run_dir = Path(args.run_dir)

	manifest = {
		"run_id": run_dir.name,
		"created_at": now_utc(),
		"files": {},
		"line_counts": {
			"ground_truth": count_lines(run_dir / "ground_truth.jsonl"),
			"wazuh_alerts": count_lines(run_dir / "wazuh_alerts.jsonl"),
			"wazuh_archives_sample": count_lines(run_dir / "wazuh_archives_sample.jsonl"),
			"dataset_candidate": count_lines(run_dir / "dataset_candidate.jsonl")
		}
	}

	for p in sorted(run_dir.rglob("*")):
		if p.is_file():
			manifest["files"][str(p.relative_to(run_dir))] ={
			"size_bytes": p.stat().st_size
		}

	out = run_dir / "MANIFEST.json"
	out.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
	print(json.dumps(manifest, indent=2, ensure_ascii=False))

if __name__ == "__main__":
	main()

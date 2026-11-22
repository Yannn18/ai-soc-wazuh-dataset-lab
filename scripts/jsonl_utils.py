#!/usr/bin/env python3
import json
from pathlib import Path

def read_jsonl_stream(path):
	"""
	Membaca JSONL baris demi baris.
	Cocok untuk alerts.json, archives.json, ground_truth.jsonl.
	"""
	p = Path(path)
	if not p.exists():
		return

	with p.open("r", encoding="utf-8", errors="replace") as f:

		for line_no, line in enumerate(f, start=1):
			line = line.strip()
			if not line:
				continue
		try:
			yield json.loads(line)
		except json.JSONDecodeError as e:
			yield {
				"_parse_error": True,
				"_line_no": line_no,
				"_error": str(e),
				"_raw": line[:500]
			}

def write_jsonl(path, records):
	p = Path(path)
	p.parent.mkdir(parents=True, exist_ok=True)

	with p.open("w", encoding="utf-8") as f:
		for r in records:
			f.write(json.dumps(r, ensure_ascii=False) + "\n")

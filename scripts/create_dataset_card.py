#!/usr/bin/env python3
import argparse
import json
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

def now_utc():
	return
datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def git_commit():
	try:
		return subprocess.check_output(
			["git", "rev-parse", "HEAD"],
			text=True
		).strip()
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
			if not line:
				continue
			try:
				rows.append(json.loads(line))
			except json.JSONDecodeError:
				pass
	return rows

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--dataset", default="datasets/normalized_alerts.jsonl")
	parser.add_argument("--version", required=True)
	parser.add_argument("--output", default="datasets/DATASET_CARD.json")
	args = parser.parse_args()
	rows = read_jsonl(args.dataset)
	labels = Counter(r.get("label", "unknown") for r in rows)
	attack_types = Counter(r.get("attack_type", "unknown") for r in rows)
	scenarios = Counter(r.get("scenario_id", "unknown") for r in rows)

	card = {
		"dataset_name": "ai-soc-wazuh-dataset",
		"version": args.version,
		"generated_at": now_utc(),
		"git_commit": git_commit(),
		"dataset_file": args.dataset,
		"total_events": len(rows),
		"label_distribution": dict(labels),
		"attack_type_distribution": dict(attack_types),
		"scenario_distribution": dict(scenarios),
		"schema": "schemas/final_dataset.schema.json",
		"ground_truth": "ground-truth/ground_truth.jsonl",
		"lab_config": [
			"configs/lab.env",
			"configs/assets.json",
			"configs/label_taxonomy.json",
			"configs/mitre_mapping.json"
		],
		"known_limitations": [
			"dataset berasal dari lab tertutup",
			"label malicious berasal dari skenario terkontrol",
			"belum mewakili semua variasi serangan dunia nyata",
			"field source_ip dapat kosong jika alert tidak menyediakan IP eksplisit",
			"mapping MITRE perlu review analis untuk skenario kompleks"
		],
		"ethical_use": [
			"hanya untuk edukasi, riset, dan pengembangan AI SOC legal",
			"tidak untuk menyerang sistem publik",
			"hapus data sensitif sebelum publikasi"
		]
	}

	out = Path(args.output)
	out.parent.mkdir(parents=True, exist_ok=True)
	out.write_text(json.dumps(card, indent=2, ensure_ascii=False), encoding="utf-8")

	print(json.dumps(card, indent=2, ensure_ascii=False))

if __name__ == "__main__":
	main()

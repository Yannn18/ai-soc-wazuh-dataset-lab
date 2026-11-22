#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import requests

def read_text(path):
	p = Path(path)
	if not p.exists():
		return ""
	return p.read_text(encoding="utf-8", errors="replace")

def main():
	api_key = os.environ.get("OLLAMA_API_KEY")
	if not api_key:
		raise SystemExit("[ERROR] OLLAMA_API_KEY belum di-export")

	parser = argparse.ArgumentParser(description="Generate AI-assisted SOC final report using Ollama")
	parser.add_argument("--ollama-url", default=os.environ.get("OLLAMA_URL", "https://ollama.com/api/chat"))
	parser.add_argument("--model", default="nemotron-3-super")
	parser.add_argument("--prompt", default="prompts/final_soc_report.prompt.txt")
	parser.add_argument("--quality-report", default="reports/final/dataset_quality_report.md")
	parser.add_argument("--model-report", default="reports/final/model_baseline_report.md")
	parser.add_argument("--dataset-card", default="datasets/final/DATASET_CARD.json")
	parser.add_argument("--output", default="reports/final/AI_ASSISTED_SOC_REPORT.md")
	args = parser.parse_args()

	prompt = read_text(args.prompt)
	quality_report = read_text(args.quality_report)
	model_report = read_text(args.model_report)
	dataset_card = read_text(args.dataset_card)

	final_prompt = f""" {prompt}

DATASET_CARD:
{dataset_card[:8000]}

QUALITY_REPORT:
{quality_report[:8000]}

MODEL_REPORT:
{model_report[:8000]}

Buat laporan final berbasis data di atas.
"""
	headers = {
		"Authorization": f"Bearer {api_key}",
		"Content-Type": "application/json"
	}

	body = {
		"model": args.model,
		"messages": [{"role": "user", "content": final_prompt}],
		"stream": False
	}

	r = requests.post(args.ollama_url, headers=headers, json=body, timeout=180)
	#r.raise_for_status()
	if not r.ok:
		raise SystemExit(f"[ERROR] {r.status_code}: {r.text[:300]}")

	data = r.json()
	text = data.get("message", {}).get("content", "")

	if not text.strip():
		raise SystemExit(f"[ERROR] empty model response: {json.dumps(data)[:500]}")

	out = Path(args.output)
	out.parent.mkdir(parents=True, exist_ok=True)
	out.write_text(text, encoding="utf-8")

	print(f"AI-assisted SOC report written to {out}")

if __name__ == "__main__":
	main()

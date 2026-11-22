#!/usr/bin/env python3
import argparse
import json
import os
import re
import requests
from datetime import datetime, timezone
from pathlib import Path

BLOCKLIST = [
	"rm -rf",
	"mkfs",
	"dd if=",
	":(){",
	"chmod -R 777 /",
	"curl http://",
	"wget http://",
	"powershell",
	"Invoke-WebRequest",
	"nc -e",
	"netcat -e",
	"reverse shell",
	"meterpreter",
	"mimikatz",
	"credential",
	"token",
	"api_key",
	"secret"
]

ALLOWED_CATEGORIES = {
	"sql_injection_pattern_dummy",
	"xss_pattern_dummy",
	"path_pattern_dummy",

	"command_pattern_dummy_non_destructive",
	"username_dummy",
	"password_dummy",
	"user_agent_dummy",
	"benign_path",
	"suspicious_path_dummy"
}

def now_utc():
	return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def extract_json_array(text):
	start = text.find("[")
	end = text.rfind("]")
	if start == -1 or end == -1 or end <= start:
		raise ValueError("JSON array tidak ditemukan")
	return json.loads(text[start:end+1])

def is_safe_payload(payload):
	low = payload.lower()
	for bad in BLOCKLIST:
		if bad.lower() in low:
			return False, f"blocked keyword: {bad}"
	if re.search(r"https?://(?!192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|localhost|127\.0\.0\.1)", payload, re.I):
		return False, "mengarah ke URL publik"
	return True, "ok"

def normalize_item(item, index):
	payload = str(item.get("payload", "")).strip()
	category = str(item.get("category", "unknown")).strip()

	if category not in ALLOWED_CATEGORIES:
		return None, f"category tidak diizinkan: {category}"

	ok, reason = is_safe_payload(payload)
	if not ok:
		return None, reason

	return {
		"payload_id": str(item.get("payload_id", f"ai_payload_{index:03d}")),
		"payload_category": category,
		"payload_text": payload,
		"risk_level": str(item.get("risk_level", "low")),
		"expected_label": str(item.get("expected_label",  "suspicious")),
		"created_by": "ollama_local",
		"created_at": now_utc(),
		"safety_status": "approved",
		"safety_note": str(item.get("safety_note", "validated by script")),
		"scenario_mapping": "chapter6_payload_variation"
	}, "ok"

def main():
	parser = argparse.ArgumentParser(description="Generate safe dummy payload catalog using local Ollama")
	parser.add_argument("--prompt", default="prompts/safe_payload_generator.prompt.txt")
	parser.add_argument("--model", default=os.environ.get("OLLAMA_MODEL", "nemotron-3-super"))
	parser.add_argument("--url", default=os.environ.get("OLLAMA_URL", "https://ollama.com/api/chat"))
	parser.add_argument("--output", default="payloads/payload_catalog.jsonl")
	parser.add_argument("--raw-output", default="logs/chapter6/ollama_raw_response.txt")
	args = parser.parse_args()

	prompt = Path(args.prompt).read_text(encoding="utf-8")


	api_key = os.environ.get("OLLAMA_API_KEY")
	if not api_key:
		raise SystemExit("[ERROR] OLLAMA_API_KEY belum di-export")

	headers = {
		"Authorization": f"Bearer {api_key}",
		"Content-Type": "application/json"
	}

	body = {
		"model": args.model,
		"messages": [{"role": "user", "content": prompt}],
		"stream": False,
		"format": "json"
	}



	response = requests.post(args.url, headers=headers, json=body, timeout=180)
	response.raise_for_status()

	if not response.ok:
		raise SystemExit(f"[ERROR] {response.status_code}: {response.text[:300]}")

	data = response.json()
	text = data.get("message", {}).get("content", "")

	raw_path = Path(args.raw_output)
	raw_path.parent.mkdir(parents=True, exist_ok=True)
	raw_path.write_text(text, encoding="utf-8")

	items = extract_json_array(text)

	out = Path(args.output)
	out.parent.mkdir(parents=True, exist_ok=True)

	approved = 0
	rejected = 0

	with out.open("a", encoding="utf-8") as f:
		for i, item in enumerate(items, start=1):
			normalized, reason = normalize_item(item, i)
			if normalized:
				f.write(json.dumps(normalized, ensure_ascii=False) + "\n")
				approved += 1
			else:
				rejected += 1
				print(json.dumps({
					"status": "rejected",
					"reason": reason,
					"item": item
				}, ensure_ascii=False))

	print(json.dumps({
		"model": args.model,
		"output": args.output,
		"approved": approved,
		"rejected": rejected
	}, indent=2, ensure_ascii=False))

if __name__ == "__main__":
	main()

#!/usr/bin/env python3
import argparse
import json
import os
import stat
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

def now_utc():
	return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def write_jsonl(path, record):
	p = Path(path)
	p.parent.mkdir(parents=True, exist_ok=True)
	with p.open("a", encoding="utf-8") as f:
		f.write(json.dumps(record, ensure_ascii=False) + "\n")

def ensure_safe_root(root):
	root = Path(root).resolve()
	allowed = Path("/opt/ai-soc-fim-lab").resolve()
	if root != allowed:
		raise SystemExit(f"[BLOCKED] root harus {allowed}")
	root.mkdir(parents=True, exist_ok=True)
	return root

def main():
	parser = argparse.ArgumentParser(description="Controlled FIM event generator")
	parser.add_argument("--root", default="/opt/ai-soc-fim-lab")
	parser.add_argument("--execute", action="store_true")
	parser.add_argument("--ground-truth", default="ground-truth/chapter5_fim.jsonl")
	parser.add_argument("--interval", type=float, default=2.0)
	args = parser.parse_args()

	root = ensure_safe_root(args.root)
	run_id = "run-" + uuid.uuid4().hex[:12]

	actions = [
		("create_file", root / "important_dummy.conf"),
		("modify_file", root / "important_dummy.conf"),
		("chmod_file", root / "important_dummy.conf"),
		("create_suspicious_dummy", root / "suspicious_dummy.sh"),
		("delete_file", root / "important_dummy.conf")
	]

	for idx, (action, path) in enumerate(actions, start=1):
		record = {
			"timestamp": now_utc(),
			"run_id": run_id,
			"scenario_id": "fim_dummy_event",
			"attack_type": "fim_event",
			"mitre_tactic": "Defense Evasion",
			"mitre_technique": "Modify File or Directory",
			"target_host": os.uname().nodename,
			"target_port": "local",
			"tool": "python_file_operation",
			"payload_id": action,
			"intensity": "low",
			"expected_label": "malicious",
			"success_status": "dry_run",
			"file_path": str(path),
			"action": action,
			"dry_run": not args.execute
		}

	if args.execute:
		if action == "create_file":
			path.write_text("dummy_config=true\n", encoding="utf-8")
		elif action == "modify_file":
			path.write_text("dummy_config=changed\n", encoding="utf-8")
		elif action == "chmod_file":
			path.chmod(stat.S_IRUSR | stat.S_IWUSR)
		elif action == "create_suspicious_dummy":
			path.write_text("#!/bin/sh\necho dummy suspicious lab file\n", encoding="utf-8")
			path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
		elif action == "delete_file":
			if path.exists():
				path.unlink()
		record["success_status"] = "success"

	write_jsonl(args.ground_truth, record)
	print(json.dumps(record, ensure_ascii=False))

	if idx < len(actions):
		time.sleep(args.interval)

if __name__ == "__main__":
	main()

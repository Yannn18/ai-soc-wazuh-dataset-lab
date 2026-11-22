#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

SAFE_COMMANDS = {
	"admin_normal": ["whoami"],
	"identity_check": ["id"],
	"host_check": ["hostname"],
	"kernel_check": ["uname", "-a"],
	"network_enum": ["ip", "addr"],
	"socket_enum": ["ss", "-tulpn"],
	"process_enum": ["ps", "aux"],
	"tmp_file_enum": ["find", "/tmp", "-maxdepth", "2", "-type", "f"]
}

def now_utc():
	return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def write_jsonl(path, record):
	p = Path(path)
	p.parent.mkdir(parents=True, exist_ok=True)
	with p.open("a", encoding="utf-8") as f:
		f.write(json.dumps(record, ensure_ascii=False) + "\n")

def main():
	parser = argparse.ArgumentParser(description="Safe suspicious command logger")
	parser.add_argument("--profile", choices=SAFE_COMMANDS.keys(), required=True)
	parser.add_argument("--execute", action="store_true")
	parser.add_argument("--ground-truth", default="ground-truth/chapter5_commands.jsonl")
	parser.add_argument("--log-dir", default="logs/commands")
	args = parser.parse_args()

	run_id = "run-" + uuid.uuid4().hex[:12]
	cmd = SAFE_COMMANDS[args.profile]
	outdir = Path(args.log_dir) / run_id
	outdir.mkdir(parents=True, exist_ok=True)

	suspicious_profiles = {"network_enum", "socket_enum", "process_enum", "tmp_file_enum"}
	attack_type = "suspicious_command" if args.profile in suspicious_profiles else "benign"

	record = {
		"timestamp": now_utc(),
		"run_id": run_id,
		"scenario_id": "command_execution_pattern",
		"attack_type": attack_type,
		"mitre_tactic": "Discovery" if attack_type ==
		"suspicious_command" else "none",
		"mitre_technique": "System Information Discovery" if
		attack_type == "suspicious_command" else "none",
		"target_host": os.uname().nodename,
		"target_port": "local",
		"tool": "python_subprocess",
		"payload_id": args.profile,
		"intensity": "low",
		"expected_label": "malicious" if attack_type ==
		"suspicious_command" else "benign",
		"success_status": "dry_run",
		"command": " ".join(cmd),
		"dry_run": not args.execute
	}

	if args.execute:
		proc = subprocess.run(cmd, text=True, capture_output=True, timeout=10)
		record["success_status"] = "success" if proc.returncode == 0 else "failed"
		record["return_code"] = proc.returncode
		(outdir / "stdout.log").write_text(proc.stdout, encoding="utf-8", errors="replace")
		(outdir / "stderr.log").write_text(proc.stderr, encoding="utf-8", errors="replace")

		logger_msg = json.dumps({
			"program": "ai-soc-command-lab",
			"run_id": run_id,
			"profile": args.profile,
			"attack_type": attack_type,
			"command": " ".join(cmd)
		})
		subprocess.run(["logger", "-t", "ai-soc-command-lab", logger_msg], check=False)

	write_jsonl(args.ground_truth, record)
	print(json.dumps(record, ensure_ascii=False))

if __name__ == "__main__":
	main()

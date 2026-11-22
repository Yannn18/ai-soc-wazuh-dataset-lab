#!/usr/bin/env python3
import argparse
import ipaddress
import json
import socket
import subprocess
from pathlib import Path
from urllib.parse import urlparse

def load_json(path):
	return json.loads(Path(path).read_text(encoding="utf-8"))

def ping(host):
	proc = subprocess.run(
		["ping", "-c", "1", "-W", "2", host],
		text=True,
		capture_output=True
	)
	return proc.returncode == 0

def tcp_check(host, port, timeout=3):
	try:
		with socket.create_connection((host, int(port)), timeout=timeout):
			return True
	except Exception:
		return False

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--config", default="configs/orchestrator.json")
	parser.add_argument("--output", default="reports/chapter8/preflight.json")
	args = parser.parse_args()

	config = load_json(args.config)

	lab = config["lab"]
	target_ip = lab["target_ip"]
	wazuh_server = lab["wazuh_server"]
	target_web = lab["target_web"]
	web_host = urlparse(target_web).hostname
	web_port = urlparse(target_web).port or 80

	checks = {
		"target_ping": ping(target_ip),
		"wazuh_ping": ping(wazuh_server),
		"target_ssh_22": tcp_check(target_ip, 22),
		"target_web": tcp_check(web_host, web_port),
		"wazuh_api_55000": tcp_check(wazuh_server, 55000)
	}
	status = "pass" if all(checks.values()) else "fail"

	report = {
		"status": status,
		"checks": checks
	}

	out = Path(args.output)
	out.parent.mkdir(parents=True, exist_ok=True)
	out.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

	print(json.dumps(report, indent=2, ensure_ascii=False))

	if status != "pass":
		raise SystemExit(1)

if __name__ == "__main__":
	main()

#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_token(base_url, user, password):
	r = requests.post(
		f"{base_url}/security/user/authenticate",
		auth=HTTPBasicAuth(user, password),
		verify=False,
		timeout=15
	)
	r.raise_for_status()
	return r.json()["data"]["token"]

def api_get(base_url, token, endpoint):
	headers = {"Authorization": f"Bearer {token}"}
	r = requests.get(
		f"{base_url}{endpoint}",
		headers=headers,
		verify=False,
		timeout=30
	)
	r.raise_for_status()
	return r.json()

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--run-dir", required=True)
	args = parser.parse_args()

	base_url = os.environ.get("WAZUH_API_URL")
	user = os.environ.get("WAZUH_USER")
	password = os.environ.get("WAZUH_PASS")

	if not base_url or not user or not password:
		raise SystemExit("Set WAZUH_API_URL, WAZUH_USER, WAZUH_PASS")

	token = get_token(base_url, user, password)

	agents = api_get(base_url, token, "/agents?limit=500")
	manager = api_get(base_url, token, "/manager/status")

	outdir = Path(args.run_dir)
	outdir.mkdir(parents=True, exist_ok=True)
	(outdir / "wazuh_api_agents.json").write_text(
		json.dumps(agents, indent=2, ensure_ascii=False),
		encoding="utf-8"
	)

	(outdir / "wazuh_api_manager_status.json").write_text(
		json.dumps(manager, indent=2, ensure_ascii=False),
		encoding="utf-8"
	)

	print(json.dumps({
		"run_dir": str(outdir),
		"files": [
			"wazuh_api_agents.json",
			"wazuh_api_manager_status.json"
		]
	}, indent=2))

if __name__ == "__main__":
	main()

#!/usr/bin/env python3
import shutil
import subprocess
from pathlib import Path

TOOLS = [
	"nmap", "curl", "jq", "git", "python3",
	"hydra", "sqlmap", "nikto", "nuclei", "docker"
]

REQUIRED_DIRS = [
	"configs", "scripts", "payloads", "ground-truth",
	"wazuh-export", "datasets", "notebooks", "reports",
	"logs"
]

def check_tool(name):
	path = shutil.which(name)
	return name, path

def check_dirs():
	missing = []
	for d in REQUIRED_DIRS:
		if not Path(d).exists():
			missing.append(d)
	return missing

def main():
	print("[1] Cek tool CLI")
	failed = []
	for tool in TOOLS:
		name, path = check_tool(tool)
		if path:
			print(f" OK {name}: {path}")
		else:
			print(f" MISS {name}")
			failed.append(name)

	print("\n[2] Cek struktur folder")
	missing_dirs = check_dirs()
	if not missing_dirs:
		print(" OK semua folder utama tersedia")
	else:
		for d in missing_dirs:
			print(f" MISS {d}")

	print("\n[3] Ringkasan")
	if failed or missing_dirs:
		print("Lab belum siap 100%. Lengkapi item MISS.")
		raise SystemExit(1)
	print("Lab siap untuk tahap dataset.")
	
if __name__ == "__main__":
	main()

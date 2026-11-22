#!/usr/bin/env python3
import argparse
import subprocess
import time

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--profile", required=True)
	parser.add_argument("--target", required=True)
	parser.add_argument("--lab-cidr", default="192.168.56.0/24")
	parser.add_argument("--count", type=int, default=3)
	parser.add_argument("--interval", type=int, default=60)
	args = parser.parse_args()

	if args.count > 10:
		raise SystemExit("[BLOCKED] count maksimal 10 untuk lab kecil")
	if args.interval < 10:
		raise SystemExit("[BLOCKED] interval minimal 10 detik")

	for i in range(args.count):
		print(f"[{i+1}/{args.count}] running {args.profile}")
		subprocess.run([
			"python", "scripts/recon_runner.py",
			"--profile", args.profile,
			"--target", args.target,
			"--lab-cidr", args.lab_cidr
		], check=False)

	if i < args.count - 1:
		time.sleep(args.interval)

if __name__ == "__main__":
	main()

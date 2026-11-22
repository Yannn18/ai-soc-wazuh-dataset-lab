#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--samples", default="samples/logtest/chapter7_samples.txt")
	parser.add_argument("--output", default="reports/chapter7/logtest-output.txt")
	args = parser.parse_args()

	samples = Path(args.samples).read_text(encoding="utf-8")

	proc = subprocess.run(
		["sudo", "/var/ossec/bin/wazuh-logtest"],
		input=samples,
		text=True,
		capture_output=True
	)

	out = Path(args.output)
	out.parent.mkdir(parents=True, exist_ok=True)
	out.write_text(proc.stdout + "\nSTDERR:\n" + proc.stderr, encoding="utf-8")
	print(f"Return code: {proc.returncode}")
	print(f"Output saved to: {args.output}")

if __name__ == "__main__":
	main()

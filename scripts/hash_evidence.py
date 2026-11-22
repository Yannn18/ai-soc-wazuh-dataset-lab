#!/usr/bin/env python3
import argparse
import hashlib
from pathlib import Path

def sha256(path):
	h = hashlib.sha256()
	with Path(path).open("rb") as f:
		for chunk in iter(lambda: f.read(1024 * 1024), b""):
			h.update(chunk)
	return h.hexdigest()

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument("--run-dir", required=True)
	args = parser.parse_args()

	run_dir = Path(args.run_dir)
	out = run_dir / "SHA256SUMS.txt"

	files = [
		p for p in run_dir.rglob("*")
		if p.is_file() and p.name != "SHA256SUMS.txt"
	]
	lines = []
	for p in sorted(files):
		rel = p.relative_to(run_dir)
		lines.append(f"{sha256(p)} {rel}")

	out.write_text("\n".join(lines) + "\n", encoding="utf-8")
	print(f"Hash evidence written to {out}")

if __name__ == "__main__":
	main()

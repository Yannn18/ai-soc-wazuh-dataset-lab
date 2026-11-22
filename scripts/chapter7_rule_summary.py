#!/usr/bin/env python3
from pathlib import Path
import re
import json

LOGTEST = Path("reports/chapter7/logtest-output.txt")
OUT = Path("reports/chapter7/rule_summary.json")

def main():
	text = LOGTEST.read_text(encoding="utf-8", errors="replace") if LOGTEST.exists() else ""

	rule_ids = re.findall(r"id: '(\d+)'", text)
	levels = re.findall(r"level: '(\d+)'", text)

	descriptions = re.findall(r"description: '([^']+)'", text)
	summary = {
		"logtest_file": str(LOGTEST),
		"rule_ids_found": rule_ids,
		"levels_found": levels,
		"descriptions_found": descriptions,
		"ai_soc_rules_found": [r for r in rule_ids if r.startswith("1100")],
		"passed_basic_check": any(r.startswith("1100") for r in rule_ids)
	}

	OUT.parent.mkdir(parents=True, exist_ok=True)
	OUT.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

	print(json.dumps(summary, indent=2, ensure_ascii=False))

if __name__ == "__main__":
	main()

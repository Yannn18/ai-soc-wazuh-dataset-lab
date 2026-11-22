#!/usr/bin/env python3
"""
SSH Successful Authentication Simulator for Wazuh Dataset Lab
Generates successful SSH login events that trigger Wazuh built-in rule 5715
MITRE: T1021.004 (Remote Services: SSH)
"""
import argparse
import ipaddress
import json
import shutil
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path


def now_utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def require_lab_ip(target, lab_cidr, allow_public=False):
    ip = ipaddress.ip_address(target)
    net = ipaddress.ip_network(lab_cidr, strict=False)
    if ip not in net:
        raise SystemExit(f"[BLOCKED] Target {target} di luar LAB_CIDR {lab_cidr}")
    if not ip.is_private and not allow_public:
        raise SystemExit(f"[BLOCKED] Target {target} bukan private IP (use --allow-public-ip to override)")
    return str(ip)


def read_lines(path):
    return [
        x.strip()
        for x in Path(path).read_text(encoding="utf-8").splitlines()
        if x.strip() and not x.strip().startswith("#")
    ]


def write_jsonl(path, record):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_ground_truth(record, ground_truth_path):
    write_jsonl(ground_truth_path, record)


def main():
    parser = argparse.ArgumentParser(description="SSH Successful Authentication Simulator for Wazuh Dataset Lab")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--lab-cidr", default="10.0.0.0/16", help="Lab CIDR range")
    parser.add_argument("--user", default="labuser", help="Username for successful login")
    parser.add_argument("--password", default="LabPass123!", help="Password for successful login")
    parser.add_argument("--timeout", type=int, default=10, help="SSH connection timeout")
    parser.add_argument("--execute", action="store_true", help="Execute real attempt (default: dry-run)")
    parser.add_argument("--ground-truth", default="ground-truth/ssh_successful_auth.jsonl", help="Ground truth output path")
    parser.add_argument("--log-dir", default="logs/auth/ssh_successful_auth", help="Log directory")
    parser.add_argument("--allow-public-ip", action="store_true", help="Allow non-private IPs (for lab environments)")
    args = parser.parse_args()

    target = require_lab_ip(args.target, args.lab_cidr, args.allow_public_ip)

    if shutil.which("sshpass") is None:
        raise SystemExit("[ERROR] sshpass tidak ditemukan. Install: sudo apt install -y sshpass")

    run_id = "run-" + uuid.uuid4().hex[:12]
    outdir = Path(args.log_dir) / run_id
    outdir.mkdir(parents=True, exist_ok=True)

    start = now_utc()

    cmd = [
        "sshpass", "-p", args.password,
        "ssh",
        "-p", str(args.port),
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "StrictHostKeyChecking=no",
        "-o", f"ConnectTimeout={args.timeout}",
        f"{args.user}@{target}",
        "whoami && id && hostname"
    ]

    record = {
        "timestamp": start,
        "run_id": run_id,
        "scenario_id": "ssh_successful_auth",
        "attack_type": "ssh_auth_success",
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1021.004",
        "target_host": target,
        "target_port": args.port,
        "tool": "sshpass+ssh",
        "payload_id": "ssh_valid_creds",
        "intensity": "low",
        "expected_label": "malicious",
        "success_status": "unknown",
        "username": args.user,
        "password_type": "dummy_lab_only",
        "dry_run": not args.execute,
        "safety_status": "lab_only",
        "post_exploitation_commands": ["whoami", "id", "hostname"]
    }

    if args.execute:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=args.timeout + 5)
        record["success_status"] = "success" if proc.returncode == 0 else "failed"
        record["return_code"] = proc.returncode
        (outdir / "stdout.log").write_text(proc.stdout, encoding="utf-8", errors="replace")
        (outdir / "stderr.log").write_text(proc.stderr, encoding="utf-8", errors="replace")
    else:
        record["success_status"] = "dry_run"

    write_ground_truth(record, args.ground_truth)
    print(json.dumps(record, ensure_ascii=False))

    summary = {
        "run_id": run_id,
        "target": target,
        "scenario": "ssh_successful_auth",
        "execute": args.execute,
        "ground_truth": args.ground_truth,
        "log_dir": str(outdir)
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

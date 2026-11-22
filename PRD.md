# Spec: AI SOC Wazuh Dataset Lab

## Objective

Build a reproducible, automated lab environment that generates labeled cybersecurity datasets by orchestrating attack scenarios against Wazuh-monitored targets, correlating ground truth with Wazuh alerts, and exporting ML-ready datasets for AI SOC training, baseline modeling, and LLM-assisted SOC experiments.

**Target Users:**
- Security researchers building AI SOC prototypes
- SOC analysts wanting labeled training data
- CTF/CEH lab practitioners
- ML engineers needing cybersecurity datasets

**Success Metrics:**
- Dataset with ≥1,000 labeled records (balanced benign/malicious)
- ≥10 attack techniques mapped to MITRE ATT&CK
- Multi-agent, multi-sensor (Wazuh + Suricata + Zeek) correlation
- Automated pipeline: scenario → ground truth → Wazuh alerts → correlation → export
- False positive rate <5%, false negative rate <10% on hold-out test set
- Full provenance: git commit, timestamps, scenario configs, sanitization log

---

## Tech Stack

| Layer | Technology | Version |
|-------|------------|---------|
| Language | Python | 3.11+ |
| Orchestration | Custom Python orchestrator | — |
| SIEM | Wazuh Manager/Agent | 4.8+ |
| Network IDS | Suricata | 7.0+ |
| Network Monitor | Zeek | 6.0+ |
| Dataset Processing | pandas, pyarrow | Latest |
| ML Baseline | scikit-learn | Latest |
| LLM Integration | Ollama (Nemotron-3-super) | Latest |
| Export Formats | JSONL, CSV, Parquet | — |
| Virtualization | VMware/VirtualBox (manual) | — |
| Shell Automation | Bash | — |

**Key Dependencies:**
- `requests` for Ollama API
- `pyarrow` for Parquet export
- `scikit-learn` for baseline models
- `sshpass` + `paramiko` for SSH scenario execution

---

## Commands

```bash
# Environment setup
python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt

# Navigate to project root (adjust if needed)
# cd ai-soc-wazuh-dataset

# Pre-flight checks (connectivity, Wazuh API, disk space)
python3 scripts/preflight_check.py

# Single-agent full cycle (scenarios → export → dataset)
./scripts/run_dataset_cycle.sh --config configs/orchestrator.json

# Multi-agent cycle (runs all enabled agent configs)
./scripts/run_dataset_cycle.sh --multi-agent

# Run orchestrator with multi-target config (NEW: supports multiple targets in one run)
python3 scripts/orchestrator.py --config configs/orchestrator.json --run-root runs

# Export Wazuh alerts for specific run (manual step on Wazuh manager)
# NEW: supports multiple --agent-names
python3 scripts/export_opensearch_alerts.py --run-dir runs/run-<timestamp> --agent-names owasp_juice_server Debian_VM --rule-groups sshd,pam,syslog --output-dir wazuh-export/

# Legacy export (deprecated - use export_opensearch_alerts.py)
# python3 scripts/export_wazuh_files.py --run-dir runs/run-<timestamp> --output-dir wazuh-export/agentN --rule-groups sshd

# Full pipeline: normalize → correlate → clean → features → label → export
# NEW: correlate_and_label.py supports multiple --agent-names
python3 scripts/normalize_wazuh_alert.py --input wazuh-export/agent1/alerts.jsonl --input wazuh-export/agent2/alerts.jsonl --output datasets/normalized_combined.jsonl
python3 scripts/correlate_and_label.py --ground-truth ground-truth/*.jsonl --alerts datasets/normalized_combined.jsonl --agent-names owasp_juice_server Debian_VM --output datasets/correlated_combined.jsonl
python3 scripts/clean_dataset.py --input datasets/correlated_combined.jsonl --output datasets/clean_combined.jsonl --dedup
python3 scripts/feature_engineering.py --input datasets/clean_combined.jsonl --output datasets/featured_combined.jsonl
python3 scripts/final_labeling.py --input datasets/featured_combined.jsonl --output datasets/labeled_combined.jsonl
python3 scripts/export_final_dataset.py --input datasets/labeled_combined.jsonl --output-dir datasets/final --version v0.2.0

# Quality & model reports
python3 scripts/dataset_quality_report.py --input datasets/final/dataset.parquet
python3 scripts/train_baseline_models.py --dataset datasets/final/dataset.parquet
python3 scripts/ai_soc_final_report.py  # Requires OLLAMA_API_KEY

# Validation
python3 scripts/run_wazuh_logtest_samples.py
python3 scripts/validate_run_pack.py --run-dir runs/run-<timestamp>
```

---

## Project Structure

```
ai-soc-wazuh-dataset/
├── configs/                    # Orchestrator configs per agent
│   ├── orchestrator.json       # Primary agent (custom decoder)
│   ├── orchestrator_ssh_agent.json   # SSH agent 1 (built-in rules)
│   └── orchestrator_ssh_agent2.json  # SSH agent 2 (built-in rules)
├── datasets/
│   ├── final/                  # Exported datasets (JSONL, CSV, Parquet, schema, DATASET_CARD)
│   └── *.jsonl                 # Intermediate pipeline outputs
├── decoders/                   # Custom Wazuh decoders
├── ground-truth/               # Ground truth JSONL per scenario
├── logs/                       # Raw scenario logs
├── models/                     # Trained model artifacts
├── payloads/                   # Attack payload catalogs
├── prompts/                    # LLM prompt templates
├── reports/
│   └── final/                  # AI-assisted SOC reports
├── rules/                      # Custom Wazuh rules
├── runs/                       # Per-execution evidence packs
├── samples/
│   └── logtest/                # Wazuh logtest validation samples
├── schemas/                    # JSON schemas for validation
├── scripts/                    # All pipeline scripts
├── wazuh-export/               # Wazuh alert exports per agent
├── venv/                       # Python virtual environment
├── requirements.txt            # Python dependencies
├── PRD.md                      # This document
├── README.md
├── DISCLAIMER.md
└── LICENSE
```

## Credits

This project is based on the **SOC Analyst Training** book module by **Onno W. Purbo**. The lab design, Wazuh deployment patterns, and attack scenario methodology draw directly from his educational materials.

---

## Code Style

**Python:** PEP 8, type hints on public functions, docstrings for modules/classes.

```python
# Good example: scripts/correlate_and_label.py
def normalize_alert(alert: dict) -> dict:
    """Normalize both raw Wazuh alerts and already-normalized alerts."""
    # Check if already normalized (has top-level agent_name)
    if "agent_name" in alert and "rule_id" in alert:
        return _from_normalized(alert)
    return _from_raw_wazuh(alert)

# Naming conventions:
# - Functions: snake_case (normalize_alert, extract_ssh_fields)
# - Classes: PascalCase (Orchestrator, ScenarioRunner)
# - Constants: UPPER_SNAKE_CASE (SENSITIVE_PATTERNS, MITRE_TACTICS)
# - Files: snake_case.py (correlate_and_label.py)
# - Configs: snake_case.json (orchestrator_ssh_agent.json)
```

**Bash:** Strict mode (`set -euo pipefail`), functions for reusable logic.

**JSON/JSONL:** UTF-8, no trailing commas, one record per line for JSONL.

---

## Testing Strategy

| Level | Framework | Scope | Coverage Target |
|-------|-----------|-------|-----------------|
| Unit | pytest | Individual functions (normalization, correlation, sanitization) | 80% |
| Integration | pytest + temp dirs | Full pipeline runs (mocked Wazuh) | 60% |
| Contract | JSON Schema | Dataset schema validation | 100% |
| Logtest | Wazuh logtest | Custom decoder/rule validation | All samples pass |
| Manual | Analyst review | Label quality, false positive/negative review | 50+ records per sprint |

**Test Organization:**
```
tests/
├── unit/
│   ├── test_normalize_wazuh_alert.py
│   ├── test_correlate_and_label.py
│   ├── test_clean_dataset.py
│   └── test_feature_engineering.py
├── integration/
│   └── test_pipeline_smoke.py
├── contract/
│   └── test_dataset_schema.py
└── fixtures/
    ├── sample_wazuh_alert.json
    └── sample_ground_truth.jsonl
```

**Run Commands:**
```bash
pytest tests/unit -v --cov=scripts --cov-report=term-missing
pytest tests/integration -v
pytest tests/contract -v
python3 scripts/run_wazuh_logtest_samples.py
```

---

## Boundaries

### Always Do
- Run `pytest tests/unit` before committing pipeline changes
- Validate dataset schema with `python3 -m jsonschema datasets/final/dataset.jsonl schemas/dataset.schema.json`
- Sanitize IPs (mask last octet), passwords, tokens, keys in `clean_dataset.py`
- Use `stable_id()` for deterministic event IDs
- Log orchestration runs to `runs/run-<timestamp>/` with execution_results.jsonl
- Tag git commit in DATASET_CARD.json

### Ask First
- Adding new external dependencies (PyPI packages)
- Changing dataset schema (field additions/removals/renames)
- Modifying Wazuh decoder/rule files (requires manager reload)
- Changing MITRE technique mappings
- Adding new attack scenario types

### Never Do
- Commit real credentials, IPs, or API keys (use `OLLAMA_API_KEY` env var only)
- Remove or disable sanitization in `clean_dataset.py`
- Use production targets (only lab CIDRs in configs)
- Skip preflight checks before orchestration runs
- Export datasets without DATASET_CARD and schema.json
- Hardcode absolute paths (use `Path(__file__).parent` or config)

---

## Success Criteria

1. **Dataset Volume:** ≥1,000 total records, ≥500 labeled malicious, ≥500 labeled benign
2. **Technique Coverage:** ≥10 distinct MITRE ATT&CK techniques across initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, exfiltration
3. **Multi-Sensor:** Wazuh + Suricata + Zeek alerts correlated in single pipeline
4. **Multi-Agent:** ≥3 Wazuh agents on different subnets/roles
5. **Quality Gates:** FPR <5%, FNR <10% on stratified hold-out test set (via `train_baseline_models.py`)
6. **Reproducibility:** Same config + seed → identical dataset (verified via hash)
7. **Documentation:** DATASET_CARD.json, schema.json, README_dataset.md auto-generated
8. **Provenance:** Every record traces to scenario_id, run_id, agent_name, rule_id

---

## Open Questions

1. **Suricata/Zeek Integration:** Should network sensors run on dedicated sensor VM or span ports on existing targets?
2. **Labeling Workflow:** Build a lightweight web UI for analyst review of unlabeled alerts, or stick to CLI + JSONL?
3. **Scenario Scheduling:** Implement cron-like scheduler in orchestrator, or keep external (systemd timers)?
4. **Dataset Versioning:** Use DVC for dataset versioning, or git LFS for Parquet files?
5. **SOAR Integration:** Define standardized alert enrichment API (Cortex, MISP, VirusTotal) before wiring playbooks.
6. **Windows Targets:** Add Windows attack scenarios (PowerShell, WinRM, RDP) — separate orchestrator config?
7. **Cloud Log Sources:** Plan for CloudTrail, VPC Flow Logs, Azure AD logs in future phases.

---

## Not Doing (Explicit Scope Exclusions)

- **Real malware execution** — only simulated attack behaviors
- **Credential stuffing against real services** — all targets are lab VMs
- **Production Wazuh deployment** — this is a dataset generator, not a SOC platform
- **Custom Wazuh rule development beyond lab needs** — use built-in rules where possible
- **Full SIEM feature parity** — no dashboard, alerting, or case management
- **Distributed orchestration** — single orchestrator controlling multiple agents is sufficient
- **Real-time streaming pipeline** — batch-oriented by design (evidence packs per run)

# AI SOC Wazuh Dataset Lab

> **Reproducible cybersecurity dataset generator** — Orchestrate attack scenarios against Wazuh-monitored targets, correlate ground truth with SIEM alerts, export ML-ready datasets.

---

## 🎯 Objective

Build a reproducible, automated lab environment that generates **labeled cybersecurity datasets** by:

1. **Orchestrating** attack scenarios (SSH brute-force, web attacks, lateral movement, privilege escalation)
2. **Capturing** ground truth (what happened, when, where)
3. **Collecting** Wazuh alerts from monitored agents
4. **Correlating** ground truth → Wazuh alerts (time-window + agent-name matching)
5. **Exporting** ML-ready datasets (JSONL, CSV, Parquet) with features + labels

**Use cases:** AI SOC prototyping, baseline ML modeling, LLM-assisted SOC experiments, CTF/CEH training.

---

## 🏗️ Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌──────────────────┐
│  Orchestrator   │────▶│  Target VMs  │────▶│  Wazuh Manager   │
│  (scenarios)    │     │  (agents)    │     │  + OpenSearch    │
└─────────────────┘     └──────────────┘     └────────┬─────────┘
                                                      │
                        ┌─────────────────────────────┘
                        ▼
            ┌─────────────────────────┐
            │  Pipeline (Python)      │
            │  normalize → correlate  │
            │  → clean → feature →    │
            │  label → export         │
            └───────────┬─────────────┘
                        ▼
            ┌─────────────────────────┐
            │  datasets/final/        │
            │  dataset.jsonl          │
            │  dataset.csv            │
            │  dataset.parquet        │
            │  schema.json            │
            │  DATASET_CARD.json      │
            └─────────────────────────┘
```

---

## 📁 Project Structure

```
ai-soc-wazuh-dataset/
├── configs/                    # Orchestrator configs per agent/target
│   ├── orchestrator.json       # Multi-Agent
│   ├── orchestrator_ssh_agent.json
│   └── orchestrator_ssh_agent2.json
├── decoders/                   # Custom Wazuh decoders
├── ground-truth/               # Per-scenario ground truth JSONL
├── models/                     # (gitignored) Trained model artifacts
├── payloads/                   # Attack payload catalogs & wordlists
├── prompts/                    # LLM prompt templates
├── reports/                    # Generated reports (chapter5-9, final)
├── rules/                      # Custom Wazuh rules
├── runs/                       # 📦 Evidence packs per execution (KEEP!)
│   └── run-<timestamp>/
│       ├── ground_truth.jsonl
│       ├── wazuh_alerts.jsonl
│       ├── config_snapshot.json
│       └── summary.*
├── samples/logtest/            # Wazuh logtest validation samples
├── schemas/                    # JSON schemas for dataset validation
├── scripts/                    # All pipeline scripts (see below)
├── tests/                      # Unit tests
├── .gitignore                  # Excludes: venv/, models/, wazuh-export/, logs/
├── PRD.md                      # Full specification
├── DISCLAIMER.md
├── LICENSE
└── security-checklist.md
```

---

## 🔧 Pipeline Scripts (in order)

| Step | Script | Purpose |
|------|--------|---------|
| 0 | `preflight_check.py` | Verify connectivity, Wazuh API, disk space |
| 1 | `orchestrator.py` | Run attack scenarios → write `ground_truth.jsonl` |
| 2 | `export_opensearch_alerts.py` | Pull Wazuh alerts from OpenSearch for time window |
| 3 | `normalize_wazuh_alert.py` | Normalize raw Wazuh alerts to flat schema |
| 4 | `correlate_and_label.py` | Match ground truth ↔ alerts (time + agent-name) |
| 5 | `clean_dataset.py` | Dedupe, sanitize IPs/masks, validate schema |
| 6 | `feature_engineering.py` | Add TF-IDF, entropy, event counts, time buckets |
| 7 | `final_labeling.py` | Assign binary/multi-class labels, source_of_truth |
| 8 | `export_final_dataset.py` | Export JSONL, CSV, Parquet + schema + DATASET_CARD |
| 9 | `dataset_quality_report.py` | Label dist, correlation status, leakage warnings |
| 10 | `train_baseline_models.py` | Logistic RF, HistGradientBoosting, IsolationForest |
| 11 | `ai_soc_final_report.py` | LLM-assisted SOC report (needs `OLLAMA_API_KEY`) |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Wazuh Manager 4.8+ with OpenSearch
- Wazuh Agents deployed on target VMs
- `sshpass` installed (`apt install sshpass`)

### Setup
```bash
git clone <this-repo>
cd ai-soc-wazuh-dataset
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### 1. Run Orchestrator (generate ground truth)
```bash
# Multi-target run (recommended)
python3 scripts/orchestrator.py --config configs/orchestrator.json --run-root runs

# Single target
python3 scripts/orchestrator.py --config configs/orchestrator_ssh_agent.json --run-root runs
```
Creates `runs/run-<timestamp>/` with `ground_truth.jsonl`, `config_snapshot.json`, `summary.*`.

### 2. Export Wazuh Alerts (manual step on Wazuh manager)
```bash
# On Wazuh manager (or via API if accessible)
python3 scripts/export_opensearch_alerts.py \
  --run-dir runs/run-<timestamp> \
  --agent-names owasp_juice_server Debian_VM \
  --rule-groups sshd,pam,syslog,web,httpd \
  --output-dir wazuh-export/
```
> **Note:** Wazuh API often only accessible inside manager. Run this manually there, copy `wazuh-export/` back.

### 3. Full Correlation Pipeline
```bash
# Combine all historical runs (recommended)
cat runs/run-*/ground_truth.jsonl > all_ground_truth.jsonl
cat runs/run-*/wazuh_alerts.jsonl > all_alerts.jsonl

python3 scripts/normalize_wazuh_alert.py --input all_alerts.jsonl --output normalized.jsonl
python3 scripts/correlate_and_label.py \
  --ground-truth all_ground_truth.jsonl \
  --alerts normalized.jsonl \
  --agent-names owasp_juice_server Debian_VM \
  --window-seconds 180 \
  --output datasets/final/correlated.jsonl

python3 scripts/clean_dataset.py --input datasets/final/correlated.jsonl --output datasets/final/cleaned.jsonl
python3 scripts/feature_engineering.py --input datasets/final/cleaned.jsonl --output datasets/final/featured.jsonl
python3 scripts/final_labeling.py --input datasets/final/featured.jsonl --output datasets/final/labeled.jsonl
python3 scripts/export_final_dataset.py --input datasets/final/labeled.jsonl --output-dir datasets/final --version v0.2.0
```

### 4. Quality & Models
```bash
python3 scripts/dataset_quality_report.py --input datasets/final/dataset.parquet
python3 scripts/train_baseline_models.py --dataset datasets/final/dataset.parquet
# Optional: python3 scripts/ai_soc_final_report.py  (requires OLLAMA_API_KEY)
```

---

## 🎯 Key Configs

### Multi-Target Orchestrator (`configs/orchestrator.json`)
```json
{
  "lab": {
    "lab_cidr": "192.168.56.0/24, 10.0.0.0/16",
    "target_ip": "192.168.56.30, 10.0.2.15",
    "wazuh_server": "10.0.0.10"
  },
  "scenarios": [
    { "name": "ssh_brute_force", "target": "owasp_juice_server", "command": "..." },
    { "name": "ssh_brute_force_cwp", "target": "Debian_VM", "command": "..." }
  ]
}
```
- **`target` field per scenario** → drives `ground_truth.target_host`
- Agent names (`owasp_juice_server`, `Debian_VM`) used for correlation

---

## 📊 Dataset Schema (key fields)

| Field | Description |
|-------|-------------|
| `event_id` | Stable hash (run_id + scenario_id + alert_id) |
| `timestamp` | ISO8601 UTC |
| `agent_name` | Wazuh agent name |
| `source_ip` | Attacker IP (masked in export) |
| `rule_id` | Wazuh rule ID |
| `rule_level` | Severity 1-15 |
| `binary_label` | `benign` / `malicious` / `unlabeled` |
| `multi_class_label` | `ssh_brute_force`, `web_attack`, `benign`, `unknown` |
| `correlation_status` | `matched_alert` / `ground_truth_without_alert` / `alert_without_ground_truth` |
| `source_of_truth` | `ground_truth_correlated` / `ground_truth_only` / `wazuh_alert_only` |
| `confidence` | 0.0–1.0 |

---

## 🧪 Testing

```bash
# Unit tests
pytest tests/unit -v --cov=scripts

# Wazuh logtest validation
python3 scripts/run_wazuh_logtest_samples.py

# Validate run evidence pack
python3 scripts/validate_run_pack.py --run-dir runs/run-<timestamp>
```

---

## 🔒 Security & Ethics

- **Lab only** — all targets in `lab_cidr` (private RFC1918)
- **No real credentials** — dummy passwords (`LabPass123!`, `trainee123`)
- **Sanitization** — IPs masked (last octet → `.X`), secrets stripped in `clean_dataset.py`
- **Disclaimer** — see `DISCLAIMER.md` and `security-checklist.md`

---

## 📈 Success Metrics (from PRD)

- ≥1,000 labeled records (balanced benign/malicious)
- ≥10 MITRE ATT&CK techniques
- FPR <5%, FNR <10% on hold-out test set
- Full provenance: git commit, timestamps, scenario configs

---

## 📚 References

- [PRD.md](PRD.md) — Full specification
- [schemas/dataset.schema.json](schemas/dataset.schema.json) — Dataset contract
- [configs/orchestrator.json](configs/orchestrator.json) — Example multi-target config
- [scripts/correlate_and_label.py](scripts/correlate_and_label.py) — Correlation logic

---

## Credits

This project is based on the **SOC Analyst Training** book module by **Onno W. Purbo**. The lab design, Wazuh deployment patterns, and attack scenario methodology draw directly from his educational materials.
[Book Module](https://drive.google.com/file/d/18_qIJxmfo5f8tPiRDWrZ5itnfGQtraRc/view?usp=drive_link)

**License:** MIT — see [LICENSE](LICENSE)

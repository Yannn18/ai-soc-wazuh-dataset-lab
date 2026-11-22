# Implementation Plan: AI SOC Wazuh Dataset Lab

## Overview
This plan breaks down the PRD into 5 major phases with explicit dependencies, verification checkpoints, and parallelization opportunities.

---

## Phase 0: Capability Map (Pre-requisite)

| Module ID | Responsibility | Depends On |
|-----------|---------------|------------|
| `core-pipeline` | Normalize → Correlate → Clean → Features → Label → Export | — |
| `orchestrator` | Scenario execution, ground truth generation, multi-agent coordination | `core-pipeline` |
| `wazuh-integration` | Custom decoders/rules, logtest validation, alert export | `core-pipeline` |
| `multi-sensor` | Suricata/Zeek integration, network+host correlation | `core-pipeline`, `wazuh-integration` |
| `ml-baseline` | Training, evaluation, quality reports | `core-pipeline` |
| `llm-report` | AI-assisted SOC report generation | `core-pipeline`, `ml-baseline` |
| `dataset-versioning` | DVC/git-LFS, schema evolution, release automation | `core-pipeline` |

**Build Order:** `core-pipeline` → `orchestrator` + `wazuh-integration` → `multi-sensor` + `ml-baseline` → `llm-report` + `dataset-versioning`

---

## Phase 1: Core Pipeline Hardening (Weeks 1-2)

### Objective
Make the existing pipeline production-grade: deterministic, tested, documented, with quality gates.

### Components
1. **Normalize** (`normalize_wazuh_alert.py`)
   - Handle both raw Wazuh + already-normalized formats (DONE)
   - Add JSON schema validation on output
   - Unit tests for custom vs built-in vs other alert types

2. **Correlate** (`correlate_and_label.py`)
   - Configurable time window (default 180s)
   - Multi-ground-truth append support (DONE)
   - Deterministic `stable_id` with collision resistance
   - Unit tests for match/no-match/partial scenarios

3. **Clean** (`clean_dataset.py`)
   - Sanitization: IP masking, password/token/key redaction, agent_name handling
   - Deduplication with fingerprint (DONE)
   - Schema validation against `schemas/dataset.schema.json`

4. **Feature Engineering** (`feature_engineering.py`)
   - Temporal: hour, day-of-week, minute-bucket counts
   - Categorical: rule_id, agent_name, attack_type one-hot
   - Text: full_log TF-IDF / entropy / length
   - Rolling: source_ip/agent/rule frequency windows

5. **Final Labeling** (`final_labeling.py`)
   - Binary: malicious/benign/unlabeled
   - Multi-class: technique-level labels
   - Confidence calibration

6. **Export** (`export_final_dataset.py`)
   - JSONL, CSV, Parquet, schema.json, DATASET_CARD.json, README_dataset.md
   - Version tagging from git

### Verification Checkpoints
- [ ] `pytest tests/unit` passes (80% coverage)
- [ ] `pytest tests/contract` validates schema
- [ ] `python3 scripts/run_wazuh_logtest_samples.py` all pass
- [ ] Deterministic run: same config + seed → identical dataset hash
- [ ] Sanitization verified: no real IPs/passwords in `datasets/final/`

### Parallelization
- Normalize, Correlate, Clean can be developed in parallel (different scripts)
- Feature Engineering + Final Labeling depend on Clean output

---

## Phase 2: Orchestrator & Multi-Agent (Weeks 2-3)

### Objective
Reliable multi-agent scenario execution with evidence packs.

### Components
1. **Orchestrator Core** (`orchestrator.py`)
   - Config-driven scenario sequencing (JSON)
   - Per-scenario timeout, cooldown, retry
   - Execution results → `runs/run-<ts>/execution_results.jsonl`
   - Seed-based determinism for payload selection

2. **Scenario Library** (per-scenario scripts)
   - SSH: brute_force, successful_auth, priv_esc, lateral (DONE)
   - Web: login_failure, input_attack, recon
   - System: fim_event, suspicious_command, recon
   - Benign: admin_ssh, admin_web, cron_jobs, package_update

3. **Multi-Agent Runner** (`run_dataset_cycle.sh`)
   - Sequential or parallel agent execution
   - Per-agent evidence isolation
   - Combined pipeline trigger

4. **Preflight Checks** (`preflight_check.py`)
   - SSH connectivity to targets
   - Wazuh API reachability
   - Disk space, venv health

### Verification Checkpoints
- [ ] All 4 SSH scenarios execute + generate ground truth
- [ ] 3+ agents run sequentially without interference
- [ ] Evidence packs complete: ground_truth.jsonl, execution_results.jsonl, config snapshot
- [ ] `validate_run_pack.py` passes

### Parallelization
- Scenario scripts independent (can develop in parallel)
- Multi-agent runs sequential by default (resource constraints)

---

## Phase 3: Wazuh Integration & Multi-Sensor (Weeks 3-5)

### Objective
Production Wazuh integration + Suricata/Zeek network correlation.

### Components
1. **Custom Decoder/Rule** (`decoders/`, `rules/`)
   - `ai-soc-pentest` decoder for custom JSON logs
   - Rules for each scenario type with MITRE tags
   - Logtest samples in `samples/logtest/`

2. **Built-in Rule Mapping** (in `normalize_wazuh_alert.py`)
   - SSH: 5700-5799 → technique mapping (DONE)
   - Web: 31100-31199, 31500-31599
   - System: 500-599, 1000-1099

3. **Suricata Integration**
   - Deploy on span port or dedicated sensor VM
   - Eve JSON export → normalize → correlate
   - Rules: ET Open + custom for lab traffic

4. **Zeek Integration**
   - Deploy alongside Suricata
   - conn.log, http.log, ssh.log, dns.log → JSONL
   - Correlate by timestamp + 5-tuple

5. **Multi-Sensor Correlation**
   - Unified timestamp normalization (UTC)
   - Join keys: src_ip, dst_ip, timestamp ±5s
   - Alert deduplication across sensors

### Verification Checkpoints
- [ ] `run_wazuh_logtest_samples.py` passes for all custom + built-in rules
- [ ] Suricata eve.json → normalized alerts → correlated
- [ ] Zeek conn.log → normalized alerts → correlated
- [ ] Cross-sensor deduplication reduces duplicate alerts >80%

### Parallelization
- Decoder/rules independent of Suricata/Zeek
- Suricata + Zeek can be deployed in parallel

---

## Phase 4: ML Baseline & Quality Gates (Weeks 5-6)

### Objective
Reliable baseline models with proper evaluation methodology.

### Components
1. **Dataset Quality Report** (`dataset_quality_report.py`)
   - Label distribution, missing values, class balance
   - Alert-ground-truth coverage matrix
   - Leakage detection (label columns in features)

2. **Baseline Training** (`train_baseline_models.py`)
   - Models: LogisticRegression, RandomForest, HistGradientBoosting, IsolationForest
   - Stratified k-fold CV (k=5) + hold-out test (20%)
   - Metrics: Precision, Recall, F1, ROC-AUC, PR-AUC, MCC
   - Leakage-safe feature selection (drop label/ID columns)

3. **Quality Gates** (enforced in `export_final_dataset.py`)
   - Min labeled per class ≥100
   - FPR <5%, FNR <10% on hold-out
   - Block export if gates fail

4. **Model Artifacts**
   - Save via joblib to `models/`
   - Metadata: training config, metrics, git commit, dataset version

### Verification Checkpoints
- [ ] Quality report generates without errors
- [ ] Baselines train + evaluate on current dataset
- [ ] Quality gates block export when unmet
- [ ] Model artifacts load + predict on new data

### Parallelization
- Quality report + baseline training can run in parallel

---

## Phase 5: LLM Report & Dataset Versioning (Weeks 6-7)

### Objective
Automated reporting + reproducible dataset releases.

### Components
1. **AI-Assisted SOC Report** (`ai_soc_final_report.py`)
   - Prompt template in `prompts/final_soc_report.prompt.txt`
   - Inputs: DATASET_CARD, QUALITY_REPORT, MODEL_REPORT
   - Output: `reports/final/AI_ASSISTED_SOC_REPORT.md`

2. **Dataset Versioning**
   - DVC for Parquet/CSV versioning
   - Git tags for releases: `dataset-v0.1.0`, `dataset-v0.2.0`
   - Schema evolution: backward-compatible additions only

3. **Release Automation**
   - `make release VERSION=v0.2.0` → tag + DVC push + GitHub release
   - Changelog auto-generated from commit messages

### Verification Checkpoints
- [ ] Report generates with Ollama (Nemotron-3-super)
- [ ] DVC tracks dataset files correctly
- [ ] Release script creates valid GitHub release

### Parallelization
- Report generation + versioning independent

---

## Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Wazuh API changes break export | Medium | High | Pin Wazuh version, integration tests |
| Suricata/Zeek deploy complexity | High | Medium | Start with span port on existing VM |
| Label imbalance persists | High | High | Benign traffic generator (Priority 1) |
| Schema drift breaks downstream | Medium | High | Contract tests, schema versioning |
| Ollama API key rotation | Low | Medium | Document env var setup, fallback to local |

---

## Dependencies Graph

```
core-pipeline (normalize, correlate, clean, features, label, export)
    │
    ├── orchestrator (scenarios, multi-agent, evidence)
    │       │
    │       └── wazuh-integration (decoders, rules, logtest)
    │               │
    │               └── multi-sensor (suricata, zeek, cross-correlation)
    │
    ├── ml-baseline (quality-report, baselines, quality-gates)
    │       │
    │       └── llm-report (AI SOC report)
    │
    └── dataset-versioning (DVC, release automation)
```

---

## Milestone Timeline

| Week | Milestone | Deliverable |
|------|-----------|-------------|
| 1 | Core pipeline hardened | Unit tests pass, deterministic runs |
| 2 | Multi-agent orchestrator | 3 agents, 8+ scenarios, evidence packs |
| 3 | Wazuh custom rules + logtest | All custom/builtin rules validated |
| 4 | Suricata + Zeek integrated | Network+host correlation working |
| 5 | ML baselines + quality gates | FPR<5%, FNR<10% on hold-out |
| 6 | AI SOC report automated | Report generates from pipeline outputs |
| 7 | Dataset v0.2.0 released | DVC + Git tag + changelog |

---

## Open Questions (from PRD) - Need Decisions

1. **Suricata/Zeek placement**: Dedicated sensor VM vs span port on target?
2. **Labeling workflow**: CLI-only vs lightweight web UI for analyst review?
3. **Scheduling**: Cron in orchestrator vs external systemd timers?
4. **Dataset versioning**: DVC vs git LFS?
5. **Windows targets**: Separate orchestrator config or extend existing?

---

## Next Steps
1. Review and approve this plan
2. Proceed to Phase 3 (Tasks) - break into discrete implementable tasks
3. Begin Phase 1 implementation (Core Pipeline Hardening)
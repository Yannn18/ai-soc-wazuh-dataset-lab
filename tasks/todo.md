# Task Breakdown: AI SOC Wazuh Dataset Lab

## Legend
- [ ] = Not started
- [~] = In progress
- [x] = Done
- **Acceptance**: What must be true when done
- **Verify**: How to confirm (test command, build, manual check)
- **Files**: Which files will be touched

---

## Phase 1: Core Pipeline Hardening

### 1.1 Normalize Module
- [ ] **Task**: Add JSON schema validation to normalize output
  - Acceptance: Output validates against `schemas/normalized_alert.schema.json`
  - Verify: `python3 -m jsonschema datasets/normalized_combined.jsonl schemas/normalized_alert.schema.json`
  - Files: `scripts/normalize_wazuh_alert.py`, `schemas/normalized_alert.schema.json`

- [ ] **Task**: Unit tests for normalize (custom, builtin, other alert types)
  - Acceptance: 3+ test cases covering each alert source type
  - Verify: `pytest tests/unit/test_normalize_wazuh_alert.py -v`
  - Files: `tests/unit/test_normalize_wazuh_alert.py`, `tests/fixtures/sample_wazuh_alert.json`

### 1.2 Correlate Module
- [ ] **Task**: Make time window configurable via CLI (default 180s)
  - Acceptance: `--window-seconds` parameter works, default 180
  - Verify: `python3 scripts/correlate_and_label.py --help` shows option
  - Files: `scripts/correlate_and_label.py`

- [ ] **Task**: Unit tests for correlation (match, no-match, partial, multi-GT)
  - Acceptance: 4+ test cases, deterministic `stable_id` verified
  - Verify: `pytest tests/unit/test_correlate_and_label.py -v`
  - Files: `tests/unit/test_correlate_and_label.py`, `tests/fixtures/sample_ground_truth.jsonl`

### 1.3 Clean Module
- [ ] **Task**: Add schema validation against `schemas/dataset.schema.json`
  - Acceptance: Clean output passes schema validation
  - Verify: `python3 -m jsonschema datasets/clean_combined.jsonl schemas/dataset.schema.json`
  - Files: `scripts/clean_dataset.py`, `schemas/dataset.schema.json`

- [ ] **Task**: Verify sanitization completeness (no real IPs, passwords, keys)
  - Acceptance: Grep for IPv4 patterns returns only masked (.X); no passwords/tokens
  - Verify: `grep -E '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' datasets/final/dataset.jsonl | grep -v '\.X"'`
  - Files: `scripts/clean_dataset.py`

### 1.4 Feature Engineering
- [ ] **Task**: Add temporal features (hour, dow, minute-bucket counts)
  - Acceptance: New columns: `feature_hour`, `feature_dow`, `feature_minute_bucket`, `feature_event_count_minute`
  - Verify: `head -1 datasets/featured_combined.jsonl | python3 -m json.tool | grep feature_`
  - Files: `scripts/feature_engineering.py`

- [ ] **Task**: Add categorical one-hot (rule_id, agent_name, attack_type)
  - Acceptance: One-hot columns for top-20 rule_ids, agents, attack_types
  - Verify: Check column names in featured output
  - Files: `scripts/feature_engineering.py`

- [ ] **Task**: Add text features (full_log entropy, length, TF-IDF hash)
  - Acceptance: Columns: `feature_full_log_entropy`, `feature_full_log_length`, `feature_full_log_tfidf_hash`
  - Verify: `pytest tests/unit/test_feature_engineering.py -v`
  - Files: `scripts/feature_engineering.py`

### 1.5 Final Labeling
- [ ] **Task**: Implement confidence calibration (isotonic regression)
  - Acceptance: `confidence` column calibrated, reliability curve plotted in quality report
  - Verify: `pytest tests/unit/test_final_labeling.py -v`
  - Files: `scripts/final_labeling.py`, `scripts/dataset_quality_report.py`

### 1.6 Export Module
- [ ] **Task**: Enforce quality gates before export (min labels, FPR/FNR thresholds)
  - Acceptance: Export fails with clear message if gates unmet
  - Verify: Run with insufficient data → exits non-zero with gate message
  - Files: `scripts/export_final_dataset.py`

- [ ] **Task**: Contract test for dataset schema
  - Acceptance: `pytest tests/contract/test_dataset_schema.py` validates all required fields
  - Verify: `pytest tests/contract -v`
  - Files: `tests/contract/test_dataset_schema.py`, `schemas/dataset.schema.json`

### 1.7 Pipeline Integration Tests
- [ ] **Task**: Smoke test full pipeline with mocked Wazuh data
  - Acceptance: `pytest tests/integration/test_pipeline_smoke.py` passes
  - Verify: `pytest tests/integration -v`
  - Files: `tests/integration/test_pipeline_smoke.py`

- [ ] **Task**: Deterministic run verification (same config + seed = identical hash)
  - Acceptance: Two runs with same seed produce identical dataset SHA256
  - Verify: Custom script comparing hashes
  - Files: `scripts/validate_deterministic.py` (new)

---

## Phase 2: Orchestrator & Multi-Agent

### 2.1 Orchestrator Core
- [ ] **Task**: Add per-scenario timeout, cooldown, retry logic
  - Acceptance: Config keys `timeout_seconds`, `cooldown_seconds`, `retry_count` respected
  - Verify: `python3 scripts/orchestrator.py --config configs/orchestrator.json --dry-run`
  - Files: `scripts/orchestrator.py`

- [ ] **Task**: Evidence pack generation (ground_truth.jsonl, execution_results.jsonl, config snapshot)
  - Acceptance: `runs/run-<ts>/` contains all three files with correct structure
  - Verify: `python3 scripts/validate_run_pack.py --run-dir runs/run-<latest>`
  - Files: `scripts/orchestrator.py`, `scripts/validate_run_pack.py`

### 2.2 Scenario Library
- [ ] **Task**: Benign traffic generator (SSH admin, web health, cron, package update)
  - Acceptance: 4 benign scenarios generate ground truth with `expected_label: "benign"`
  - Verify: `python3 scripts/generate_benign.py --target <ip> --count 10 --execute`
  - Files: `scripts/generate_benign.py` (new), `configs/orchestrator_benign.json` (new)

- [ ] **Task**: Web attack scenarios (login_failure, input_attack, recon)
  - Acceptance: 3 web scenarios execute, generate ground truth with MITRE tags
  - Verify: `python3 scripts/web_login_failure.py --target <ip> --execute`
  - Files: `scripts/web_login_failure.py`, `scripts/web_input_attack.py`, `scripts/recon_runner.py`

- [ ] **Task**: System scenarios (FIM, suspicious_command, recon_repeat)
  - Acceptance: 3 system scenarios execute with proper MITRE mapping
  - Verify: Individual script execution
  - Files: `scripts/fim_event_generator.py`, `scripts/suspicious_command_logger.py`, `scripts/recon_repeat.py`

### 2.3 Multi-Agent Runner
- [ ] **Task**: `run_dataset_cycle.sh --multi-agent` runs all enabled agent configs sequentially
  - Acceptance: Script detects `configs/orchestrator_*.json`, runs each, aggregates exports
  - Verify: `./scripts/run_dataset_cycle.sh --multi-agent`
  - Files: `scripts/run_dataset_cycle.sh`

- [ ] **Task**: Preflight checks (SSH, Wazuh API, disk, venv)
  - Acceptance: `python3 scripts/preflight_check.py` exits 0 only if all checks pass
  - Verify: Run with/without connectivity
  - Files: `scripts/preflight_check.py`

---

## Phase 3: Wazuh Integration & Multi-Sensor

### 3.1 Custom Decoder/Rules
- [ ] **Task**: Finalize `ai-soc-pentest` decoder in `decoders/`
  - Acceptance: Decoder extracts scenario_id, attack_type, MITRE fields from custom JSON
  - Verify: `python3 scripts/run_wazuh_logtest_samples.py` shows decoder matches
  - Files: `decoders/ai_soc_pentest_decoder.xml`

- [ ] **Task**: Custom rules for each scenario type with MITRE tags
  - Acceptance: One rule per scenario, level 5-10, MITRE technique in rule
  - Verify: `python3 scripts/run_wazuh_logtest_samples.py` all pass
  - Files: `rules/ai_soc_pentest_rules.xml`, `samples/logtest/`

### 3.2 Built-in Rule Mapping
- [ ] **Task**: Complete MITRE mapping for web (31100-31199, 31500-31599) and system (500-599)
  - Acceptance: `map_builtin_rule_to_attack()` covers web + system rule ranges
  - Verify: `grep -r "311\|315\|5[0-9][0-9]" scripts/normalize_wazuh_alert.py`
  - Files: `scripts/normalize_wazuh_alert.py`

### 3.3 Suricata Integration
- [ ] **Task**: Deploy Suricata on span port / sensor VM with ET Open rules
  - Acceptance: Suricata running, eve.json produced with alerts
  - Verify: `tail -f /var/log/suricata/eve.json`
  - Files: Infrastructure (document in `docs/suricata_setup.md`)

- [ ] **Task**: Suricata eve.json → normalize → correlate pipeline
  - Acceptance: New `alert_source: "suricata"` records in correlated output
  - Verify: `python3 scripts/normalize_wazuh_alert.py --input suricata-export/eve.jsonl`
  - Files: `scripts/normalize_wazuh_alert.py` (add suricata handler)

### 3.4 Zeek Integration
- [ ] **Task**: Deploy Zeek alongside Suricata, export conn/http/ssh/dns logs
  - Acceptance: Zeek logs in JSONL format via `zeek -C -r` or `zeekctl`
  - Verify: `head -1 zeek-export/conn.jsonl | python3 -m json.tool`
  - Files: Infrastructure (document in `docs/zeek_setup.md`)

- [ ] **Task**: Zeek logs → normalize → correlate pipeline
  - Acceptance: New `alert_source: "zeek"` records with 5-tuple correlation keys
  - Verify: Correlation finds matches across Wazuh + Zeek
  - Files: `scripts/normalize_wazuh_alert.py` (add zeek handler), `scripts/correlate_and_label.py`

### 3.5 Cross-Sensor Deduplication
- [ ] **Task**: Deduplicate alerts across Wazuh/Suricata/Zeek by timestamp±5s + 5-tuple
  - Acceptance: Duplicate reduction >80% on multi-sensor test data
  - Verify: Count before/after dedup in correlated output
  - Files: `scripts/correlate_and_label.py`

---

## Phase 4: ML Baseline & Quality Gates

### 4.1 Dataset Quality Report
- [ ] **Task**: Alert-ground-truth coverage matrix (matched, GT-only, alert-only)
  - Acceptance: Matrix printed in quality report with counts and percentages
  - Verify: `python3 scripts/dataset_quality_report.py --input datasets/final/dataset.parquet`
  - Files: `scripts/dataset_quality_report.py`

- [ ] **Task**: Leakage detection (label/ID columns in feature set)
  - Acceptance: Report flags any feature column containing label info
  - Verify: Run on current dataset, verify no false positives
  - Files: `scripts/dataset_quality_report.py`

### 4.2 Baseline Training
- [ ] **Task**: Stratified 5-fold CV + 20% hold-out test split
  - Acceptance: All models evaluated with CV and hold-out, metrics saved
  - Verify: `python3 scripts/train_baseline_models.py --input datasets/final/dataset.parquet`
  - Files: `scripts/train_baseline_models.py`

- [ ] **Task**: Metrics: Precision, Recall, F1, ROC-AUC, PR-AUC, MCC per class
  - Acceptance: All 6 metrics computed for binary and multi-class
  - Verify: MODEL_REPORT includes all metrics
  - Files: `scripts/train_baseline_models.py`, `scripts/model_report_markdown.py`

### 4.3 Quality Gates
- [ ] **Task**: Enforce min 100 labeled per class, FPR<5%, FNR<10% on hold-out
  - Acceptance: `export_final_dataset.py` exits non-zero if gates fail
  - Verify: Temporarily lower thresholds, verify export succeeds
  - Files: `scripts/export_final_dataset.py`

- [ ] **Task**: Model artifact persistence (joblib + metadata JSON)
  - Acceptance: `models/<model_name>.joblib` + `models/<model_name>.meta.json` saved
  - Verify: Load model, predict on sample data
  - Files: `scripts/train_baseline_models.py`

---

## Phase 5: LLM Report & Dataset Versioning

### 5.1 AI SOC Report
- [ ] **Task**: Refine prompt template for structured report sections
  - Acceptance: Report includes Executive Summary, Dataset Overview, Label Distribution, Model Results, Findings, Limitations, Recommendations, Next Steps
  - Verify: `python3 scripts/ai_soc_final_report.py` generates complete markdown
  - Files: `prompts/final_soc_report.prompt.txt`, `scripts/ai_soc_final_report.py`

### 5.2 Dataset Versioning
- [ ] **Task**: Initialize DVC for `datasets/final/*.parquet`, `datasets/final/*.csv`
  - Acceptance: `dvc add datasets/final/dataset.parquet` works, `.dvc` files tracked
  - Verify: `dvc status`, `dvc push` (if remote configured)
  - Files: `.dvc/`, `datasets/final/*.dvc`

- [ ] **Task**: Release script (`make release VERSION=vX.Y.Z`)
  - Acceptance: Creates git tag, DVC push, GitHub release with changelog
  - Verify: `make release VERSION=v0.2.0` (dry-run)
  - Files: `Makefile`, `scripts/release.py` (new)

---

## Summary Count
- Phase 1: 10 tasks
- Phase 2: 7 tasks
- Phase 3: 8 tasks
- Phase 4: 6 tasks
- Phase 5: 3 tasks
**Total: 34 tasks**

---

## Execution Order (Dependency-Aware)

1. 1.1 → 1.2 → 1.3 → 1.4 → 1.5 → 1.6 → 1.7 (sequential within phase)
2. 2.1 → 2.2 (scenarios parallel) → 2.3
3. 3.1 → 3.2 → (3.3 + 3.4 parallel) → 3.5
4. 4.1 → 4.2 → 4.3
5. 5.1 → 5.2

**Start with:** Task 1.1 (Normalize schema validation) - unblocks contract tests
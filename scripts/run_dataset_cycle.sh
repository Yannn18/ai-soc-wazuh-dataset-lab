#!/usr/bin/env bash

set -euo pipefail
PROJECT_DIR="${PROJECT_DIR:-$HOME/SOCv2/radnext-ai-soc}"
LOG_DIR="$PROJECT_DIR/logs/chapter8"

mkdir -p "$LOG_DIR"

cd "$PROJECT_DIR"

START_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[$START_TIME] Starting multi-agent dataset cycle" | tee -a "$LOG_DIR/run_dataset_cycle.log"

source venv/bin/activate 2>/dev/null || true

# Agent 1: Original AI SOC Agent (custom decoder/rules)
echo "[$START_TIME] Running Agent 1: Original AI SOC Agent" | tee -a "$LOG_DIR/run_dataset_cycle.log"
python scripts/orchestrator.py \
	--config configs/orchestrator.json \
	--run-root runs \
	2>> "$LOG_DIR/orchestrator_agent1.stderr.log" \
	| tee -a "$LOG_DIR/orchestrator_agent1.stdout.log"

# Agent 2: SSH Agent (built-in Wazuh SSH rules)
echo "[$START_TIME] Running Agent 2: SSH Agent (built-in rules)" | tee -a "$LOG_DIR/run_dataset_cycle.log"
python scripts/orchestrator.py \
	--config configs/orchestrator_ssh_agent.json \
	--run-root runs \
	2>> "$LOG_DIR/orchestrator_agent2.stderr.log" \
	| tee -a "$LOG_DIR/orchestrator_agent2.stdout.log"

# Export alerts from both agents
# Find the latest run directories
AGENT1_RUN=$(ls -td runs/run-* | head -1)
AGENT2_RUN=$(ls -td runs/run-* | head -2 | tail -1)

echo "[$START_TIME] Exporting alerts from Agent 1: $AGENT1_RUN" | tee -a "$LOG_DIR/run_dataset_cycle.log"
python scripts/export_wazuh_files.py \
	--run-dir "$AGENT1_RUN" \
	--output "wazuh-export/agent1" \
	2>> "$LOG_DIR/export_agent1.stderr.log" \
	| tee -a "$LOG_DIR/export_agent1.stdout.log"

echo "[$START_TIME] Exporting alerts from Agent 2: $AGENT2_RUN" | tee -a "$LOG_DIR/run_dataset_cycle.log"
python scripts/export_wazuh_files.py \
	--run-dir "$AGENT2_RUN" \
	--output "wazuh-export/agent2" \
	2>> "$LOG_DIR/export_agent2.stderr.log" \
	| tee -a "$LOG_DIR/export_agent2.stdout.log"

# Run combined pipeline
echo "[$START_TIME] Running combined normalization pipeline" | tee -a "$LOG_DIR/run_dataset_cycle.log"
python scripts/normalize_wazuh_alert.py \
	--input "wazuh-export/agent1/alerts.jsonl" \
	--input "wazuh-export/agent2/alerts.jsonl" \
	--output "datasets/normalized_combined.jsonl" \
	2>> "$LOG_DIR/normalize.stderr.log" \
	| tee -a "$LOG_DIR/normalize.stdout.log"

# Correlate with ground truth from both agents
echo "[$START_TIME] Running correlation with multi-agent ground truth" | tee -a "$LOG_DIR/run_dataset_cycle.log"
python scripts/correlate_and_label.py \
	--ground-truth "$AGENT1_RUN/ground_truth.jsonl" \
	--ground-truth "$AGENT2_RUN/ground_truth.jsonl" \
	--alerts "datasets/normalized_combined.jsonl" \
	--output "datasets/final/correlated_combined.jsonl" \
	--window-seconds 180 \
	2>> "$LOG_DIR/correlate.stderr.log" \
	| tee -a "$LOG_DIR/correlate.stdout.log"

# Continue with rest of pipeline
echo "[$START_TIME] Running dataset cleaning" | tee -a "$LOG_DIR/run_dataset_cycle.log"
python scripts/clean_dataset.py \
	--input "datasets/final/correlated_combined.jsonl" \
	--output "datasets/final/clean_combined.jsonl" \
	2>> "$LOG_DIR/clean.stderr.log" \
	| tee -a "$LOG_DIR/clean.stdout.log"

echo "[$START_TIME] Running feature engineering" | tee -a "$LOG_DIR/run_dataset_cycle.log"
python scripts/feature_engineering.py \
	--input "datasets/final/clean_combined.jsonl" \
	--output "datasets/final/featured_combined.jsonl" \
	2>> "$LOG_DIR/feature_eng.stderr.log" \
	| tee -a "$LOG_DIR/feature_eng.stdout.log"

echo "[$START_TIME] Running final labeling" | tee -a "$LOG_DIR/run_dataset_cycle.log"
python scripts/final_labeling.py \
	--input "datasets/final/featured_combined.jsonl" \
	--output "datasets/final/labeled_combined.jsonl" \
	2>> "$LOG_DIR/final_label.stderr.log" \
	| tee -a "$LOG_DIR/final_label.stdout.log"

echo "[$START_TIME] Exporting final dataset" | tee -a "$LOG_DIR/run_dataset_cycle.log"
python scripts/export_final_dataset.py \
	--input "datasets/final/labeled_combined.jsonl" \
	--output-dir "datasets/final" \
	--format all \
	2>> "$LOG_DIR/export_final.stderr.log" \
	| tee -a "$LOG_DIR/export_final.stdout.log"

echo "[$START_TIME] Generating dataset quality report" | tee -a "$LOG_DIR/run_dataset_cycle.log"
python scripts/dataset_quality_report.py \
	--input "datasets/final/labeled_combined.jsonl" \
	--output "reports/final/quality_report_combined.json" \
	2>> "$LOG_DIR/quality_report.stderr.log" \
	| tee -a "$LOG_DIR/quality_report.stdout.log"

END_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[$END_TIME] Finished multi-agent dataset cycle" | tee -a "$LOG_DIR/run_dataset_cycle.log"
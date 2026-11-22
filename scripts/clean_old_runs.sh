#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-$HOME/ai-soc-wazuh-dataset}"
KEEP_DAYS="${KEEP_DAYS:-14}"

cd "$PROJECT_DIR"

find runs -maxdepth 1 -type d -name 'run-*' -mtime
+"$KEEP_DAYS" -print
echo "Dry-run only. Tambahkan -delete manual jika benar-benar ingin menghapus."

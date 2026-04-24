#!/usr/bin/env bash
# ==============================================================================
# OWASP Top 10 2025 TUI Scanner - Professional Grade
# Version: 3.2.2 (Termux & Linux Compatible, Fixed Enumeration)
# ==============================================================================

set -euo pipefail

# Get script directory to source modules relatively
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Source modules in order
source "$SCRIPT_DIR/modules/00_error_handler.sh"
source "$SCRIPT_DIR/modules/01_init.sh"
source "$SCRIPT_DIR/modules/02_prompts.sh"
source "$SCRIPT_DIR/modules/02b_proxy_manager.sh"
source "$SCRIPT_DIR/modules/03_core.sh"
source "$SCRIPT_DIR/modules/04_execution.sh"
source "$SCRIPT_DIR/modules/05_auditing.sh"
source "$SCRIPT_DIR/modules/06_reporting.sh"
source "$SCRIPT_DIR/modules/07_html_report.sh"

# Tanyakan apakah pengguna ingin mengaktifkan AI Pentester
echo -e "${YELLOW}[?] Apakah Anda ingin menggunakan AI Pentester (Ollama Lokal) untuk menganalisis hasil scan? (y/n) [n]: ${NC}\c"
read USE_AI
export USE_AI=${USE_AI:-n}

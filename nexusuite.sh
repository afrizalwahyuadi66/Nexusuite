#!/usr/bin/env bash
# ==============================================================================
# OWASP Top 10 2025 TUI Scanner - Professional Grade
# Version: 3.2.2 (Termux & Linux Compatible, Fixed Enumeration)
# ==============================================================================

set -euo pipefail

# Get script directory to source modules relatively
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# CLI flags
DOCTOR_MODE=false
DOCTOR_JSON=false
DRY_RUN=false
PLATFORM_API=false
PLATFORM_WORKER=false

show_help() {
    cat <<'EOF'
Usage:
  ./nexusuite.sh [--doctor] [--doctor-json] [--dry-run] [--platform-api] [--platform-worker] [--help]

Options:
  --doctor   Jalankan self-check dependency + konektivitas AI, lalu keluar.
  --doctor-json Jalankan self-check dalam format JSON (untuk CI/automation).
  --dry-run  Simulasi workflow tanpa mengeksekusi command scanning.
  --platform-api Jalankan API server + Web UI platform mode.
  --platform-worker Jalankan worker queue platform mode.
  --help     Tampilkan bantuan.
EOF
}

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    printf '%s' "$s"
}

json_array() {
    local arr=("$@")
    local i
    printf "["
    for ((i = 0; i < ${#arr[@]}; i++)); do
        ((i > 0)) && printf ", "
        printf "\"%s\"" "$(json_escape "${arr[$i]}")"
    done
    printf "]"
}

run_doctor() {
    local output_json="${1:-false}"
    local cfg="$SCRIPT_DIR/ai_rag_tool/ai_config.sh"
    if [[ -f "$cfg" ]]; then
        # shellcheck disable=SC1090
        source "$cfg"
    fi

    local missing=0
    local ollama_ok=false
    local python_ok=false
    local -a tools_ok=()
    local -a tools_missing=()
    local -a py_missing=()
    local required_tools=(
        "gum" "subfinder" "httpx" "nmap" "nuclei" "dalfox" "gau"
        "katana" "arjun" "sqlmap" "paramspider" "nikto" "jq" "flock" "timeout" "ffuf" "wafw00f"
    )

    if [[ "$output_json" != "true" ]]; then
        echo "============================================================"
        echo "Nexusuite Doctor"
        echo "============================================================"
        echo "[INFO] OLLAMA_HOST=${OLLAMA_HOST:-http://localhost:11434}"
        echo "[INFO] OLLAMA_MODEL=${OLLAMA_MODEL:-qwen2.5:0.5b}"
        echo
        echo "[CHECK] Tools:"
    fi
    for tool in "${required_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            tools_ok+=("$tool")
            [[ "$output_json" != "true" ]] && echo "  [OK]  $tool"
        else
            tools_missing+=("$tool")
            [[ "$output_json" != "true" ]] && echo "  [MISS] $tool"
            missing=1
        fi
    done

    [[ "$output_json" != "true" ]] && echo
    [[ "$output_json" != "true" ]] && echo "[CHECK] Python modules:"
    if command -v python3 >/dev/null 2>&1; then
        local py_check_output=""
        if py_check_output="$(python3 - <<'PY'
import sys
mods = ["requests", "duckduckgo_search"]
bad = []
for mod in mods:
    try:
        __import__(mod)
    except Exception:
        bad.append(mod)
if bad:
    print("MISSING:", ", ".join(bad))
    sys.exit(1)
print("OK: requests, duckduckgo_search")
PY
        )"; then
            python_ok=true
            [[ "$output_json" != "true" ]] && echo "$py_check_output"
        else
            [[ "$output_json" != "true" ]] && echo "$py_check_output"
            if [[ "$py_check_output" == MISSING:* ]]; then
                local raw_missing="${py_check_output#MISSING: }"
                IFS=',' read -r -a py_missing <<< "$raw_missing"
                local i
                for i in "${!py_missing[@]}"; do
                    py_missing[$i]="$(echo "${py_missing[$i]}" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
                done
            fi
            missing=1
        fi
    else
        [[ "$output_json" != "true" ]] && echo "MISSING: python3"
        py_missing=("python3")
        missing=1
    fi

    [[ "$output_json" != "true" ]] && echo
    [[ "$output_json" != "true" ]] && echo "[CHECK] Ollama API:"
    if command -v curl >/dev/null 2>&1 && ollama_check; then
        [[ "$output_json" != "true" ]] && echo "  [OK] Ollama aktif"
        ollama_ok=true
    else
        [[ "$output_json" != "true" ]] && echo "  [WARN] Ollama tidak terjangkau (${OLLAMA_HOST:-http://localhost:11434})"
        missing=1
    fi

    if [[ "$output_json" == "true" ]]; then
        local ok_status="false"
        [[ $missing -eq 0 ]] && ok_status="true"
        printf '{\n'
        printf '  "ok": %s,\n' "$ok_status"
        printf '  "ollama_host": "%s",\n' "$(json_escape "${OLLAMA_HOST:-http://localhost:11434}")"
        printf '  "ollama_model": "%s",\n' "$(json_escape "${OLLAMA_MODEL:-qwen2.5:0.5b}")"
        printf '  "tools": {\n'
        printf '    "ok": '
        json_array "${tools_ok[@]}"
        printf ',\n'
        printf '    "missing": '
        json_array "${tools_missing[@]}"
        printf '\n'
        printf '  },\n'
        printf '  "python": {\n'
        printf '    "ok": %s,\n' "$python_ok"
        printf '    "missing": '
        json_array "${py_missing[@]}"
        printf '\n'
        printf '  },\n'
        printf '  "ollama": {\n'
        printf '    "reachable": %s\n' "$ollama_ok"
        printf '  }\n'
        printf '}\n'
    else
        echo "============================================================"
        if [[ $missing -eq 0 ]]; then
            echo "Doctor selesai: environment siap dipakai."
            return 0
        fi
        echo "Doctor selesai: ada komponen yang belum siap."
    fi

    if [[ $missing -eq 0 ]]; then
        return 0
    fi
    return 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --doctor) DOCTOR_MODE=true ;;
        --doctor-json)
            DOCTOR_MODE=true
            DOCTOR_JSON=true
            ;;
        --dry-run) DRY_RUN=true ;;
        --platform-api) PLATFORM_API=true ;;
        --platform-worker) PLATFORM_WORKER=true ;;
        --help|-h)
            show_help
            exit 0
            ;;
        *)
            echo "Argumen tidak dikenal: $1"
            show_help
            exit 1
            ;;
    esac
    shift
done

if [[ "$DOCTOR_MODE" == "true" ]]; then
    run_doctor "$DOCTOR_JSON"
    exit $?
fi

if [[ "$PLATFORM_API" == "true" ]]; then
    if ! command -v python3 >/dev/null 2>&1; then
        echo "python3 tidak ditemukan. Platform API membutuhkan python3."
        exit 1
    fi
    exec python3 "$SCRIPT_DIR/platform/api_server.py"
fi

if [[ "$PLATFORM_WORKER" == "true" ]]; then
    if ! command -v python3 >/dev/null 2>&1; then
        echo "python3 tidak ditemukan. Platform Worker membutuhkan python3."
        exit 1
    fi
    exec python3 "$SCRIPT_DIR/platform/worker.py"
fi

export DRY_RUN

if [[ "${OSTYPE:-}" == "msys"* || "${OSTYPE:-}" == "cygwin"* || "${OSTYPE:-}" == "win32"* ]]; then
    echo "[WARN] Terdeteksi shell Windows native. Untuk stabilitas penuh, jalankan via WSL2."
    echo "[INFO] Gunakan: powershell -ExecutionPolicy Bypass -File .\\run_windows.ps1"
fi

# Source modules in order
source "$SCRIPT_DIR/modules/00_error_handler.sh"
source "$SCRIPT_DIR/modules/01_init.sh"
if [[ -f "$SCRIPT_DIR/ai_rag_tool/ai_config.sh" ]]; then
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/ai_rag_tool/ai_config.sh"
fi

# Define ANSI Colors
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
NC='\033[0m' # No Color

# Tanyakan mode AI saat awal startup.
# - Manual: AI hanya untuk analisis/audit (opsional)
# - Full Control: AI orchestrator aktif + dorking aktif selama scan berjalan
if [[ "${AI_ORCHESTRATOR_MODE:-false}" == "true" || "${AI_ORCHESTRATOR_MODE:-false}" == "1" ]]; then
    export USE_AI="y"
    echo -e "${CYAN}[*] AI Orchestrator mode aktif dari environment: AI Full Control diaktifkan otomatis.${NC}"
else
    echo -e "${YELLOW}[?] Pilih mode operasi AI saat startup:${NC}"
    echo -e "    1) Manual (default) - tools berjalan normal, AI opsional untuk analisis"
    echo -e "    2) AI Full Control - AI mengorkestrasi discovery + dorking selama scan"
    echo -e "${YELLOW}Masukkan pilihan [1/2] (default: 1): ${NC}\c"
    read AI_BOOT_MODE
    AI_BOOT_MODE="${AI_BOOT_MODE:-1}"

    if [[ "$AI_BOOT_MODE" == "2" ]]; then
        export AI_ORCHESTRATOR_MODE="true"
        export USE_AI="y"
        export AI_ENABLE_DORKING="${AI_ENABLE_DORKING:-true}"
        echo -e "${CYAN}[*] AI Full Control aktif: orchestrator + dorking akan dijalankan.${NC}"
    else
        echo -e "${YELLOW}[?] Aktifkan AI Pentester (Ollama Lokal) untuk analisis hasil scan? (y/n) [n]: ${NC}\c"
        read USE_AI
        export USE_AI=${USE_AI:-n}
    fi
fi

# Jika pengguna memilih ya, cek status Ollama
if [[ "$USE_AI" == "y" || "$USE_AI" == "Y" ]]; then
    if command -v curl &>/dev/null; then
        echo -e "${CYAN}[*] Mengecek status AI (Ollama)...${NC}"
        if ollama_check; then
            echo -e "\033[1;32m[+] Status AI (Ollama): AKTIF (${OLLAMA_HOST:-http://localhost:11434})\033[0m"
        else
            echo -e "\033[1;31m[-] Status AI (Ollama): NON-AKTIF (${OLLAMA_HOST:-http://localhost:11434}). AI Agent akan dilewati.\033[0m"
        fi
    fi
fi
echo ""

if [[ "${DRY_RUN:-false}" == "true" ]]; then
    echo -e "${YELLOW}[!] DRY-RUN aktif: command scanning tidak akan dieksekusi.${NC}"
fi

source "$SCRIPT_DIR/modules/02_prompts.sh"
source "$SCRIPT_DIR/modules/02b_proxy_manager.sh"
source "$SCRIPT_DIR/modules/08_ai_advanced.sh"
source "$SCRIPT_DIR/modules/03_core.sh"
source "$SCRIPT_DIR/modules/04_execution.sh"
source "$SCRIPT_DIR/modules/05_auditing.sh"
source "$SCRIPT_DIR/modules/06_reporting.sh"
source "$SCRIPT_DIR/modules/07_html_report.sh"

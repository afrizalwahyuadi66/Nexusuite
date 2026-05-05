#!/usr/bin/env bash
# ==============================================================================
# OWASP Top 10 2025 TUI Scanner - Professional Grade
# Version: 3.2.2 (Termux & Linux Compatible, Fixed Enumeration)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# V4 Engine auto-start helper
ensure_v4_engine_running() {
  local health_url="http://localhost:8000/health"
  local engine_log_dir="${SCRIPT_DIR}/nx_platform/v4/logs"
  local engine_log="${engine_log_dir}/engine_v4.log"
  local engine_pid_file="${engine_log_dir}/engine_v4.pid"
  # If engine health is up, good. If not, rely on the API server startup to start the engine.
  if curl -sSf "${health_url}" >/dev/null 2>&1; then
    return 0
  fi

  echo "[INFO] V4 Engine tidak hidup. API server akan memulai engine saat dijalankan."
  return 0
}

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

ollama_check() {
    curl -s --max-time 5 "${OLLAMA_HOST:-http://localhost:11434}/api/tags" > /dev/null 2>&1
}

select_ollama_model() {
    local YELLOW='\033[1;33m'
    local CYAN='\033[1;36m'
    local GREEN='\033[0;32m'
    local NC='\033[0m'

    echo -e "${YELLOW}[?] Memuat daftar model Ollama yang tersedia...${NC}"
    if command -v curl &>/dev/null; then
        local available_models
        available_models=$(curl -s "${OLLAMA_HOST:-http://localhost:11434}/api/tags" | jq -r '.models[].name' 2>/dev/null)
        if [[ -n "$available_models" ]]; then
            echo -e "${CYAN}Model AI yang tersedia di Ollama lokal Anda:${NC}"
            local model_array=()
            local idx=1
            while IFS= read -r model_name; do
                echo -e "    $idx) $model_name"
                model_array+=("$model_name")
                ((idx++))
            done <<< "$available_models"
            
            echo -e "${YELLOW}Pilih model AI (masukkan angka, default: 1): ${NC}\c"
            local MODEL_CHOICE
            read MODEL_CHOICE
            MODEL_CHOICE="${MODEL_CHOICE:-1}"
            
            if [[ "$MODEL_CHOICE" =~ ^[0-9]+$ ]] && [[ "$MODEL_CHOICE" -gt 0 ]] && [[ "$MODEL_CHOICE" -le "${#model_array[@]}" ]]; then
                local selected_model="${model_array[$((MODEL_CHOICE-1))]}"
                export OLLAMA_MODEL="$selected_model"
                echo -e "${GREEN}[+] Model AI diatur ke: $selected_model${NC}"
            else
                echo -e "${YELLOW}[!] Pilihan tidak valid. Menggunakan model default: ${OLLAMA_MODEL:-deepseek-r1:8b}${NC}"
            fi
        else
            echo -e "${YELLOW}[!] Gagal mengambil daftar model dari Ollama. Menggunakan model default: ${OLLAMA_MODEL:-deepseek-r1:8b}${NC}"
        fi
    fi
}

run_doctor() {
    local output_json="${1:-false}"
    local cfg="$SCRIPT_DIR/ai_rag_tool/ai_config. sh"
    if [[ -f "$cfg" ]]; then
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
        "katana" "arjun" "sqlmap" "paramspider" "nikto" "jq" "flock" "timeout" "ffuf" "wafw00f" "whatweb" "wpscan"
    )

    if [[ "$output_json" != "true" ]]; then
        echo "============================================================"
        echo "Nexusuite Doctor"
        echo "============================================================"
        echo "[INFO] OLLAMA_HOST=${OLLAMA_HOST:-http://localhost:11434}"
        echo "[INFO] OLLAMA_MODEL=${OLLAMA_MODEL:-deepseek-r1:8b}"
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
mods = ["requests", "bs4"]
bad = []
for mod in mods:
    try:
        __import__(mod)
    except Exception:
        bad.append(mod)
if bad:
    print("MISSING:", ", ".join(bad))
    sys.exit(1)
print("OK: requests, beautifulsoup4")
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
        printf '  "ollama_model": "%s",\n' "$(json_escape "${OLLAMA_MODEL:-deepseek-r1:8b}")"
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
            echo "Argumen tidak diakui: $1"
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
    # Ensure V4 Engine is running before starting API server
    ensure_v4_engine_running
    # If engine failed to start, still attempt to start API to allow debugging
    exec python3 "$SCRIPT_DIR/nx_platform/v4/main.py"
fi

if [[ "$PLATFORM_WORKER" == "true" ]]; then
    if ! command -v python3 >/dev/null 2>&1; then
        echo "python3 tidak ditemukan. Platform Worker membutuhkan python3."
        exit 1
    fi
    exec python3 "$SCRIPT_DIR/nx_platform/v4/engine/worker.py"
fi

export DRY_RUN

if [[ "${OSTYPE:-}" == "msys"* || "${OSTYPE:-}" == "cygwin"* || "${OSTYPE:-}" == "win32"* ]]; then
    echo "[WARN] Terdeteksi shell Windows native. Untuk stabilitas penuh, jalankan via WSL2."
    echo "[INFO] Gunakan: powershell -ExecutionPolicy Bypass -File .\run_windows.ps1"
fi

source "$SCRIPT_DIR/modules/00_error_handler.sh"
source "$SCRIPT_DIR/modules/01_init.sh"
if [[ -f "$SCRIPT_DIR/ai_rag_tool/ai_config.sh" ]]; then
    source "$SCRIPT_DIR/ai_rag_tool/ai_config.sh"
fi

YELLOW='\033[1;33m'
CYAN='\033[1;36m'
GREEN='\033[0;32m'
NC='\033[0m'

if [[ "${AI_ORCHESTRATOR_MODE:-false}" == "true" || "${AI_ORCHESTRATOR_MODE:-false}" == "1" ]]; then
    export USE_AI="y"
    export USE_V4_ENGINE="true"
    echo -e "${CYAN}[*] AI Orchestrator mode aktif dari environment: AI Full Control diaktifkan otomatis.${NC}"
else
    echo -e "${YELLOW}[?] Select Operational Control Mode:${NC}"
    echo -e "    1) Manual Mode (You lead, AI consults)"
    echo -e "    2) Autonomous Mode (AI leads total mission)"
    echo -e "    3) Advanced AI Agent Configuration (Brain Settings)"
    echo -e "${YELLOW}Masukkan pilihan [1/2/3] (default: 1): ${NC}\c"
    read AI_BOOT_MODE
    AI_BOOT_MODE="${AI_BOOT_MODE:-1}"

    if [[ "$AI_BOOT_MODE" == "2" ]]; then
        export AI_ORCHESTRATOR_MODE="true"
        export USE_AI="y"
        export USE_V4_ENGINE="false" # Opsi 2 menggunakan Engine Klasik (ai_rag_tool)
        export AI_AGENT_MODE="standard"
        echo -e "${CYAN}[*] Autonomous Mission aktif: Menggunakan Engine Klasik (ai_rag_tool).${NC}"
        select_ollama_model
    
    elif [[ "$AI_BOOT_MODE" == "3" ]]; then
        echo ""
        echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗"
        echo -e "║          NEXUSUITE V4 - ADVANCED AI ENGINE                ║"
        echo -e "╚═══════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${YELLOW}Pilih Strategi Brain V4 yang ingin digunakan:${NC}"
        echo -e "    1) NX-ADVANCED (Iterative reasoning, aggressive tool dispatch) ${GREEN}(Recommended)${NC}"
        echo -e "    2) TRUE AI (Deep observation of every output line)"
        echo -e "    3) HYBRID (AI decides targets, Shell executes tools)"
        echo -e "    4) RAG-BASED (Match findings with Exploit-DB knowledge)"
        echo -e "    5) EXIT (Kembali)"
        echo ""
        echo -e "${YELLOW}Masukkan pilihan [1/2/3/4/5] (default: 1): ${NC}\c"
        read AGENT_CHOICE
        AGENT_CHOICE="${AGENT_CHOICE:-1}"
        [[ "$AGENT_CHOICE" == "5" ]] && exec "$0"

        export USE_AI="y"
        export USE_V4_ENGINE="true" # Opsi 3 mengaktifkan Engine V4 (nx_platform)
        export AI_ORCHESTRATOR_MODE="true" # V4 selalu autonomous di mode ini
        
        case "$AGENT_CHOICE" in
            1) export AI_AGENT_MODE="nx_advanced" ;;
            2) export AI_AGENT_MODE="true_ai" ;;
            3) export AI_AGENT_MODE="hybrid" ;;
            4) export AI_AGENT_MODE="rag_based" ;;
        esac
        
        select_ollama_model
        echo -e "${GREEN}[+] Nexusuite V4 Engine diaktifkan dengan strategi: $AI_AGENT_MODE${NC}"
    else
        export AI_ORCHESTRATOR_MODE="false"
        export USE_V4_ENGINE="false"
        export AI_AGENT_MODE="tools_only"
        echo -e "${YELLOW}[?] Aktifkan AI Pentester (Ollama Lokal) untuk analisis hasil scan? (y/n) [n]: ${NC}\c"
        read USE_AI
        export USE_AI=${USE_AI:-n}
        if [[ "$USE_AI" =~ ^[Yy]$ ]]; then
            select_ollama_model
        fi
    fi
fi

DEFAULT_TIMEOUT_MIN=5
echo -e "${YELLOW}[?] Atur timeout request AI/ Ollama (menit, minimal 5, isi 0 untuk unlimited) [default: ${DEFAULT_TIMEOUT_MIN}]: ${NC}\c"
read AI_TIMEOUT_MINUTES
AI_TIMEOUT_MINUTES="${AI_TIMEOUT_MINUTES:-$DEFAULT_TIMEOUT_MIN}"
if ! [[ "$AI_TIMEOUT_MINUTES" =~ ^[0-9]+$ ]]; then
    AI_TIMEOUT_MINUTES="$DEFAULT_TIMEOUT_MIN"
fi
if [[ "$AI_TIMEOUT_MINUTES" -eq 0 ]]; then
    export AI_HTTP_TIMEOUT="0"
    echo -e "${CYAN}[*] Timeout AI/ Ollama diatur ke UNLIMITED.${NC}"
else
    if [[ "$AI_TIMEOUT_MINUTES" -lt 5 ]]; then
        AI_TIMEOUT_MINUTES=5
    fi
    export AI_HTTP_TIMEOUT="$((AI_TIMEOUT_MINUTES * 60))"
    echo -e "${CYAN}[*] Timeout AI/ Ollama diatur ke ${AI_TIMEOUT_MINUTES} menit (${AI_HTTP_TIMEOUT} detik).${NC}"
fi

echo -e "${YELLOW}[?] Atur timeout untuk tool network/ request eksternal AI seperti curl (detik, isi 0 untuk unlimited) [default: 10]: ${NC}\c"
read CUSTOM_CURL_TIMEOUT
CUSTOM_CURL_TIMEOUT="${CUSTOM_CURL_TIMEOUT:-10}"
if ! [[ "$CUSTOM_CURL_TIMEOUT" =~ ^[0-9]+$ ]]; then
    CUSTOM_CURL_TIMEOUT=10
fi
export AI_CURL_TIMEOUT="$CUSTOM_CURL_TIMEOUT"
if [[ "$AI_CURL_TIMEOUT" -eq 0 ]]; then
    echo -e "${CYAN}[*] Timeout tool request AI diatur ke: UNLIMITED (Berjalan sampai server merespon).${NC}"
else
    echo -e "${CYAN}[*] Timeout tool request AI diatur ke: ${AI_CURL_TIMEOUT} detik.${NC}"
fi

if [[ "$USE_AI" == "y" || "$USE_AI" == "Y" ]]; then
    if command -v curl &>/dev/null; then
        echo -e "${CYAN}[*] Mengecek status AI (Ollama)...${NC}"
        if ollama_check; then
            echo -e "\033[1;32m[+] Status AI (Ollama): AKTIF (${OLLAMA_HOST:-http://localhost:11434})\033[0m"
        else
            echo -e "\033[1;31m[-] Status AI (Ollama): NONAKTIF (${OLLAMA_HOST:-http://localhost:11434}). AI Agent akan dilewati.\033[0m"
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

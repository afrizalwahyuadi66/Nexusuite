# ==============================================================================
# Pre-scan Internet Check
# ==============================================================================
if [[ "${DRY_RUN:-false}" == "true" ]]; then
    gum style --foreground 240 "DRY-RUN aktif: internet check dilewati."
elif ! check_internet; then
    gum style --foreground 214 "Internet connection not detected."
    choice=$(gum choose "Wait for internet" "Continue anyway (tools may fail)")
    if [[ "$choice" == "Wait for internet" ]]; then
        wait_for_internet
    else
        gum style --foreground 214 "Proceeding without internet. Network tools will likely fail."
    fi
fi

# ==============================================================================
# Setup Skip File & Signal Lock
# ==============================================================================
SKIP_DOMAIN_FILE=$(mktemp)
export SKIP_DOMAIN_FILE
add_cleanup 'rm -f "$SKIP_DOMAIN_FILE"'

SIGINT_LOCK_FILE="${TMPDIR:-/tmp}/owasp_sigint_$$.lock"
export SIGINT_LOCK_FILE
add_cleanup 'rm -f "$SIGINT_LOCK_FILE"'

# ==============================================================================
# Core Scanning Function (process_target)
# ==============================================================================
process_target() {
    local TARGET="$1"
    [[ -z "$TARGET" ]] && return 0
    # Hilangkan http:// atau https:// dan slash di akhir untuk mendapatkan domain murni
    local TARGET_DOMAIN=$(echo "$TARGET" | sed -e 's|^https*://||' -e 's|/.*||')
    # Jadikan aman untuk nama folder
    local TARGET_SAFE=$(echo "$TARGET_DOMAIN" | sed 's/[^a-zA-Z0-9.-]/_/g')

    local TARGET_DIR="$OUTPUT_BASE/targets/$TARGET_SAFE"
    mkdir -p "$TARGET_DIR"/{recon,vulnerabilities,scans}
    mkdir -p "$OUTPUT_BASE/.status"

    local TARGET_LOG="$TARGET_DIR/scan.log"
    echo -e "\n=== Starting scan: $TARGET ===" > "$TARGET_LOG"
    local PROXY_AUDIT_FILE="$TARGET_DIR/proxy_report.txt"
    {
        echo "PROXY ROUTING REPORT - $(date)"
        echo "Target: $TARGET"
        echo "Use Proxy: ${USE_PROXY:-false}"
        echo "AI Proxy for Intel: ${AI_PROXY_FOR_INTEL:-false}"
        echo "AI Dorking via Proxy: ${AI_DORK_USE_PROXY:-false}"
        echo "AI Aggressive Mode: ${AI_AGGRESSIVE_MODE:-false} (level=${AI_AGGRESSIVE_LEVEL:-1})"
        echo "NO_PROXY: ${NO_PROXY:-${no_proxy:-N/A}}"
        if [[ "${PROXY_STRICT:-false}" == "true" ]]; then
            echo "Policy: Strict Proxy-Only"
        else
            echo "Policy: Best Effort"
        fi
        echo "------------------------------------------------------------"
    } > "$PROXY_AUDIT_FILE"
    local skip_domain_flag=0
    local current_cmd_pid=""
    local AI_DISCOVERY_PID=""
    local AI_DISCOVERY_SCRIPT="$SCRIPT_DIR/ai_rag_tool/ai_orchestrator_safe.sh"
    local AI_DISCOVERY_LOG="$TARGET_DIR/recon/ai_orchestrator_runtime.log"
    local AI_PLAN_FILE="$TARGET_DIR/recon/ai_execution_plan.json"
    local AI_PLAN_RAW="$TARGET_DIR/recon/ai_execution_plan_raw.txt"
    local AI_REPLAN_FILE="$TARGET_DIR/recon/ai_phase2_replan.json"
    local ACTIVE_TOOLS="${SELECTED_TOOLS:-}"
    local AI_PLAN_RETRY_DEFAULT=2
    local AI_PLAN_RETRY_RECON=2
    local AI_PLAN_RETRY_VULN=2
    local AI_PLAN_RETRY_HEAVY=1
    local AI_PLAN_PROFILE_PRIMARY="balanced"
    local AI_PLAN_PROFILE_BACKUP="web"
    local AI_PLANNER_ENABLED=0
    
    local TARGET_DISPLAY="$TARGET"
    cmd_fingerprint() {
        local raw="$1"
        if command -v sha256sum >/dev/null 2>&1; then
            printf "%s" "$raw" | sha256sum | awk '{print $1}'
        elif command -v md5sum >/dev/null 2>&1; then
            printf "%s" "$raw" | md5sum | awk '{print $1}'
        else
            printf "%s" "$raw" | cksum | awk '{print $1}'
        fi
    }

    audit_proxy() {
        local step="$1"
        local action="$2"
        local detail="${3:-}"
        printf '[%s] [%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$step" "$action" "$detail" >> "$PROXY_AUDIT_FILE"
    }

    local STATUS_FILE="$OUTPUT_BASE/.status/${TARGET_SAFE}.active"
    local TARGET_FINALIZED=0

    append_skip_domain_once() {
        grep -qxF "$TARGET" "$SKIP_DOMAIN_FILE" 2>/dev/null || echo "$TARGET" >> "$SKIP_DOMAIN_FILE"
    }

    cleanup_target_state() {
        [[ "$TARGET_FINALIZED" -eq 1 ]] && return 0
        TARGET_FINALIZED=1
        if [[ -n "$AI_DISCOVERY_PID" ]] && kill -0 "$AI_DISCOVERY_PID" 2>/dev/null; then
            kill "$AI_DISCOVERY_PID" 2>/dev/null || true
        fi
        rm -f "$STATUS_FILE" \
              "$OUTPUT_BASE/.status/${TARGET_SAFE}.skip_tool" \
              "$OUTPUT_BASE/.status/${TARGET_SAFE}.skip_domain"
        current_cmd_pid=""
        trap - SIGINT
    }

    abort_target_scan() {
        [[ "$TARGET_FINALIZED" -eq 1 ]] && return 0
        {
            echo "------------------------------------------------------------"
            echo "Skipped: $(date)"
        } >> "$PROXY_AUDIT_FILE"
        echo -e "\n=== Scan skipped for: $TARGET ===" >> "$TARGET_LOG"
        cleanup_target_state
    }

    echo "$TARGET|INIT|Starting|$TARGET_LOG" > "$STATUS_FILE"
    log_msg ">" "\033[1;36m" "$TARGET_DISPLAY" "INIT" "Starting scan..."

    start_ai_discovery_async() {
        local phase="${1:-runtime}"
        local ai_proxy_for_dork="${AI_DORK_USE_PROXY:-${AI_PROXY_FOR_INTEL:-false}}"
        if [[ "${USE_AI:-n}" != "y" && "${USE_AI:-n}" != "Y" ]]; then
            return 0
        fi
        if [[ "${AI_ORCHESTRATOR_MODE:-false}" != "true" && "${AI_ORCHESTRATOR_MODE:-false}" != "1" ]]; then
            return 0
        fi
        if [[ "${AI_ENABLE_DORKING:-true}" != "true" && "${AI_ENABLE_DORKING:-true}" != "1" ]]; then
            return 0
        fi
        if [[ "${DRY_RUN:-false}" == "true" ]]; then
            return 0
        fi
        if [[ ! -f "$AI_DISCOVERY_SCRIPT" ]]; then
            return 0
        fi
        if [[ -n "$AI_DISCOVERY_PID" ]] && kill -0 "$AI_DISCOVERY_PID" 2>/dev/null; then
            return 0
        fi

        chmod +x "$AI_DISCOVERY_SCRIPT" 2>/dev/null || true
        log_msg "AI" "\033[1;35m" "$TARGET" "ORCHESTRATOR" "Passive dorking/discovery berjalan di background ($phase)."
        {
            echo "===== $(date) | phase=$phase ====="
            if [[ "$ai_proxy_for_dork" == "true" || "$ai_proxy_for_dork" == "1" ]]; then
                bash "$AI_DISCOVERY_SCRIPT" --target "$TARGET" --log-dir "$TARGET_DIR"
            else
                env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy \
                    bash "$AI_DISCOVERY_SCRIPT" --target "$TARGET" --log-dir "$TARGET_DIR"
            fi
            echo ""
        } >> "$AI_DISCOVERY_LOG" 2>&1 &
        AI_DISCOVERY_PID=$!
    }

    tool_enabled() {
        local tool="$1"
        [[ -n "$tool" ]] || return 1
        echo " $ACTIVE_TOOLS " | grep -q " $tool "
    }

    normalize_tools_line() {
        local raw="$1"
        local out=""
        local one
        for one in $raw; do
            [[ -n "$one" ]] || continue
            if ! echo " $out " | grep -q " $one "; then
                out="$out $one"
            fi
        done
        echo "$out" | xargs
    }

    reorder_tools_by_preferred_order() {
        local current="$1"
        local preferred="$2"
        local out=""
        local t=""
        for t in $preferred; do
            if echo " $current " | grep -q " $t "; then
                out="$out $t"
            fi
        done
        for t in $current; do
            if ! echo " $out " | grep -q " $t "; then
                out="$out $t"
            fi
        done
        normalize_tools_line "$out"
    }

    apply_strategy_profile() {
        local profile="$1"
        local preferred=""
        case "$profile" in
            web)
                preferred="subfinder httpx wafw00f gau katana paramspider arjun ffuf nuclei dalfox sqlmap wapiti nikto nmap"
                ;;
            network)
                preferred="subfinder httpx nmap wafw00f nuclei nikto gau katana ffuf wapiti sqlmap paramspider arjun dalfox"
                ;;
            *)
                preferred="subfinder httpx nmap gau katana paramspider arjun ffuf wafw00f nuclei dalfox wapiti sqlmap nikto"
                ;;
        esac
        ACTIVE_TOOLS="$(reorder_tools_by_preferred_order "$ACTIVE_TOOLS" "$preferred")"
    }

    infer_default_profile() {
        local t="$1"
        # IP murni cenderung network-heavy; domain/URL cenderung web-heavy.
        if [[ "$t" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ "$t" =~ : ]]; then
            echo "network"
        else
            echo "web"
        fi
    }

    apply_ai_execution_plan() {
        local summary_file="$TARGET_DIR/recon/ai_plan_summary.txt"
        local allow_ai_planner=0
        local planner_prompt=""
        local payload=""
        local raw_resp=""
        local llm_resp=""
        local planned_tools=""
        local skip_tools=""
        local t=""

        : > "$summary_file"
        echo "AI Execution Plan Summary - $(date)" >> "$summary_file"
        echo "Target: $TARGET" >> "$summary_file"
        echo "Initial tools: $ACTIVE_TOOLS" >> "$summary_file"

        if [[ "${USE_AI:-n}" == "y" || "${USE_AI:-n}" == "Y" ]]; then
            if [[ "${AI_ORCHESTRATOR_MODE:-false}" == "true" || "${AI_ORCHESTRATOR_MODE:-false}" == "1" ]]; then
                allow_ai_planner=1
            fi
        fi
        if [[ "$allow_ai_planner" -ne 1 ]]; then
            AI_PLAN_PROFILE_PRIMARY="$(infer_default_profile "$TARGET")"
            apply_strategy_profile "$AI_PLAN_PROFILE_PRIMARY"
            echo "Planner mode: disabled (manual mode)." >> "$summary_file"
            echo "Profile fallback: $AI_PLAN_PROFILE_PRIMARY" >> "$summary_file"
            ACTIVE_TOOLS="$(normalize_tools_line "$ACTIVE_TOOLS")"
            return 0
        fi
        if [[ "${DRY_RUN:-false}" == "true" ]]; then
            AI_PLAN_PROFILE_PRIMARY="$(infer_default_profile "$TARGET")"
            apply_strategy_profile "$AI_PLAN_PROFILE_PRIMARY"
            echo "Planner mode: disabled (DRY-RUN)." >> "$summary_file"
            echo "Profile fallback: $AI_PLAN_PROFILE_PRIMARY" >> "$summary_file"
            ACTIVE_TOOLS="$(normalize_tools_line "$ACTIVE_TOOLS")"
            return 0
        fi
        if ! command -v jq >/dev/null 2>&1; then
            AI_PLAN_PROFILE_PRIMARY="$(infer_default_profile "$TARGET")"
            apply_strategy_profile "$AI_PLAN_PROFILE_PRIMARY"
            echo "Planner mode: disabled (jq not found)." >> "$summary_file"
            echo "Profile fallback: $AI_PLAN_PROFILE_PRIMARY" >> "$summary_file"
            ACTIVE_TOOLS="$(normalize_tools_line "$ACTIVE_TOOLS")"
            return 0
        fi
        if ! ollama_check; then
            AI_PLAN_PROFILE_PRIMARY="$(infer_default_profile "$TARGET")"
            apply_strategy_profile "$AI_PLAN_PROFILE_PRIMARY"
            echo "Planner mode: disabled (Ollama unavailable)." >> "$summary_file"
            echo "Profile fallback: $AI_PLAN_PROFILE_PRIMARY" >> "$summary_file"
            ACTIVE_TOOLS="$(normalize_tools_line "$ACTIVE_TOOLS")"
            return 0
        fi
        AI_PLANNER_ENABLED=1

        # Deteksi jenis target (IP atau Domain)
        local target_type="domain"
        if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            target_type="ip"
        fi

        planner_prompt=$(cat <<EOF
Kamu adalah AI Decision Engine utama untuk workflow pentest.
Target: $TARGET (Jenis: $target_type)
Tools tersedia (boleh dipilih subset): $ACTIVE_TOOLS
Scan speed: ${SCAN_SPEED:-Normal (Balanced)}
Proxy mode: ${USE_PROXY:-false}

Tugas:
1) Lakukan reasoning (berpikir langkah-demi-langkah) terlebih dahulu mengenai target ini.
2) Tentukan tool yang paling prioritas untuk target ini. (Misal: IP butuh Nmap, Domain butuh Subfinder).
3) Tentukan tool yang sebaiknya di-skip jika target tidak relevan.
4) Tentukan strategi retry agar efisien.
5) Beri override argumen Nmap/SQLMap jika perlu (buat lebih agresif jika target aman untuk di-scan).

Kembalikan HANYA JSON valid (tanpa markdown/code fence) dengan schema:
{
  "strategy": {"primary":"web|network|balanced|aggressive","backup":"web|network|balanced"},
  "tool_order": ["subfinder","httpx","nmap","gau","katana","paramspider","arjun","ffuf","nuclei","dalfox","wapiti","sqlmap","nikto","wafw00f"],
  "skip_tools": ["tool_opsional"],
  "retry": {"default":2,"recon":2,"vuln":2,"heavy":1},
  "nmap_args_override": "",
  "sqlmap_args_override": "",
  "reasoning_short": "ringkas <= 2 kalimat"
}

Aturan:
- Untuk model DeepSeek-R1, silakan gunakan tag <think>...</think> untuk menalar, lalu letakkan JSON valid di akhir output.
- Gunakan "aggressive" untuk strategy primary jika target berupa domain/URL web yang kompleks.
- Hanya gunakan nama tools dari daftar tersedia.
- Nilai retry harus integer 0..4.
- Jangan menambah command destruktif.
EOF
)

        payload="$(jq -n --arg model "${OLLAMA_MODEL:-deepseek-r1:8b}" --arg prompt "$planner_prompt" '{model:$model,prompt:$prompt,stream:false}')"
        raw_resp="$(ollama_curl -fsS -m "${AI_HTTP_TIMEOUT:-30}" -X POST "${OLLAMA_GENERATE_API:-${OLLAMA_HOST%/}/api/generate}" -H "Content-Type: application/json" -d "$payload" || true)"
        echo "$raw_resp" > "$AI_PLAN_RAW"
        
        # Bersihkan tag <think> jika ada (dari DeepSeek R1)
        llm_resp="$(echo "$raw_resp" | jq -r '.response // empty' 2>/dev/null || true)"
        llm_resp="$(clean_json_response "$llm_resp")"

        if [[ -z "$llm_resp" ]] || ! echo "$llm_resp" | jq -e . >/dev/null 2>&1; then
            echo "Planner mode: invalid AI JSON response, fallback to default tools." >> "$summary_file"
            AI_PLAN_PROFILE_PRIMARY="$(infer_default_profile "$TARGET")"
            apply_strategy_profile "$AI_PLAN_PROFILE_PRIMARY"
            echo "Profile fallback: $AI_PLAN_PROFILE_PRIMARY" >> "$summary_file"
            ACTIVE_TOOLS="$(normalize_tools_line "$ACTIVE_TOOLS")"
            return 0
        fi

        echo "$llm_resp" > "$AI_PLAN_FILE"
        
        # Upgrade Logika: Tambahkan opsi 'aggressive' untuk AI
        AI_PLAN_PROFILE_PRIMARY="$(echo "$llm_resp" | jq -r '.strategy.primary // "balanced"' | tr '[:upper:]' '[:lower:]')"
        AI_PLAN_PROFILE_BACKUP="$(echo "$llm_resp" | jq -r '.strategy.backup // "web"' | tr '[:upper:]' '[:lower:]')"
        [[ "$AI_PLAN_PROFILE_PRIMARY" != "web" && "$AI_PLAN_PROFILE_PRIMARY" != "network" && "$AI_PLAN_PROFILE_PRIMARY" != "balanced" && "$AI_PLAN_PROFILE_PRIMARY" != "aggressive" ]] && AI_PLAN_PROFILE_PRIMARY="balanced"
        [[ "$AI_PLAN_PROFILE_BACKUP" != "web" && "$AI_PLAN_PROFILE_BACKUP" != "network" && "$AI_PLAN_PROFILE_BACKUP" != "balanced" ]] && AI_PLAN_PROFILE_BACKUP="web"
        planned_tools="$(echo "$llm_resp" | jq -r '.tool_order[]?')"
        skip_tools="$(echo "$llm_resp" | jq -r '.skip_tools[]?')"

        # Build active tools from AI order first, but only keep tools that are available in current selection.
        local ai_tools=""
        while IFS= read -r t; do
            [[ -n "$t" ]] || continue
            # Jika mode aggressive, paksa masukkan tool berat
            if echo " $SELECTED_TOOLS " | grep -q " $t " || [[ "$AI_PLAN_PROFILE_PRIMARY" == "aggressive" && "$t" =~ ^(sqlmap|dalfox|nuclei)$ ]]; then
                ai_tools="$ai_tools $t"
            fi
        done <<< "$planned_tools"
        if [[ -z "$ai_tools" ]]; then
            ai_tools="$SELECTED_TOOLS"
        fi

        # Remove skipped tools
        while IFS= read -r t; do
            [[ -n "$t" ]] || continue
            ai_tools="$(echo " $ai_tools " | sed "s/ $t / /g")"
        done <<< "$skip_tools"

        ACTIVE_TOOLS="$(normalize_tools_line "$ai_tools")"
        [[ -z "$ACTIVE_TOOLS" ]] && ACTIVE_TOOLS="$(normalize_tools_line "$SELECTED_TOOLS")"
        
        # Apply profile and dynamic logic
        if [[ "$AI_PLAN_PROFILE_PRIMARY" == "aggressive" ]]; then
            export AI_AGGRESSIVE_MODE=true
            apply_strategy_profile "web" # aggressive is usually web heavy
        else
            apply_strategy_profile "$AI_PLAN_PROFILE_PRIMARY"
        fi

        AI_PLAN_RETRY_DEFAULT="$(echo "$llm_resp" | jq -r '.retry.default // 2' | tr -dc '0-9')"
        AI_PLAN_RETRY_RECON="$(echo "$llm_resp" | jq -r '.retry.recon // 2' | tr -dc '0-9')"
        AI_PLAN_RETRY_VULN="$(echo "$llm_resp" | jq -r '.retry.vuln // 2' | tr -dc '0-9')"
        AI_PLAN_RETRY_HEAVY="$(echo "$llm_resp" | jq -r '.retry.heavy // 1' | tr -dc '0-9')"
        [[ -z "$AI_PLAN_RETRY_DEFAULT" ]] && AI_PLAN_RETRY_DEFAULT=2
        [[ -z "$AI_PLAN_RETRY_RECON" ]] && AI_PLAN_RETRY_RECON=2
        [[ -z "$AI_PLAN_RETRY_VULN" ]] && AI_PLAN_RETRY_VULN=2
        [[ -z "$AI_PLAN_RETRY_HEAVY" ]] && AI_PLAN_RETRY_HEAVY=1
        (( AI_PLAN_RETRY_DEFAULT > 4 )) && AI_PLAN_RETRY_DEFAULT=4
        (( AI_PLAN_RETRY_RECON > 4 )) && AI_PLAN_RETRY_RECON=4
        (( AI_PLAN_RETRY_VULN > 4 )) && AI_PLAN_RETRY_VULN=4
        (( AI_PLAN_RETRY_HEAVY > 4 )) && AI_PLAN_RETRY_HEAVY=4
        if [[ "${AI_AGGRESSIVE_MODE:-false}" == "true" || "${AI_AGGRESSIVE_MODE:-false}" == "1" ]]; then
            (( AI_PLAN_RETRY_DEFAULT < 3 )) && AI_PLAN_RETRY_DEFAULT=3
            (( AI_PLAN_RETRY_RECON < 3 )) && AI_PLAN_RETRY_RECON=3
            (( AI_PLAN_RETRY_VULN < 3 )) && AI_PLAN_RETRY_VULN=3
            (( AI_PLAN_RETRY_HEAVY < 2 )) && AI_PLAN_RETRY_HEAVY=2
        fi

        local nmap_override=""
        local sqlmap_override=""
        nmap_override="$(echo "$llm_resp" | jq -r '.nmap_args_override // ""')"
        sqlmap_override="$(echo "$llm_resp" | jq -r '.sqlmap_args_override // ""')"
        if [[ -n "$nmap_override" && "$nmap_override" != "null" ]]; then
            NMAP_ARGS="$nmap_override"
        fi
        if [[ -n "$sqlmap_override" && "$sqlmap_override" != "null" ]]; then
            SQLMAP_ARGS="$sqlmap_override"
        fi

        {
            echo "Planner mode: enabled"
            echo "Strategy: primary=$AI_PLAN_PROFILE_PRIMARY backup=$AI_PLAN_PROFILE_BACKUP"
            echo "Active tools: $ACTIVE_TOOLS"
            echo "Retry policy: default=$AI_PLAN_RETRY_DEFAULT recon=$AI_PLAN_RETRY_RECON vuln=$AI_PLAN_RETRY_VULN heavy=$AI_PLAN_RETRY_HEAVY"
            echo "Nmap args: $NMAP_ARGS"
            echo "SQLMap args: $SQLMAP_ARGS"
            echo "Reasoning: $(echo "$llm_resp" | jq -r '.reasoning_short // "N/A"')"
        } >> "$summary_file"
    }

    ai_replan_after_recon() {
        local summary_file="$TARGET_DIR/recon/ai_plan_summary.txt"
        local all_urls_count params_count alive_count
        local repl_prompt payload raw_resp llm_resp
        local enable_tools disable_tools t

        [[ "$AI_PLANNER_ENABLED" -eq 1 ]] || return 0
        [[ "${DRY_RUN:-false}" != "true" ]] || return 0
        command -v jq >/dev/null 2>&1 || return 0
        ollama_check || return 0

        all_urls_count=$(wc -l < "$TARGET_DIR/recon/all_urls.txt" 2>/dev/null | tr -d ' ')
        params_count=$(wc -l < "$TARGET_DIR/recon/urls_with_params.txt" 2>/dev/null | tr -d ' ')
        alive_count=$(wc -l < "$TARGET_DIR/recon/alive.txt" 2>/dev/null | tr -d ' ')
        [[ -z "$all_urls_count" ]] && all_urls_count=0
        [[ -z "$params_count" ]] && params_count=0
        [[ -z "$alive_count" ]] && alive_count=0
        
        # Ekstrak data nyata (Ports & URLs) untuk konteks yang lebih dalam
        local open_ports=""
        if [[ -f "$TARGET_DIR/recon/nmap.nmap" ]]; then
            open_ports=$(awk -F/ '/^[0-9]+\/tcp.*open/ {print $1}' "$TARGET_DIR/recon/nmap.nmap" | xargs echo | tr ' ' ',')
        fi
        [[ -z "$open_ports" ]] && open_ports="Tidak diketahui"
        
        local top_urls="Tidak ada URL yang ditemukan"
        if [[ -f "$TARGET_DIR/recon/urls_with_params.txt" ]] && [[ "$params_count" -gt 0 ]]; then
            top_urls=$(head -n 5 "$TARGET_DIR/recon/urls_with_params.txt" | tr '\n' ' ')
        elif [[ -f "$TARGET_DIR/recon/all_urls.txt" ]] && [[ "$all_urls_count" -gt 0 ]]; then
            top_urls=$(head -n 5 "$TARGET_DIR/recon/all_urls.txt" | tr '\n' ' ')
        fi

        repl_prompt=$(cat <<EOF
Kamu adalah AI Pentest Planner fase-2 (setelah recon).
Target: $TARGET
Strategy awal: $AI_PLAN_PROFILE_PRIMARY (backup: $AI_PLAN_PROFILE_BACKUP)
Tools aktif saat ini: $ACTIVE_TOOLS

[TEMUAN RECON]
- alive_hosts: $alive_count
- total_urls: $all_urls_count
- urls_with_params: $params_count
- open_ports: $open_ports
- top_urls_sample: $top_urls

[TUGAS]
Berdasarkan temuan di atas, putuskan alat mana yang harus dijalankan untuk Fase 2 (Vulnerability Scanning).
- Jika ada banyak parameter, prioritaskan dalfox, sqlmap, wapiti.
- Jika target terlihat seperti API (JSON) atau jaringan murni, sesuaikan pilihanmu.

Kembalikan HANYA JSON valid:
{
  "phase2_focus":"web|network|balanced",
  "enable_tools":["nuclei","dalfox","sqlmap","wapiti","nikto","nmap"],
  "disable_tools":["tool_optional"],
  "retry":{"vuln":2,"heavy":1},
  "nmap_args_override":"",
  "sqlmap_args_override":"",
  "reasoning_short":"singkat (maksimal 2 kalimat)"
}

Aturan:
- Untuk model reasoning, silakan berpikir di dalam <think>...</think>, lalu berikan JSON.
- Jangan buat command baru.
- Hanya pilih nama tool yang sudah ada.
- Jika urls_with_params sangat kecil, kurangi fokus dalfox/sqlmap.
EOF
)

        payload="$(jq -n --arg model "${OLLAMA_MODEL:-deepseek-r1:8b}" --arg prompt "$repl_prompt" '{model:$model,prompt:$prompt,stream:false}')"
        raw_resp="$(ollama_curl -fsS -m "${AI_HTTP_TIMEOUT:-30}" -X POST "${OLLAMA_GENERATE_API:-${OLLAMA_HOST%/}/api/generate}" -H "Content-Type: application/json" -d "$payload" || true)"
        
        llm_resp="$(echo "$raw_resp" | jq -r '.response // empty' 2>/dev/null || true)"
        llm_resp="$(clean_json_response "$llm_resp")"

        if [[ -z "$llm_resp" ]] || ! echo "$llm_resp" | jq -e . >/dev/null 2>&1; then
            return 0
        fi

        echo "$llm_resp" > "$AI_REPLAN_FILE"
        local phase2_focus
        phase2_focus="$(echo "$llm_resp" | jq -r '.phase2_focus // "balanced"' | tr '[:upper:]' '[:lower:]')"
        [[ "$phase2_focus" != "web" && "$phase2_focus" != "network" && "$phase2_focus" != "balanced" ]] && phase2_focus="$AI_PLAN_PROFILE_BACKUP"
        apply_strategy_profile "$phase2_focus"

        enable_tools="$(echo "$llm_resp" | jq -r '.enable_tools[]?')"
        disable_tools="$(echo "$llm_resp" | jq -r '.disable_tools[]?')"

        while IFS= read -r t; do
            [[ -n "$t" ]] || continue
            if echo " $SELECTED_TOOLS " | grep -q " $t "; then
                if ! echo " $ACTIVE_TOOLS " | grep -q " $t "; then
                    ACTIVE_TOOLS="$ACTIVE_TOOLS $t"
                fi
            fi
        done <<< "$enable_tools"
        while IFS= read -r t; do
            [[ -n "$t" ]] || continue
            ACTIVE_TOOLS="$(echo " $ACTIVE_TOOLS " | sed "s/ $t / /g")"
        done <<< "$disable_tools"
        ACTIVE_TOOLS="$(normalize_tools_line "$ACTIVE_TOOLS")"

        local rv rh nmap2 sqlmap2
        rv="$(echo "$llm_resp" | jq -r '.retry.vuln // empty' | tr -dc '0-9')"
        rh="$(echo "$llm_resp" | jq -r '.retry.heavy // empty' | tr -dc '0-9')"
        [[ -n "$rv" ]] && AI_PLAN_RETRY_VULN="$rv"
        [[ -n "$rh" ]] && AI_PLAN_RETRY_HEAVY="$rh"
        (( AI_PLAN_RETRY_VULN > 4 )) && AI_PLAN_RETRY_VULN=4
        (( AI_PLAN_RETRY_HEAVY > 4 )) && AI_PLAN_RETRY_HEAVY=4

        nmap2="$(echo "$llm_resp" | jq -r '.nmap_args_override // ""')"
        sqlmap2="$(echo "$llm_resp" | jq -r '.sqlmap_args_override // ""')"
        [[ -n "$nmap2" && "$nmap2" != "null" ]] && NMAP_ARGS="$nmap2"
        [[ -n "$sqlmap2" && "$sqlmap2" != "null" ]] && SQLMAP_ARGS="$sqlmap2"

        {
            echo "Phase2 replan: enabled"
            echo "Phase2 focus: $phase2_focus"
            echo "Active tools (phase2): $ACTIVE_TOOLS"
            echo "Retry update: vuln=$AI_PLAN_RETRY_VULN heavy=$AI_PLAN_RETRY_HEAVY"
            echo "Reasoning phase2: $(echo "$llm_resp" | jq -r '.reasoning_short // "N/A"')"
        } >> "$summary_file"
    }

    build_ai_attack_graph() {
        local graph_file="$TARGET_DIR/vulnerabilities/ai_attack_graph.json"
        local graph_txt="$TARGET_DIR/vulnerabilities/ai_attack_graph.txt"
        local summary_file="$TARGET_DIR/recon/ai_plan_summary.txt"
        local nuclei_high=0 nuclei_critical=0 xss_hits=0 sqlmap_hits=0 param_count=0 alive_count=0
        local prompt payload raw_resp llm_resp
        local generated_by="heuristic"

        [[ "${USE_AI:-n}" == "y" || "${USE_AI:-n}" == "Y" ]] || return 0
        command -v jq >/dev/null 2>&1 || return 0

        nuclei_high=$(grep -Eic '(^|\s)(high)(\s|$)' "$TARGET_DIR/vulnerabilities/nuclei.txt" 2>/dev/null || echo 0)
        nuclei_critical=$(grep -Eic '(^|\s)(critical)(\s|$)' "$TARGET_DIR/vulnerabilities/nuclei.txt" 2>/dev/null || echo 0)
        xss_hits=$(grep -Eic '(xss|payload|vulnerable|reflected)' "$TARGET_DIR/vulnerabilities/xss.txt" 2>/dev/null || echo 0)
        sqlmap_hits=$(grep -Eic '(is vulnerable|sql injection|parameter|payload)' "$TARGET_DIR/vulnerabilities/sqlmap"/* 2>/dev/null || echo 0)
        param_count=$(wc -l < "$TARGET_DIR/recon/urls_with_params.txt" 2>/dev/null | tr -d ' ')
        alive_count=$(wc -l < "$TARGET_DIR/recon/alive.txt" 2>/dev/null | tr -d ' ')
        [[ -z "$param_count" ]] && param_count=0
        [[ -z "$alive_count" ]] && alive_count=0

        if [[ "$AI_PLANNER_ENABLED" -eq 1 ]] && ollama_check; then
            prompt=$(cat <<EOF
Kamu adalah Senior Pentester Planner (fase post-vulnerability).
Target: $TARGET
Konteks ringkas:
- strategy_primary: $AI_PLAN_PROFILE_PRIMARY
- strategy_backup: $AI_PLAN_PROFILE_BACKUP
- alive_hosts: $alive_count
- urls_with_params: $param_count
- nuclei_high: $nuclei_high
- nuclei_critical: $nuclei_critical
- xss_hits: $xss_hits
- sqlmap_hits: $sqlmap_hits

Buat attack graph praktis untuk eksekusi berikutnya.
Kembalikan HANYA JSON valid:
{
  "persona":"web|network|hybrid",
  "priority_path":[
    {"phase":"validate_surface","tool":"httpx","goal":"...","reason":"...","confidence":0.0},
    {"phase":"exploit_validation","tool":"sqlmap","goal":"...","reason":"...","confidence":0.0}
  ],
  "quick_wins":["..."],
  "manual_checks":["..."],
  "controlled_commands":["..."],
  "risk_notes":["..."]
}

Aturan:
- confidence 0.0 - 1.0
- controlled_commands non-destruktif / semi-otomatis
- tanpa markdown/code fence
EOF
)
            payload="$(jq -n --arg model "${OLLAMA_MODEL:-deepseek-r1:8b}" --arg prompt "$prompt" '{model:$model,prompt:$prompt,stream:false}')"
            raw_resp="$(ollama_curl -fsS -m "${AI_HTTP_TIMEOUT:-30}" -X POST "${OLLAMA_GENERATE_API:-${OLLAMA_HOST%/}/api/generate}" -H "Content-Type: application/json" -d "$payload" || true)"
            llm_resp="$(echo "$raw_resp" | jq -r '.response // empty' 2>/dev/null || true)"
            if [[ -n "$llm_resp" ]] && echo "$llm_resp" | jq -e . >/dev/null 2>&1; then
                echo "$llm_resp" > "$graph_file"
                generated_by="llm"
            fi
        fi

        if [[ ! -f "$graph_file" ]]; then
            # Ensure all numeric vars are properly set (default 0)
            alive_count="${alive_count:-0}"; alive_count="${alive_count//[^0-9]/}"; [[ -z "$alive_count" ]] && alive_count=0
            param_count="${param_count:-0}"; param_count="${param_count//[^0-9]/}"; [[ -z "$param_count" ]] && param_count=0
            nuclei_high="${nuclei_high:-0}"; nuclei_high="${nuclei_high//[^0-9]/}"; [[ -z "$nuclei_high" ]] && nuclei_high=0
            nuclei_critical="${nuclei_critical:-0}"; nuclei_critical="${nuclei_critical//[^0-9]/}"; [[ -z "$nuclei_critical" ]] && nuclei_critical=0
            xss_hits="${xss_hits:-0}"; xss_hits="${xss_hits//[^0-9]/}"; [[ -z "$xss_hits" ]] && xss_hits=0
            sqlmap_hits="${sqlmap_hits:-0}"; sqlmap_hits="${sqlmap_hits//[^0-9]/}"; [[ -z "$sqlmap_hits" ]] && sqlmap_hits=0
            
            jq -n \
              --arg persona "$AI_PLAN_PROFILE_PRIMARY" \
              --argjson alive "$alive_count" \
              --argjson params "$param_count" \
              --argjson n_high "$nuclei_high" \
              --argjson n_crit "$nuclei_critical" \
              --argjson xss "$xss_hits" \
              --argjson sqli "$sqlmap_hits" \
              '{
                persona: (if $persona=="balanced" then "hybrid" else $persona end),
                priority_path: [
                  {phase:"validate_surface", tool:"httpx", goal:"Validasi endpoint hidup dan status", reason:"Kurangi false positive sebelum verifikasi lanjutan", confidence:0.74},
                  {phase:"vuln_focus", tool:(if $sqli>0 then "sqlmap" elif $xss>0 then "dalfox" else "nuclei" end), goal:"Validasi temuan berisiko tertinggi", reason:"Prioritas berdasarkan sinyal vulnerability yang tersedia", confidence:0.78},
                  {phase:"hardening_check", tool:"nmap", goal:"Verifikasi service exposure dan versi", reason:"Konteks network tetap dibutuhkan untuk chaining", confidence:0.66}
                ],
                quick_wins: [
                  ("Nuclei high/critical total: " + (($n_high + $n_crit)|tostring)),
                  ("URLs dengan parameter: " + ($params|tostring)),
                  ("Alive hosts: " + ($alive|tostring))
                ],
                manual_checks: [
                  "Cek endpoint auth/admin dari interesting_endpoints_pack.txt",
                  "Uji IDOR pada parameter id, user_id, account",
                  "Validasi business logic bypass setelah payload otomatis"
                ],
                controlled_commands: [
                  "nuclei -l recon/alive.txt -severity high,critical -silent",
                  "sqlmap -m recon/urls_with_params.txt --batch --smart --level=1 --risk=1",
                  "dalfox file recon/urls_with_params.txt --silence"
                ],
                risk_notes: [
                  "Gunakan approval untuk aksi tier medium/high",
                  "Pertahankan delay jika target menunjukkan gejala rate-limit/WAF"
                ]
              }' > "$graph_file"
        fi

        jq -r '
            "AI ATTACK GRAPH",
            "persona: " + (.persona // "unknown"),
            "",
            "priority_path:",
            (.priority_path[]? | "- [" + (.phase // "phase") + "] " + (.tool // "tool") + " => " + (.goal // "goal")),
            "",
            "quick_wins:",
            (.quick_wins[]? | "- " + .),
            "",
            "manual_checks:",
            (.manual_checks[]? | "- " + .),
            "",
            "controlled_commands:",
            (.controlled_commands[]? | "- " + .)
        ' "$graph_file" > "$graph_txt" 2>/dev/null || true

        {
            echo "Post-vuln attack graph: generated ($generated_by)"
            echo "Attack graph file: $graph_file"
        } >> "$summary_file"
    }

    ai_retries_for_step() {
        local step="$1"
        case "$step" in
            "Subfinder"|"Wafw00f"|"httpx"|"Nmap"*|"GAU"|"Katana"|"Probe URLs (filter 200)"|"ParamSpider"|"Arjun"|"FFUF ("*)
                echo "$AI_PLAN_RETRY_RECON"
                ;;
            "Nuclei"|"Dalfox"|"Wapiti ("*|"SQLMap"*)
                echo "$AI_PLAN_RETRY_VULN"
                ;;
            "Nikto ("*)
                echo "$AI_PLAN_RETRY_HEAVY"
                ;;
            *)
                echo "$AI_PLAN_RETRY_DEFAULT"
                ;;
        esac
    }

    if declare -F scope_guard_target >/dev/null 2>&1; then
        if ! scope_guard_target "$TARGET"; then
            log_msg "!" "\033[1;31m" "$TARGET_DISPLAY" "ScopeGuard" "Target diblokir policy. Target dilewati."
            echo "[$TARGET] Scope guard blocked target." >> "$OUTPUT_BASE/failed_tasks.txt"
            abort_target_scan
            return 0
        fi
    fi

    # Jalankan orchestrator discovery dari awal agar AI bisa mengumpulkan intel saat tools lain masih berjalan.
    start_ai_discovery_async "startup"
    apply_ai_execution_plan
    log_msg "AI" "\033[1;35m" "$TARGET" "PLANNER" "Engine aktif. Tools: $ACTIVE_TOOLS"

    # Proxy Allocation and Checking
    local CURRENT_PROXY=""
    local TARGET_DISPLAY="$TARGET"

    if [[ "$USE_PROXY" == "true" ]]; then
        CURRENT_PROXY=$(get_proxy)
        
        if [[ -n "$CURRENT_PROXY" ]]; then
            TARGET_DISPLAY="$TARGET [$CURRENT_PROXY]"
            set_proxy_env "$CURRENT_PROXY"
            ensure_proxy_alive "$TARGET" "INIT"
            audit_proxy "INIT" "PROXY_ASSIGNED" "$CURRENT_PROXY"
        else
            log_msg "!" "\033[1;33m" "$TARGET_DISPLAY" "Proxy" "No proxies available. Running without proxy."
            set_proxy_env ""
            audit_proxy "INIT" "NO_PROXY_AVAILABLE" "Proxy pool empty at startup."
        fi
    else
        audit_proxy "INIT" "PROXY_DISABLED" "User selected No Proxy mode."
    fi

    run_cmd() {
        is_network_step() {
            local s="$1"
            case "$s" in
                "Subfinder"|"Wafw00f"|"httpx"|"Nmap"*|"GAU"|"Katana"|"Probe URLs (filter 200)"|"ParamSpider"|"Arjun"|"FFUF ("*|"Nuclei"|"Dalfox"|"Wapiti ("*|"SQLMap"*|"Nikto ("*)
                    return 0
                    ;;
            esac
            return 1
        }

        cmd_has_proxy_flag() {
            local -n cmd_array_ref="$1"
            local token
            for token in "${cmd_array_ref[@]}"; do
                case "$token" in
                    -proxy|--proxy|-proxy-url|--proxy-url|-http-proxy|--http-proxy|-x|--proxy=*|--proxy-url=*|--http-proxy=*)
                        return 0
                        ;;
                esac
            done
            return 1
        }

        inject_proxy_for_tool() {
            local -n tool_cmd_ref="$1"
            local proxy="$2"
            local tool="${tool_cmd_ref[0]:-}"

            # Respect custom proxy flags if user already provided in custom args.
            if cmd_has_proxy_flag tool_cmd_ref; then
                return 0
            fi

            case "$tool" in
                subfinder) tool_cmd_ref+=("-proxy" "$proxy") ;;
                httpx) tool_cmd_ref+=("-http-proxy" "$proxy") ;;
                katana) tool_cmd_ref+=("-proxy" "$proxy") ;;
                ffuf) tool_cmd_ref+=("-x" "$proxy") ;;
                nuclei) tool_cmd_ref+=("-proxy-url" "$proxy") ;;
                dalfox) tool_cmd_ref+=("--proxy" "$proxy") ;;
                sqlmap) tool_cmd_ref+=("--proxy=$proxy") ;;
                *)
                    return 1
                    ;;
            esac
            return 0
        }

        local step="$1"; shift
        local max_retries
        local retry_count=0
        local cmd_pid=""
        local exit_code=1
        local start_time=$(date +%s)
        local attempt_no=1
        FORCE_SKIP_TOOL=0
        max_retries="$(ai_retries_for_step "$step")"
        [[ -z "$max_retries" ]] && max_retries=2

        check_skip_request() {
            local requested_step=""

            if [[ -f "$OUTPUT_BASE/.status/${TARGET_SAFE}.skip_domain" ]]; then
                rm -f "$OUTPUT_BASE/.status/${TARGET_SAFE}.skip_domain"
                log_msg "→" "\033[1;36m" "$TARGET_DISPLAY" "System" "Skipping entire domain..."
                append_skip_domain_once
                echo "$TARGET|$step|Skipped Domain|0" > "$STATUS_FILE"
                return 2
            fi

            if [[ -f "$OUTPUT_BASE/.status/${TARGET_SAFE}.skip_tool" ]]; then
                requested_step=$(head -n 1 "$OUTPUT_BASE/.status/${TARGET_SAFE}.skip_tool" 2>/dev/null || true)
                rm -f "$OUTPUT_BASE/.status/${TARGET_SAFE}.skip_tool"
                if [[ -z "$requested_step" || "$requested_step" == "$step" ]]; then
                    log_msg "!" "\033[1;33m" "$TARGET_DISPLAY" "$step" "Skipped manually by user."
                    echo "$TARGET|$step|Skipped Manual|0" > "$STATUS_FILE"
                    FORCE_SKIP_TOOL=0
                    return 10
                fi
            fi

            if [[ "$FORCE_SKIP_TOOL" -eq 1 ]]; then
                log_msg "!" "\033[1;33m" "$TARGET_DISPLAY" "$step" "Skipped manually by user."
                FORCE_SKIP_TOOL=0
                echo "$TARGET|$step|Skipped Manual|0" > "$STATUS_FILE"
                return 10
            fi

            return 1
        }

        while [[ $retry_count -le $max_retries ]]; do
            check_skip_request
            local skip_rc=$?
            case "$skip_rc" in
                2) return 2 ;;
                10) return 0 ;;
            esac

            if [[ $retry_count -gt 0 ]]; then
                log_msg "↻" "\033[1;33m" "$TARGET_DISPLAY" "$step" "Retry $retry_count/$max_retries"
                audit_proxy "$step" "RETRY" "attempt=$attempt_no retry=$retry_count/$max_retries"
                sleep 3
            fi

            # Pastikan proxy hidup sebelum menjalankan tool apapun (termasuk nmap)
            ensure_proxy_alive "$TARGET" "$step"

            # Optimal timeout based on tool complexity
            local timeout_sec=600
            case "$step" in
                "httpx"|"Probe URLs"*) timeout_sec=180 ;;
                "Wafw00f"|"Subfinder") timeout_sec=120 ;;
                "Nmap"*) timeout_sec=1200 ;; # Nmap can take longer
                "SQLMap"*) timeout_sec=900 ;;
                "Nuclei"|"Dalfox"|"Wapiti"|"FFUF"*) timeout_sec=900 ;;
            esac
            
            # Construct actual command
            local cmd=()
            local has_proxy_marker=false
            for arg in "$@"; do
                if [[ "$arg" == "__PROXY__" ]]; then
                    has_proxy_marker=true
                    continue
                fi
                cmd+=("$arg")
            done
            local dry_cmd=""
            dry_cmd=$(printf "%q " "${cmd[@]}")
            local cmd_hash=""
            cmd_hash=$(cmd_fingerprint "$dry_cmd")

            if [[ "$USE_PROXY" == "true" && "${PROXY_STRICT:-false}" == "true" ]] && is_network_step "$step" && [[ "$has_proxy_marker" != "true" ]]; then
                log_msg "!" "\033[1;33m" "$TARGET_DISPLAY" "$step" "Strict proxy: tool ini belum punya integrasi proxy internal. Step dilewati."
                echo "$TARGET|$step|Skipped (strict proxy)|0" > "$STATUS_FILE"
                audit_proxy "$step" "SKIP_STRICT_UNSUPPORTED" "Network step missing __PROXY__ marker."
                return 0
            fi

            if [[ "$has_proxy_marker" == "true" && "$USE_PROXY" == "true" ]]; then
                if [[ -n "$CURRENT_PROXY" ]]; then
                    if inject_proxy_for_tool cmd "$CURRENT_PROXY"; then
                        log_msg "i" "\033[1;35m" "$TARGET_DISPLAY" "$step" "Proxy applied: $CURRENT_PROXY"
                        audit_proxy "$step" "PROXY_APPLIED" "$CURRENT_PROXY"
                    elif [[ "${PROXY_STRICT:-false}" == "true" ]]; then
                        log_msg "!" "\033[1;33m" "$TARGET_DISPLAY" "$step" "Strict proxy: mapping proxy untuk tool ini belum didukung. Step dilewati."
                        echo "$TARGET|$step|Skipped (strict proxy unsupported)|0" > "$STATUS_FILE"
                        audit_proxy "$step" "SKIP_STRICT_MAPPING" "No proxy flag mapping for tool."
                        return 0
                    else
                        log_msg "i" "\033[1;35m" "$TARGET_DISPLAY" "$step" "Best effort: tool tanpa proxy flag khusus, mengandalkan env proxy."
                        audit_proxy "$step" "ENV_PROXY_ONLY" "No explicit proxy flag mapping, using env proxy vars."
                    fi
                elif [[ "${PROXY_STRICT:-false}" == "true" ]]; then
                    log_msg "!" "\033[1;33m" "$TARGET_DISPLAY" "$step" "Strict proxy: tidak ada proxy aktif. Step dilewati."
                    echo "$TARGET|$step|Skipped (no proxy available)|0" > "$STATUS_FILE"
                    audit_proxy "$step" "SKIP_STRICT_NO_PROXY" "No active proxy available."
                    return 0
                else
                    log_msg "!" "\033[1;33m" "$TARGET_DISPLAY" "$step" "Best effort: proxy tidak tersedia, lanjut direct."
                    audit_proxy "$step" "FALLBACK_DIRECT" "No active proxy, best-effort continued direct."
                fi
            fi

            if [[ "${DRY_RUN:-false}" == "true" ]]; then
                log_msg "i" "\033[1;35m" "$TARGET_DISPLAY" "$step" "DRY-RUN: $dry_cmd"
                echo "[DRY-RUN] $step :: $dry_cmd" >> "$TARGET_LOG"
                echo "$TARGET|$step|Dry-Run|0" > "$STATUS_FILE"
                audit_proxy "$step" "DRY_RUN" "attempt=$attempt_no cmd_hash=$cmd_hash cmd=$dry_cmd"
                return 0
            fi

            local cooldown_sec="${GLOBAL_REQUEST_COOLDOWN_SEC:-$(policy_get global_request_cooldown_sec '0.2')}"
            if is_network_step "$step" && [[ -n "$cooldown_sec" ]] && [[ "$cooldown_sec" != "0" ]]; then
                sleep "$cooldown_sec" 2>/dev/null || true
            fi

            audit_proxy "$step" "EXEC_START" "attempt=$attempt_no cmd_hash=$cmd_hash cmd=$dry_cmd"

            if [[ "$OUTPUT_MODE" == "Verbose"* ]]; then
                log_msg ">" "\033[1;36m" "$TARGET_DISPLAY" "$step" "Running..."
                timeout $timeout_sec "${cmd[@]}" 2>&1 | tee -a "$TARGET_LOG" &
                cmd_pid=$!
            else
                log_msg ">" "\033[1;36m" "$TARGET_DISPLAY" "$step" "Running..."
                echo "[>] $TARGET_DISPLAY - $step" >> "$TARGET_LOG"
                timeout $timeout_sec "${cmd[@]}" >> "$TARGET_LOG" 2>&1 &
                cmd_pid=$!
            fi

            # Update status file dengan PID proses yang sedang berjalan
            echo "$TARGET|$step|Running|$cmd_pid" > "$STATUS_FILE"

            current_cmd_pid=$cmd_pid
            wait $cmd_pid 2>/dev/null
            exit_code=$?
            current_cmd_pid=""

            check_skip_request
            skip_rc=$?
            case "$skip_rc" in
                2) return 2 ;;
                10) return 0 ;;
            esac

            # --- DETEKSI WAF / BLOKIR ---
            # Jika tool seperti Katana, FFUF, atau Nuclei gagal/dihentikan paksa, kita ping ulang target.
            if [[ $exit_code -ne 0 ]] && [[ "$step" =~ (Katana|FFUF|Nuclei|SQLMap) ]]; then
                log_msg "i" "\033[1;33m" "$TARGET_DISPLAY" "PingCheck" "Tool $step gagal (kode $exit_code). Mengecek apakah server WAF/Host mati..."
                
                local host_is_dead=1
                
                if [[ "$USE_PROXY" == "true" ]] && [[ -n "$CURRENT_PROXY" ]]; then
                    # Tahap 1: Ping dengan proxy saat ini
                    if curl -x "$CURRENT_PROXY" -s -I -m 5 "http://$TARGET" >/dev/null || curl -x "$CURRENT_PROXY" -s -I -m 5 "https://$TARGET" >/dev/null; then
                        host_is_dead=0 # Host hidup lewat proxy
                    else
                        # Tahap 2: Ping tanpa proxy (Koneksi Langsung)
                        if curl -s -I -m 5 "http://$TARGET" >/dev/null || curl -s -I -m 5 "https://$TARGET" >/dev/null; then
                            log_msg "i" "\033[1;35m" "$TARGET_DISPLAY" "PingCheck" "Host merespon TANPA proxy! Ini berarti Proxy lama mati."
                            host_is_dead=0 # Host hidup
                            
                            rotate_proxy "$TARGET"
                            CURRENT_PROXY=$(get_proxy)
                            set_proxy_env "$CURRENT_PROXY"
                            TARGET_DISPLAY="$TARGET [$CURRENT_PROXY]"
                        else
                            # Tahap 3-6: Coba rotasi proxy lain (maksimal 4 percobaan tambahan)
                            log_msg "i" "\033[1;33m" "$TARGET_DISPLAY" "PingCheck" "Koneksi langsung & proxy lama diblokir. Mencoba proxy alternatif..."
                            local attempts=0
                            while [[ $attempts -lt 4 ]]; do
                                rotate_proxy "$TARGET"
                                local test_proxy=$(get_proxy)
                                
                                if [[ -z "$test_proxy" ]]; then
                                    log_msg "!" "\033[1;31m" "$TARGET_DISPLAY" "PingCheck" "Kehabisan proxy di pool."
                                    break
                                fi
                                
                                log_msg "i" "\033[1;36m" "$TARGET_DISPLAY" "PingCheck" "Tahap $((attempts+3))/6: Uji proxy $test_proxy..."
                                if curl -x "$test_proxy" -s -I -m 5 "http://$TARGET" >/dev/null || curl -x "$test_proxy" -s -I -m 5 "https://$TARGET" >/dev/null; then
                                    log_msg "✓" "\033[1;32m" "$TARGET_DISPLAY" "PingCheck" "Berhasil menembus WAF menggunakan proxy baru!"
                                    host_is_dead=0
                                    CURRENT_PROXY="$test_proxy"
                                    set_proxy_env "$CURRENT_PROXY"
                                    TARGET_DISPLAY="$TARGET [$CURRENT_PROXY]"
                                    break
                                fi
                                ((attempts++))
                            done
                        fi
                    fi
                else
                    # Mode tanpa proxy
                    if curl -s -I -m 5 "http://$TARGET" >/dev/null || curl -s -I -m 5 "https://$TARGET" >/dev/null; then
                        host_is_dead=0
                    fi
                fi

                if [[ $host_is_dead -eq 1 ]]; then
                    log_msg "!" "\033[1;31m" "$TARGET_DISPLAY" "PingCheck" "HOST MATI/TERBLOKIR WAF! Menghentikan semua pemindaian untuk domain ini."
                    echo "[$TARGET_DISPLAY] Dihentikan paksa. Host mati/terblokir WAF saat menjalankan $step." >> "$OUTPUT_BASE/failed_tasks.txt"
                    
                    # Tambahkan ke file skip agar proses selanjutnya tidak berjalan
                    append_skip_domain_once
                    return 2 # Keluar dari run_cmd dengan status error fatal
                else
                    log_msg "✓" "\033[1;32m" "$TARGET_DISPLAY" "PingCheck" "Host masih merespon. Melanjutkan proses/retry..."
                fi
            fi

            local end_time=$(date +%s)
            local duration=$((end_time - start_time))

            if [[ $exit_code -eq 0 ]]; then
                log_msg "✓" "\033[1;32m" "$TARGET_DISPLAY" "$step" "Completed (${duration}s)"
                if [[ "$USE_PROXY" == "true" && "$has_proxy_marker" == "true" ]]; then
                    audit_proxy "$step" "SUCCESS" "attempt=$attempt_no exit_code=0 duration=${duration}s cmd_hash=$cmd_hash"
                fi
                return 0
            elif [[ $exit_code -eq 2 ]]; then
                # Keluar total dari fungsi target jika diblokir
                audit_proxy "$step" "ABORTED" "attempt=$attempt_no exit_code=2 cmd_hash=$cmd_hash"
                return 2
            elif [[ $exit_code -eq 124 ]]; then
                log_msg "!" "\033[1;31m" "$TARGET_DISPLAY" "$step" "Unresponsive/Too long (${timeout_sec}s). Skipping."
                echo "[$TARGET_DISPLAY] $step - Skipped (Unresponsive/Timeout)" >> "$OUTPUT_BASE/failed_tasks.txt"
                audit_proxy "$step" "TIMEOUT" "attempt=$attempt_no exit_code=124 timeout=${timeout_sec}s cmd_hash=$cmd_hash"
                return 0
            elif [[ $exit_code -eq 137 || $exit_code -eq 139 ]]; then
                # 137 (SIGKILL) usually Out of Memory, 139 (SIGSEGV) usually Segmentation Fault
                log_msg "!" "\033[1;31m" "$TARGET_DISPLAY" "$step" "System Crash/OOM (exit $exit_code). Skipping to prevent freeze."
                echo "[$TARGET_DISPLAY] $step - Skipped (Crash/OOM - Exit $exit_code)" >> "$OUTPUT_BASE/failed_tasks.txt"
                audit_proxy "$step" "CRASH" "attempt=$attempt_no exit_code=$exit_code cmd_hash=$cmd_hash"
                return 0
            else
                log_msg "!" "\033[1;31m" "$TARGET_DISPLAY" "$step" "Failed (exit $exit_code, ${duration}s)"
                audit_proxy "$step" "FAILED" "attempt=$attempt_no exit_code=$exit_code duration=${duration}s cmd_hash=$cmd_hash"
                local prev_proxy="$CURRENT_PROXY"
                rotate_proxy "$TARGET"
                if [[ "$USE_PROXY" == "true" ]]; then
                    if [[ -n "$CURRENT_PROXY" && "$CURRENT_PROXY" != "$prev_proxy" ]]; then
                        audit_proxy "$step" "PROXY_ROTATED" "$prev_proxy -> $CURRENT_PROXY"
                    elif [[ -z "$CURRENT_PROXY" ]]; then
                        audit_proxy "$step" "PROXY_DEPLETED" "No proxy remaining after rotation attempt."
                    fi
                fi
                
                # Jika sebuah tool gagal lebih dari 1 kali secara beruntun, kemungkinan target sangat rentan terhadap beban tinggi.
                # Kita terapkan fallback "Safe Mode" dengan menambahkan delay antar request secara instan (mengedit args global)
                if [[ $retry_count -ge 1 ]]; then
                    log_msg "i" "\033[1;35m" "$TARGET_DISPLAY" "$step" "Anomaly detected. Applying Safe Mode (delay) for next retry..."
                    case "$step" in
                        "Nmap"*) NMAP_ARGS="$NMAP_ARGS --max-rate 5" ;;
                        "Nuclei"*) NUCLEI_RL="-rl 5 -c 2" ;;
                        "SQLMap"*) SQLMAP_RL="--delay 3 --threads 1" ;;
                        "Dalfox"*) DALFOX_RL="--delay 2000 --worker 5" ;;
                        "FFUF"*) FFUF_RL="-p 2 -t 5" ;;
                    esac
                fi
            fi

            case "$step" in
                Subfinder|httpx|GAU|Katana|ParamSpider|Arjun|SQLMap|Nikto|Wapiti|FFUF)
                    if ! check_internet; then
                        log_msg "!" "\033[1;33m" "$TARGET_DISPLAY" "Network" "No internet. Waiting..."
                        wait_for_internet
                    fi
                    ;;
            esac

            ((retry_count++))
            ((attempt_no++))
            start_time=$(date +%s)
        done

        log_msg "!" "\033[1;31m" "$TARGET_DISPLAY" "$step" "Skipped after $max_retries retries."
        echo "[$TARGET_DISPLAY] $step - Skipped after $max_retries retries (Exit Code: $exit_code)" >> "$OUTPUT_BASE/failed_tasks.txt"
        
        case "$step" in
            "ParamSpider") log_msg "i" "\033[1;33m" "$TARGET_DISPLAY" "$step" "Hint: May not support '-o' flag." ;;
            "SQLMap") log_msg "i" "\033[1;33m" "$TARGET_DISPLAY" "$step" "Hint: Unresponsive or no parameters." ;;
        esac
        if [[ "$OUTPUT_MODE" != "Verbose"* ]]; then
            log_msg "i" "\033[1;33m" "$TARGET_DISPLAY" "$step" "Error details:"
            # Prioritaskan menampilkan baris log yang mengandung pesan error
            if grep -qiE "error|fatal|timeout|failed|down|not found" "$TARGET_LOG" 2>/dev/null; then
                grep -iE "error|fatal|timeout|failed|down|not found" "$TARGET_LOG" 2>/dev/null | tail -n 5 | while read -r line; do 
                    log_msg "↳" "\033[1;33m" "$TARGET_DISPLAY" "$step" "$line"
                done || true
            else
                tail -n 5 "$TARGET_LOG" 2>/dev/null | while read -r line; do 
                    log_msg "↳" "\033[1;33m" "$TARGET_DISPLAY" "$step" "$line"
                done || true
            fi
        fi
        return 0
    }

    run_step() {
        run_cmd "$@"
        local rc=$?
        if [[ $rc -eq 2 ]]; then
            skip_domain_flag=1
            return 2
        fi
        return 0
    }

    # ==============================================================================
    # SET SPEED/RATE LIMIT ARGUMENTS BASED ON USER CHOICE
    # ==============================================================================
    build_baseline_profile() {
        [[ "${AI_ENABLE_BASELINE_PROFILE:-true}" == "true" ]] || return 0
        local out_file="$TARGET_DIR/recon/baseline_profile.tsv"
        local max_urls="${AI_MAX_BASELINE_URLS:-8}"
        local source_file="$TARGET_DIR/recon/alive.txt"
        [[ -s "$source_file" ]] || return 0
        : > "$out_file"
        printf "url\tstatus\tserver\tcontent_type\tbody_sha256\n" >> "$out_file"
        head -n "$max_urls" "$source_file" | while IFS= read -r u; do
            [[ "$u" =~ ^https?:// ]] || continue
            local hdr tmp status server ctype bodyhash
            hdr="$(mktemp)"
            tmp="$(mktemp)"
            curl -sS -L -m 15 -D "$hdr" -o "$tmp" "$u" >/dev/null 2>&1 || true
            status="$(awk 'toupper($1) ~ /^HTTP/ {code=$2} END{print code}' "$hdr")"
            server="$(awk 'BEGIN{IGNORECASE=1} /^server:/ {sub(/\r$/,"",$0); sub(/^server:[[:space:]]*/,"",$0); print; exit}' "$hdr")"
            ctype="$(awk 'BEGIN{IGNORECASE=1} /^content-type:/ {sub(/\r$/,"",$0); sub(/^content-type:[[:space:]]*/,"",$0); print; exit}' "$hdr")"
            if command -v sha256sum >/dev/null 2>&1; then
                bodyhash="$(sha256sum "$tmp" | awk '{print $1}')"
            else
                bodyhash="$(md5sum "$tmp" | awk '{print $1}')"
            fi
            printf "%s\t%s\t%s\t%s\t%s\n" "$u" "${status:-NA}" "${server:-NA}" "${ctype:-NA}" "${bodyhash:-NA}" >> "$out_file"
            rm -f "$hdr" "$tmp"
        done
        log_msg "i" "\033[1;36m" "$TARGET" "Baseline" "Baseline profile tersimpan: recon/baseline_profile.tsv"
    }

    local NUCLEI_RL=""
    local FFUF_RL=""
    local SQLMAP_RL=""
    local DALFOX_RL=""
    
    if [[ "$SCAN_SPEED" == "Stealth"* ]]; then
        NUCLEI_RL="-rl 10 -c 5 -bs 5"
        FFUF_RL="-p 1.5 -t 10"
        SQLMAP_RL="--delay 2 --threads 1"
        DALFOX_RL="--delay 1500 --worker 10"
        log_msg "i" "\033[1;35m" "$TARGET" "Speed" "Stealth mode active. Limiting request rates."
    elif [[ "$SCAN_SPEED" == "Normal"* ]]; then
        NUCLEI_RL="-rl 150 -c 30"
        FFUF_RL="-p 0.1 -t 40"
        SQLMAP_RL="--delay 0.5 --threads 3"
        DALFOX_RL="--delay 200 --worker 40"
    else
        # Insane (Default / Max Speed)
        NUCLEI_RL="-rl 500 -c 100"
        FFUF_RL="-t 100"
        SQLMAP_RL="--threads 10"
        DALFOX_RL="--worker 200"
    fi
    if [[ "${AI_AGGRESSIVE_MODE:-false}" == "true" || "${AI_AGGRESSIVE_MODE:-false}" == "1" ]]; then
        # Mode agresif untuk validasi lebih dalam (tetap non-destruktif).
        NUCLEI_RL="-rl 700 -c 140"
        FFUF_RL="-t 140 -mc 200,204,301,302,307,401,403"
        SQLMAP_RL="--threads 10 --delay 0"
        DALFOX_RL="--worker 260 --delay 50"
        log_msg "AI" "\033[1;35m" "$TARGET" "AGGRESSIVE" "Aggressive mode aktif: depth/rate verifikasi dinaikkan."
    fi

    # ========== PHASE 1: RECONNAISSANCE ==========
    # Subfinder hanya dieksekusi jika alat tersebut ada di SELECTED_TOOLS (sudah difilter di prompts.sh)
    if tool_enabled "subfinder"; then
        run_step "Subfinder" subfinder -d "$TARGET" -silent __PROXY__ -o "$TARGET_DIR/recon/subfinder.txt" || { abort_target_scan; return 0; }
    fi

    # WAFW00F (WAF Detector)
    local AI_WAF_BYPASS_HEADERS=""
    if tool_enabled "wafw00f"; then
        # Menggunakan bash -c dan tee untuk menghindari bug upstream wafw00f (crash saat host down dengan flag -o)
        run_step "Wafw00f" bash -c "wafw00f '$TARGET' | tee '$TARGET_DIR/recon/waf.txt'" || { abort_target_scan; return 0; }
        
        # FITUR BARU: AI WAF Bypass Suggester
        if [[ "$AI_PLANNER_ENABLED" -eq 1 ]] && [[ -f "$TARGET_DIR/recon/waf.txt" ]]; then
            local waf_result
            waf_result=$(grep -iE "is behind|No WAF detected" "$TARGET_DIR/recon/waf.txt" || true)
            if [[ -n "$waf_result" ]] && [[ ! "$waf_result" =~ "No WAF detected" ]]; then
                log_msg "AI" "\033[1;35m" "$TARGET" "WAF_ANALYST" "Menganalisis jenis WAF untuk mencari teknik bypass..."
                local waf_prompt
                waf_prompt=$(cat <<EOF
Kamu adalah Senior Web Security Expert.
Target dilindungi oleh Web Application Firewall (WAF) dengan deteksi berikut:
$waf_result

Tugasmu: Berikan saran HTTP Headers khusus (seperti X-Forwarded-For, X-Originating-IP) yang bisa digunakan untuk mem-bypass atau mengelabui WAF ini.

Kembalikan HANYA JSON valid:
{
  "recommended_headers": ["X-Forwarded-For: 127.0.0.1", "Client-IP: 127.0.0.1"],
  "reasoning": "Alasan singkat mengapa header ini mungkin bekerja"
}

Aturan:
- Untuk model reasoning, silakan berpikir di dalam <think>...</think>, lalu berikan JSON.
- Jika WAF ini tidak bisa di-bypass menggunakan header sederhana, kembalikan array kosong.
EOF
)
                local waf_payload
                waf_payload="$(jq -n --arg model "${OLLAMA_MODEL:-deepseek-r1:8b}" --arg prompt "$waf_prompt" '{model:$model,prompt:$prompt,stream:false}')"
                local waf_resp
                waf_resp="$(ollama_curl -fsS -m "${AI_HTTP_TIMEOUT:-30}" -X POST "${OLLAMA_GENERATE_API:-${OLLAMA_HOST%/}/api/generate}" -H "Content-Type: application/json" -d "$waf_payload" || true)"
                
                local waf_json
                waf_json="$(echo "$waf_resp" | jq -r '.response // empty' 2>/dev/null || true)"
                waf_json="$(clean_json_response "$waf_json")"
                
                if [[ -n "$waf_json" ]] && echo "$waf_json" | jq -e . >/dev/null 2>&1; then
                    local headers_array
                    headers_array=$(echo "$waf_json" | jq -r '.recommended_headers[]?')
                    if [[ -n "$headers_array" ]]; then
                        log_msg "AI" "\033[1;32m" "$TARGET" "WAF_ANALYST" "AI menyarankan $(echo "$headers_array" | wc -l) header bypass."
                        # Simpan headers ke file dan ke variable
                        echo "$headers_array" > "$TARGET_DIR/recon/ai_waf_headers.txt"
                        while IFS= read -r h; do
                            AI_WAF_BYPASS_HEADERS="$AI_WAF_BYPASS_HEADERS -H \"$h\""
                        done <<< "$headers_array"
                    fi
                fi
            fi
        fi
    fi

    if [[ "$FULL_AUTO_MODE" != "true" ]] && tool_enabled "httpx"; then
        if [[ -s "$TARGET_DIR/recon/subfinder.txt" ]]; then
            HOSTS_FILE="$TARGET_DIR/recon/subfinder.txt"
        else
            echo "$TARGET" > "$TARGET_DIR/recon/temp_host.txt"
            HOSTS_FILE="$TARGET_DIR/recon/temp_host.txt"
        fi
        run_step "httpx" httpx -l "$HOSTS_FILE" -silent -td -title -status-code -ip __PROXY__ -o "$TARGET_DIR/recon/alive.txt" || { abort_target_scan; return 0; }
    else
        echo "$TARGET" > "$TARGET_DIR/recon/alive.txt"
    fi
    build_baseline_profile

    if tool_enabled "nmap"; then
        IFS=' ' read -ra nmap_args <<< "$NMAP_ARGS"
        local nmap_target=""
        if [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
            # Menggunakan awk untuk hanya mengambil URL murni, membuang status code [302] dan tech stack yang menempel
            awk '{print $1}' "$TARGET_DIR/recon/alive.txt" | sed -e 's#^http://##' -e 's#^https://##' -e 's#/.*##' | sort -u > "$TARGET_DIR/recon/hosts_nmap.txt"
            nmap_target="-iL $TARGET_DIR/recon/hosts_nmap.txt"
        else
            nmap_target="$TARGET"
        fi
        
        run_step "Nmap" nmap $nmap_target "${nmap_args[@]}" -oA "$TARGET_DIR/scans/nmap" || { abort_target_scan; return 0; }
        
        # Cek jika nmap gagal menemukan host up (biasanya karena block ICMP)
        if grep -q "0 hosts up" "$TARGET_DIR/scans/nmap.nmap" 2>/dev/null; then
            log_msg "i" "\033[1;33m" "$TARGET" "Nmap" "0 hosts up detected. Retrying with -Pn (No Ping)..."
            run_step "Nmap (Fallback -Pn)" nmap $nmap_target -Pn "${nmap_args[@]}" -oA "$TARGET_DIR/scans/nmap_pn" || { abort_target_scan; return 0; }
        fi
    fi

    if tool_enabled "gau"; then
        run_step "GAU" gau "$TARGET" --subs --o "$TARGET_DIR/recon/gau_urls.txt" || { abort_target_scan; return 0; }
    fi

    if tool_enabled "katana" && [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
        run_step "Katana" katana -u "$TARGET_DIR/recon/alive.txt" -silent -jc -kf all __PROXY__ -o "$TARGET_DIR/recon/katana_urls.txt" || { abort_target_scan; return 0; }
    fi

    # Gabungkan URL dari gau dan katana
    cat "$TARGET_DIR/recon"/{gau_urls,katana_urls}.txt 2>/dev/null | sort -u > "$TARGET_DIR/recon/all_urls_raw.txt" 2>/dev/null || true

    # MODIFIKASI 1: Filter URL dengan httpx (hanya yang status 200)
    if [[ -s "$TARGET_DIR/recon/all_urls_raw.txt" ]]; then
        run_step "Probe URLs (filter 200)" httpx -l "$TARGET_DIR/recon/all_urls_raw.txt" -silent -status-code -mc 200 __PROXY__ -o "$TARGET_DIR/recon/all_urls_200.txt" || { abort_target_scan; return 0; }
        if [[ -s "$TARGET_DIR/recon/all_urls_200.txt" ]]; then
            # Hanya simpan URL tanpa status code (jika httpx menambahkannya)
            sed -E 's/\s+\[[0-9]+\]$//' "$TARGET_DIR/recon/all_urls_200.txt" > "$TARGET_DIR/recon/all_urls.txt"
            log_msg "i" "\033[1;36m" "$TARGET" "Filter" "$(wc -l < "$TARGET_DIR/recon/all_urls.txt") URLs with status 200 retained."
            
            # FITUR BARU: AI JS Endpoint Extractor
            if [[ "$AI_PLANNER_ENABLED" -eq 1 ]] && grep -qi '\.js$' "$TARGET_DIR/recon/all_urls.txt"; then
                log_msg "AI" "\033[1;35m" "$TARGET" "JS_ANALYST" "Mengekstrak file JavaScript untuk mencari API tersembunyi..."
                local js_files="$TARGET_DIR/recon/js_files.txt"
                grep -i '\.js$' "$TARGET_DIR/recon/all_urls.txt" | head -n 3 > "$js_files" || true
                
                if [[ -s "$js_files" ]]; then
                    > "$TARGET_DIR/recon/ai_js_endpoints.txt"
                    while IFS= read -r js_url; do
                        log_msg "i" "\033[1;34m" "$TARGET" "JS_ANALYST" "Menganalisis $js_url"
                        local js_content
                        js_content=$(curl -sL -m 10 "$js_url" | head -c 5000 || true)
                        
                        if [[ -n "$js_content" ]]; then
                            local js_prompt
                            js_prompt=$(cat <<EOF
Kamu adalah AI Source Code Analyst.
Tugasmu: Temukan Endpoint API tersembunyi, path direktori rahasia, atau parameter sensitif dari potongan file JavaScript berikut.

[JavaScript Code]
$js_content

Kembalikan HANYA JSON valid:
{
  "found_endpoints": ["/api/v1/users", "/admin/dashboard"],
  "found_parameters": ["token", "secret_key"]
}

Aturan:
- Untuk model reasoning, silakan berpikir di dalam <think>...</think>, lalu berikan JSON.
- Jika tidak ada temuan, kosongkan array.
EOF
)
                            local js_payload
                            js_payload="$(jq -n --arg model "${OLLAMA_MODEL:-deepseek-r1:8b}" --arg prompt "$js_prompt" '{model:$model,prompt:$prompt,stream:false}')"
                            local js_resp
                            js_resp="$(ollama_curl -fsS -m "${AI_HTTP_TIMEOUT:-30}" -X POST "${OLLAMA_GENERATE_API:-${OLLAMA_HOST%/}/api/generate}" -H "Content-Type: application/json" -d "$js_payload" || true)"
                            
                            local js_json
                            js_json="$(echo "$js_resp" | jq -r '.response // empty' 2>/dev/null || true)"
                            js_json="$(clean_json_response "$js_json")"
                            
                            if [[ -n "$js_json" ]] && echo "$js_json" | jq -e . >/dev/null 2>&1; then
                                echo "$js_json" | jq -r '.found_endpoints[]?' >> "$TARGET_DIR/recon/ai_js_endpoints.txt"
                                echo "$js_json" | jq -r '.found_parameters[]?' >> "$TARGET_DIR/recon/ai_js_parameters.txt"
                            fi
                        fi
                    done < "$js_files"
                    
                    # Tambahkan endpoint yang ditemukan ke all_urls
                    if [[ -s "$TARGET_DIR/recon/ai_js_endpoints.txt" ]]; then
                        local found_js_ep
                        found_js_ep=$(wc -l < "$TARGET_DIR/recon/ai_js_endpoints.txt")
                        log_msg "AI" "\033[1;32m" "$TARGET" "JS_ANALYST" "Menemukan $found_js_ep endpoint API rahasia dari JS!"
                        
                        # Bentuk URL lengkap dari endpoint (asumsi relative path)
                        local base_url
                        base_url=$(echo "$TARGET" | sed -e 's|https*://||' -e 's|/.*||')
                        awk -v base="http://$base_url" '{print base $0}' "$TARGET_DIR/recon/ai_js_endpoints.txt" >> "$TARGET_DIR/recon/all_urls.txt"
                        sort -u -o "$TARGET_DIR/recon/all_urls.txt" "$TARGET_DIR/recon/all_urls.txt"
                    fi
                fi
            fi
            
        else
            > "$TARGET_DIR/recon/all_urls.txt"
            log_msg "!" "\033[1;33m" "$TARGET" "Filter" "No URL with status 200 found. Skipping further URL-based tests."
        fi
        # Buat juga file auditable URLs (dengan parameter) untuk referensi manual
        grep -E '(\?|=)' "$TARGET_DIR/recon/all_urls.txt" 2>/dev/null > "$TARGET_DIR/recon/auditable_urls.txt" || true
    else
        > "$TARGET_DIR/recon/all_urls.txt"
    fi

    # Jalankan putaran kedua saat URL recon sudah lebih kaya.
    start_ai_discovery_async "post-recon"

    if tool_enabled "paramspider"; then
        run_step "ParamSpider" bash -c "
            cd '$TARGET_DIR/recon' || exit 1
            paramspider -d '$TARGET' --quiet 2>/dev/null
            if [[ -f 'results/$TARGET.txt' ]]; then
                mv 'results/$TARGET.txt' paramspider.txt
                rm -rf results
            elif [[ -f 'results/${TARGET}.txt' ]]; then
                mv 'results/${TARGET}.txt' paramspider.txt
                rm -rf results
            fi
        " || { abort_target_scan; return 0; }
        if [[ -s "$TARGET_DIR/recon/paramspider.txt" ]]; then
            grep -oP '[\?&]\K[^=&\s]+' "$TARGET_DIR/recon/paramspider.txt" | sort -u > "$TARGET_DIR/recon/params_wordlist.txt" || true
        else
            log_msg "!" "\033[1;33m" "$TARGET" "ParamSpider" "ParamSpider produced no output."
        fi
    fi

    if tool_enabled "arjun" && [[ -s "$TARGET_DIR/recon/all_urls.txt" ]]; then
        head -n 50 "$TARGET_DIR/recon/all_urls.txt" | run_step "Arjun" arjun -i /dev/stdin -oT "$TARGET_DIR/recon/params.txt" -q || { abort_target_scan; return 0; }
    fi

    # Menambahkan FFUF untuk Directory & File Discovery
    if tool_enabled "ffuf" && [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
        # Menggunakan file dictionary ringan yang umum dipakai (jika belum ada, download otomatis)
        local wordlist="$HOME/tools/wordlists/common.txt"
        if [[ ! -f "$wordlist" ]]; then
            mkdir -p "$HOME/tools/wordlists"
            curl -sL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" -o "$wordlist" > /dev/null 2>&1 || true
        fi
        
        if [[ -f "$wordlist" ]]; then
            IFS=' ' read -ra ffuf_rl_arr <<< "$FFUF_RL"
            while IFS= read -r host; do
                [[ "$host" =~ ^https?:// ]] || continue
                safe_host=$(echo "$host" | md5sum | cut -d' ' -f1)
                # Mencari status 200, 301 untuk endpoint rahasia/admin
                run_step "FFUF ($host)" ffuf -u "$host/FUZZ" -w "$wordlist" "${ffuf_rl_arr[@]}" -mc 200,204,301,302,307,401 -s __PROXY__ -o "$TARGET_DIR/recon/ffuf_${safe_host}.json" || { abort_target_scan; return 0; }
            done < "$TARGET_DIR/recon/alive.txt"
        else
            log_msg "!" "\033[1;31m" "$TARGET" "FFUF" "Wordlist not found. Skipping FFUF."
        fi
    fi

    # ==============================================================================
    # PREPARE URLS FOR INJECTION (Extract URLs with parameters)
    # ==============================================================================
    if [[ -s "$TARGET_DIR/recon/all_urls.txt" ]]; then
        grep -E '(\?|=)' "$TARGET_DIR/recon/all_urls.txt" | grep -viE '\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip|tar|gz|mp4|mp3|webm)(\?|$)' > "$TARGET_DIR/recon/urls_with_params.txt" || true
    else
        > "$TARGET_DIR/recon/urls_with_params.txt"
    fi

    # Re-planning setelah recon agar fase vulnerability lebih kontekstual.
    ai_replan_after_recon

    # ========== PHASE 2: VULNERABILITY SCANNING ==========
    if tool_enabled "nuclei" && [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
        IFS=' ' read -ra nuclei_rl_arr <<< "$NUCLEI_RL"
        run_step "Nuclei" nuclei -l "$TARGET_DIR/recon/alive.txt" -silent "${nuclei_rl_arr[@]}" __PROXY__ -o "$TARGET_DIR/vulnerabilities/nuclei.txt" || { abort_target_scan; return 0; }
    fi

    # Dalfox hanya jika ada URL valid dengan parameter
    if tool_enabled "dalfox" && [[ -s "$TARGET_DIR/recon/urls_with_params.txt" ]]; then
        # Filter static files for Dalfox as well
        grep -ivE '\.(js|css|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|pdf|zip|tar|gz|rar|mp4|mp3|avi|wmv)\?.*=' "$TARGET_DIR/recon/urls_with_params.txt" > "$TARGET_DIR/recon/urls_for_dalfox.txt" || true
        
        if [[ -s "$TARGET_DIR/recon/urls_for_dalfox.txt" ]]; then
            IFS=' ' read -ra dalfox_rl_arr <<< "$DALFOX_RL"
            run_step "Dalfox" dalfox file "$TARGET_DIR/recon/urls_for_dalfox.txt" --silence "${dalfox_rl_arr[@]}" __PROXY__ --output "$TARGET_DIR/vulnerabilities/xss.txt" || { abort_target_scan; return 0; }
        else
            log_msg "i" "\033[1;33m" "$TARGET" "Dalfox" "All parameterized URLs were static assets (.js, .css, etc). Skipping Dalfox."
        fi
    fi

    if tool_enabled "wapiti" && [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
        while IFS= read -r host; do
            [[ "$host" =~ ^https?:// ]] || continue
            safe_host=$(echo "$host" | md5sum | cut -d' ' -f1)
            # Wapiti checks for multiple vulns (SQLi, XSS, File Inclusion, SSRF, CRLF, XXE)
            run_step "Wapiti ($host)" wapiti -u "$host" --flush-session -m "sql,xss,file,xxe,ssrf,crlf" -f txt -o "$TARGET_DIR/vulnerabilities/wapiti_${safe_host}.txt" || { abort_target_scan; return 0; }
        done < "$TARGET_DIR/recon/alive.txt"
    fi

    # MODIFIKASI 3: SQLMap dengan argumen kustom dan hanya URL valid dengan parameter
    if tool_enabled "sqlmap" && [[ -s "$TARGET_DIR/recon/urls_with_params.txt" ]]; then
        # Filter out static extensions (.js, .css, .png, .jpg, etc) before passing to SQLMap
        grep -ivE '\.(js|css|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|pdf|zip|tar|gz|rar|mp4|mp3|avi|wmv)\?.*=' "$TARGET_DIR/recon/urls_with_params.txt" > "$TARGET_DIR/recon/urls_for_sqlmap.txt" || true
        
        if [[ -s "$TARGET_DIR/recon/urls_for_sqlmap.txt" ]]; then
            IFS=' ' read -ra sqlmap_args <<< "$SQLMAP_ARGS"
            IFS=' ' read -ra sqlmap_rl_arr <<< "$SQLMAP_RL"
            # Cek apakah pengguna menggunakan -u (single URL) dalam argumen
            if [[ "${sqlmap_args[*]}" == *"-u"* ]]; then
                # Mode satu per satu URL
                while IFS= read -r url; do
                    run_step "SQLMap ($url)" sqlmap -u "$url" "${sqlmap_args[@]}" "${sqlmap_rl_arr[@]}" __PROXY__ --output-dir="$TARGET_DIR/vulnerabilities/sqlmap" || { abort_target_scan; return 0; }
                done < "$TARGET_DIR/recon/urls_for_sqlmap.txt"
            else
                # Mode batch dengan file (-m)
                run_step "SQLMap" sqlmap -m "$TARGET_DIR/recon/urls_for_sqlmap.txt" "${sqlmap_args[@]}" "${sqlmap_rl_arr[@]}" __PROXY__ --output-dir="$TARGET_DIR/vulnerabilities/sqlmap" || { abort_target_scan; return 0; }
            fi
        else
            log_msg "i" "\033[1;33m" "$TARGET" "SQLMap" "All parameterized URLs were static assets (.js, .css, etc). Skipping SQLMap."
        fi
    fi

    # Planner fase-3: setelah vulnerability scan, AI menyusun attack graph prioritas.
    build_ai_attack_graph

    # ========== PHASE 3: FINAL (NIKTO) ==========
    if tool_enabled "nikto" && [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
        while IFS= read -r host; do
            [[ "$host" =~ ^https?:// ]] || continue
            run_step "Nikto ($host)" nikto -h "$host" -output "$TARGET_DIR/scans/nikto_$(echo "$host" | md5sum | cut -d' ' -f1).txt" || { abort_target_scan; return 0; }
        done < "$TARGET_DIR/recon/alive.txt"
    fi

    if [[ -n "$AI_DISCOVERY_PID" ]] && kill -0 "$AI_DISCOVERY_PID" 2>/dev/null; then
        log_msg "AI" "\033[1;35m" "$TARGET" "ORCHESTRATOR" "Menunggu dorking background selesai..."
        wait "$AI_DISCOVERY_PID" 2>/dev/null || true
        AI_DISCOVERY_PID=""
    fi

    # Done with this target
    local TARGET_INDEX_FILE="$TARGET_DIR/README_TARGET.txt"
    {
        echo "TARGET RESULT NAVIGATOR"
        echo "======================="
        echo "Target          : $TARGET"
        echo "Generated       : $(date)"
        echo "Root Folder     : $TARGET_DIR"
        echo ""
        echo "[Recon]"
        [[ -f "$TARGET_DIR/recon/subfinder.txt" ]] && echo "- Subdomains         : recon/subfinder.txt"
        [[ -f "$TARGET_DIR/recon/alive.txt" ]] && echo "- Alive Hosts        : recon/alive.txt"
        [[ -f "$TARGET_DIR/recon/waf.txt" ]] && echo "- WAF Fingerprint    : recon/waf.txt"
        [[ -f "$TARGET_DIR/recon/gau_urls.txt" ]] && echo "- GAU URLs           : recon/gau_urls.txt"
        [[ -f "$TARGET_DIR/recon/katana_urls.txt" ]] && echo "- Katana URLs        : recon/katana_urls.txt"
        [[ -f "$TARGET_DIR/recon/all_urls.txt" ]] && echo "- Merged URLs        : recon/all_urls.txt"
        [[ -f "$TARGET_DIR/recon/urls_with_params.txt" ]] && echo "- URLs With Params   : recon/urls_with_params.txt"
        [[ -f "$TARGET_DIR/recon/params.txt" ]] && echo "- Arjun Params       : recon/params.txt"
        [[ -f "$TARGET_DIR/recon/params_wordlist.txt" ]] && echo "- Param Wordlist     : recon/params_wordlist.txt"
        if compgen -G "$TARGET_DIR/recon/ffuf_*.json" > /dev/null; then
            ffuf_count=$(find "$TARGET_DIR/recon" -maxdepth 1 -name 'ffuf_*.json' | wc -l | tr -d ' ')
            echo "- FFUF Results       : recon/ffuf_*.json (${ffuf_count} file)"
        fi
        echo ""
        echo "[Vulnerabilities]"
        [[ -f "$TARGET_DIR/vulnerabilities/nuclei.txt" ]] && echo "- Nuclei             : vulnerabilities/nuclei.txt"
        [[ -f "$TARGET_DIR/vulnerabilities/xss.txt" ]] && echo "- Dalfox XSS         : vulnerabilities/xss.txt"
        if compgen -G "$TARGET_DIR/vulnerabilities/wapiti_*.txt" > /dev/null; then
            wapiti_count=$(find "$TARGET_DIR/vulnerabilities" -maxdepth 1 -name 'wapiti_*.txt' | wc -l | tr -d ' ')
            echo "- Wapiti             : vulnerabilities/wapiti_*.txt (${wapiti_count} file)"
        fi
        if [[ -d "$TARGET_DIR/vulnerabilities/sqlmap" ]]; then
            echo "- SQLMap Output Dir  : vulnerabilities/sqlmap/"
        fi
        [[ -f "$TARGET_DIR/vulnerabilities/ai_attack_graph.json" ]] && echo "- AI Attack Graph    : vulnerabilities/ai_attack_graph.json"
        [[ -f "$TARGET_DIR/vulnerabilities/ai_attack_graph.txt" ]] && echo "- AI Attack Notes    : vulnerabilities/ai_attack_graph.txt"
        [[ -f "$TARGET_DIR/vulnerabilities/ai_recommendation.txt" ]] && echo "- AI Recommendation  : vulnerabilities/ai_recommendation.txt"
        [[ -f "$TARGET_DIR/proxy_report.txt" ]] && echo "- Proxy Audit        : proxy_report.txt"
        echo ""
        echo "[Network Scans]"
        [[ -f "$TARGET_DIR/scans/nmap.nmap" ]] && echo "- Nmap Normal        : scans/nmap.nmap"
        [[ -f "$TARGET_DIR/scans/nmap.xml" ]] && echo "- Nmap XML           : scans/nmap.xml"
        [[ -f "$TARGET_DIR/scans/nmap_pn.nmap" ]] && echo "- Nmap Fallback -Pn  : scans/nmap_pn.nmap"
        if compgen -G "$TARGET_DIR/scans/nikto_*.txt" > /dev/null; then
            nikto_count=$(find "$TARGET_DIR/scans" -maxdepth 1 -name 'nikto_*.txt' | wc -l | tr -d ' ')
            echo "- Nikto              : scans/nikto_*.txt (${nikto_count} file)"
        fi
        echo ""
        echo "[Logs]"
        echo "- Target Scan Log    : scan.log"
    } > "$TARGET_INDEX_FILE"

    echo "$TARGET" >> "$COMPLETED_FILE"
    {
        echo "------------------------------------------------------------"
        echo "Done: $(date)"
    } >> "$PROXY_AUDIT_FILE"
    echo -e "\n=== Scan finished for: $TARGET ===" >> "$TARGET_LOG"
    cleanup_target_state
}
export -f process_target

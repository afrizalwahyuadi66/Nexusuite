# ==============================================================================
# AI Advanced Helpers (scope guard, snapshots, policy-backed controls)
# ==============================================================================

AI_TOOL_DIR_ADV="$(dirname "$(dirname "$BASH_SOURCE")")/ai_rag_tool"
if [[ -f "$AI_TOOL_DIR_ADV/ai_config.sh" ]]; then
    # shellcheck disable=SC1090
    source "$AI_TOOL_DIR_ADV/ai_config.sh"
fi

scope_guard_target() {
    local target="$1"
    local allow_private allow_local
    allow_private="$(policy_get scope_allow_private_ranges 'false')"
    allow_local="$(policy_get scope_allow_localhost 'false')"

    if declare -F target_blocked_by_scope_policy >/dev/null 2>&1; then
        if target_blocked_by_scope_policy "$target"; then
            log_msg "!" "\033[1;31m" "$target" "ScopeGuard" "Target diblokir oleh scope_blocklist/suffix policy."
            return 1
        fi
    fi

    if ! target_in_allowlist "$target"; then
        log_msg "!" "\033[1;31m" "$target" "ScopeGuard" "Target di luar allowlist policy."
        return 1
    fi

    if target_is_private_or_local "$target"; then
        if [[ "$target" == "localhost" || "$target" == "127.0.0.1" || "$target" == "::1" || "$target" == *"localhost"* ]]; then
            [[ "$allow_local" == "true" || "$allow_local" == "1" ]] || {
                log_msg "!" "\033[1;31m" "$target" "ScopeGuard" "Localhost diblokir policy."
                return 1
            }
        else
            [[ "$allow_private" == "true" || "$allow_private" == "1" ]] || {
                log_msg "!" "\033[1;31m" "$target" "ScopeGuard" "Private IP range diblokir policy."
                return 1
            }
        fi
    fi
    return 0
}

# --- AI Query Helper ---
ai_query() {
    local prompt="$1"
    local system_context="${2:-"Kamu adalah expert cybersecurity assistant."}"
    local output_file="${3:-}"
    local timeout="${AI_HTTP_TIMEOUT:-300}"
    
    # Validasi jq
    if ! command -v jq >/dev/null 2>&1; then
        echo '{"error": "jq not found"}'
        return 1
    fi

    local payload
    payload=$(jq -n \
        --arg model "${OLLAMA_MODEL:-deepseek-r1:8b}" \
        --arg system "$system_context" \
        --arg prompt "$prompt" \
        '{model: $model, system: $system, prompt: $prompt, stream: false}')
    
    local response
    response=$(ollama_curl -fsS -m "$timeout" -X POST \
        "${OLLAMA_GENERATE_API:-${OLLAMA_HOST%/}/api/generate}" \
        -H "Content-Type: application/json" -d "$payload" 2>/dev/null || echo '{"error": "connection failed"}')
    
    local raw_text
    raw_text=$(echo "$response" | jq -r '.response // empty' 2>/dev/null || true)
    
    local clean_resp
    if [[ -n "$raw_text" ]]; then
        clean_resp=$(echo "$raw_text" | clean_json_response)
    else
        clean_resp=""
    fi
    
    if [[ -n "$output_file" ]]; then
        echo "$clean_resp" > "$output_file"
    fi
    echo "$clean_resp"
}
export -f ai_query

# --- AI Pipeline Orchestrator (v4.1) ---
# Mengelola siklus hidup 6-tahap: Recon > Vuln > Exploit > Payload > Proof > Report
ai_orchestrate_pipeline() {
    local target="$1"
    local job_id="$2"
    local target_dir="$3"
    
    log_msg "AI" "\033[1;35m" "$target" "PIPELINE" "Entering Nexusuite Standard Offensive Pipeline (Autonomous)..."
    
    # Inisialisasi State di Database via Python Engine
    local _v4_api_url="${V4_API_URL:-http://localhost:8000}"
    
    # 1. Panggil Advanced AI Engine untuk mulai berpikir
    log_msg "AI" "\033[1;35m" "$target" "THINK" "AI is planning the offensive strategy..."
    
    # Integrasi dengan Python Engine nx_ai_engine.py
    # Kita menggunakan API POST /api/v1/scan yang sudah kita update sebelumnya
    local _payload
    _payload=$(jq -n \
        --arg url "$target" \
        --arg mode "nx_advanced" \
        --arg job_id "$job_id" \
        '{url: $url, ai_mode: $mode, job_id: $job_id, force_enum: true}')
        
    local _response
    _response=$(curl -s -X POST "$_v4_api_url/api/v1/scan" \
         -H "Content-Type: application/json" \
         -H "X-API-Key: admin-secret-key" \
         -d "$_payload")
         
    if [[ "$_response" == *"id"* ]]; then
        local _new_job_id
        _new_job_id=$(echo "$_response" | jq -r '.id')
        log_msg "✓" "\033[1;32m" "$target" "PIPELINE" "AI Engine active. Mission ID: $_new_job_id"
        
        # Monitor progress secara otonom
        local _status="running"
        local _last_log_idx=0
        while [[ "$_status" == "running" ]]; do
            sleep 5
            local _job_data
            _job_data=$(curl -s "$_v4_api_url/api/v1/scan/$_new_job_id")
            _status=$(echo "$_job_data" | jq -r '.status' 2>/dev/null || echo "running")
            
            # Ambil semua log baru sejak pengecekan terakhir
            local _current_logs
            _current_logs=$(echo "$_job_data" | jq -c '.logs' 2>/dev/null)
            
            if [[ -n "$_current_logs" && "$_current_logs" != "null" ]]; then
                local _num_logs
                _num_logs=$(echo "$_current_logs" | jq 'length')
                
                while [[ $_last_log_idx -lt $_num_logs ]]; do
                    local _log_line
                    _log_line=$(echo "$_current_logs" | jq -r ".[$_last_log_idx]")
                    
                    if [[ "$_log_line" == "➔ [SENT TO AI]"* ]]; then
                        log_msg "📤" "\033[1;33m" "$target" "AI_INPUT" "$_log_line"
                    elif [[ "$_log_line" == "🤖 [AI RESPONSE]"* ]]; then
                        log_msg "📥" "\033[1;32m" "$target" "AI_PLAN" "$_log_line"
                    else
                        log_msg "🤖" "\033[1;34m" "$target" "AI_EXEC" "$_log_line"
                    fi
                    
                    ((_last_log_idx++))
                done
            fi
        done
        
        log_msg "🏁" "\033[1;32m" "$target" "PIPELINE" "Autonomous Mission Completed. Check Web Dashboard (Port 8000)."
    else
        log_msg "!" "\033[1;31m" "$target" "PIPELINE" "Failed to handoff mission to AI Engine. Reverting to local Shell logic."
        return 1
    fi
}
export -f ai_orchestrate_pipeline

write_state_snapshot() {
    local snapshot_file="$OUTPUT_BASE/.state_snapshot.json"
    local selected_tools="${SELECTED_TOOLS:-}"
    local targets_count=0
    [[ -f "${TARGETS_FILE:-}" ]] && targets_count="$(wc -l < "$TARGETS_FILE" | tr -d ' ')"

    if command -v jq >/dev/null 2>&1; then
        # Ensure targets_count is a valid number
        targets_count="${targets_count:-0}"
        targets_count="${targets_count//[^0-9]/}"
        [[ -z "$targets_count" ]] && targets_count=0
        
        jq -n \
          --arg ts "$(date -Iseconds)" \
          --arg output_base "${OUTPUT_BASE:-}" \
          --arg mode "${MODE:-unknown}" \
          --arg workflow "${WORKFLOW:-unknown}" \
          --arg ai_orchestrator "${AI_ORCHESTRATOR_MODE:-false}" \
          --arg scan_speed "${SCAN_SPEED:-}" \
          --arg concurrency "${CONCURRENCY:-}" \
          --arg nmap_args "${NMAP_ARGS:-}" \
          --arg sqlmap_args "${SQLMAP_ARGS:-}" \
          --arg selected_tools "$selected_tools" \
          --arg risk_policy "${AI_RISK_POLICY_FILE:-}" \
          --arg replay_failed "${AI_REPLAY_FAILED_ONLY:-false}" \
          --argjson targets_count "$targets_count" \
          '{
            generated_at: $ts,
            output_base: $output_base,
            mode: $mode,
            workflow: $workflow,
            ai_orchestrator_mode: $ai_orchestrator,
            scan_speed: $scan_speed,
            concurrency: $concurrency,
            nmap_args: $nmap_args,
            sqlmap_args: $sqlmap_args,
            selected_tools: ($selected_tools | split(" ") | map(select(length>0))),
            risk_policy_file: $risk_policy,
            replay_failed_only: $replay_failed,
            targets_count: $targets_count
          }' > "$snapshot_file"
    else
        {
            echo "{"
            echo "  \"generated_at\": \"$(date -Iseconds)\","
            echo "  \"output_base\": \"${OUTPUT_BASE:-}\","
            echo "  \"mode\": \"${MODE:-unknown}\","
            echo "  \"workflow\": \"${WORKFLOW:-unknown}\""
            echo "}"
        } > "$snapshot_file"
    fi
}

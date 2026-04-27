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

write_state_snapshot() {
    local snapshot_file="$OUTPUT_BASE/.state_snapshot.json"
    local selected_tools="${SELECTED_TOOLS:-}"
    local targets_count=0
    [[ -f "${TARGETS_FILE:-}" ]] && targets_count="$(wc -l < "$TARGETS_FILE" | tr -d ' ')"

    if command -v jq >/dev/null 2>&1; then
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
          --argjson targets_count "${targets_count:-0}" \
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

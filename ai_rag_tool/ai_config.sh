#!/usr/bin/env bash

# Shared AI/Ollama configuration loader for Nexusuite.
# Priority (highest -> lowest):
# 1) Existing exported env vars
# 2) Project .env file
# 3) Built-in defaults

set -u

_AI_CFG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_AI_PROJECT_ROOT="$(cd "$_AI_CFG_DIR/.." && pwd)"
_AI_POLICY_FILE_DEFAULT="$_AI_PROJECT_ROOT/config/risk_policy.yaml"

_load_env_file() {
    local env_file="$1"
    [[ -f "$env_file" ]] || return 0

    while IFS= read -r line || [[ -n "$line" ]]; do
        # Skip comments and empty lines.
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        [[ "$line" == *"="* ]] || continue

        local key="${line%%=*}"
        local value="${line#*=}"

        # Trim spaces around key/value.
        key="$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        value="$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

        # Remove optional wrapping quotes.
        if [[ "$value" =~ ^\".*\"$ ]]; then
            value="${value:1:${#value}-2}"
        elif [[ "$value" =~ ^\'.*\'$ ]]; then
            value="${value:1:${#value}-2}"
        fi

        # Only set if not already exported/set by parent shell.
        if [[ -z "${!key:-}" ]]; then
            export "$key=$value"
        fi
    done < "$env_file"
}

_load_env_file "$_AI_PROJECT_ROOT/.env"

export OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"
export OLLAMA_MODEL="${OLLAMA_MODEL:-qwen2.5:0.5b}"
export AI_HTTP_TIMEOUT="${AI_HTTP_TIMEOUT:-30}"
export AI_LOG_SNIPPET_CHARS="${AI_LOG_SNIPPET_CHARS:-6000}"
export AI_ENABLE_WEB_SEARCH="${AI_ENABLE_WEB_SEARCH:-true}"
export AI_EXECUTE_VERIFICATION="${AI_EXECUTE_VERIFICATION:-false}"
export AI_MAX_EXEC_COMMANDS="${AI_MAX_EXEC_COMMANDS:-3}"
export AI_CMD_TIMEOUT="${AI_CMD_TIMEOUT:-40}"
export AI_EXECUTE_CONTROLLED_ACTIONS="${AI_EXECUTE_CONTROLLED_ACTIONS:-false}"
export AI_MAX_CONTROLLED_COMMANDS="${AI_MAX_CONTROLLED_COMMANDS:-2}"
export AI_ENABLE_APPROVAL_PROMPT="${AI_ENABLE_APPROVAL_PROMPT:-true}"
export AI_NONINTERACTIVE_APPROVE="${AI_NONINTERACTIVE_APPROVE:-false}"
export AI_ORCHESTRATOR_MODE="${AI_ORCHESTRATOR_MODE:-false}"
export AI_AUTONOMOUS_TARGETS="${AI_AUTONOMOUS_TARGETS:-}"
export AI_AUTONOMOUS_TARGETS_FILE="${AI_AUTONOMOUS_TARGETS_FILE:-}"
export AI_AUTONOMOUS_CONCURRENCY="${AI_AUTONOMOUS_CONCURRENCY:-3}"
export AI_ENABLE_DORKING="${AI_ENABLE_DORKING:-true}"
export AI_RISK_POLICY_FILE="${AI_RISK_POLICY_FILE:-$_AI_POLICY_FILE_DEFAULT}"
export AI_REPLAY_FAILED_ONLY="${AI_REPLAY_FAILED_ONLY:-false}"
export AI_REPLAY_SOURCE_FILE="${AI_REPLAY_SOURCE_FILE:-}"
export AI_MAX_BASELINE_URLS="${AI_MAX_BASELINE_URLS:-8}"
export AI_ENABLE_BASELINE_PROFILE="${AI_ENABLE_BASELINE_PROFILE:-true}"
export AI_DRY_RUN_EXPLAIN="${AI_DRY_RUN_EXPLAIN:-false}"

merge_no_proxy_list() {
    local merged="${AI_NO_PROXY:-${NO_PROXY:-${no_proxy:-}}}"
    local entry

    for entry in localhost 127.0.0.1 ::1; do
        case ",$merged," in
            *,"$entry",*) ;;
            *)
                if [[ -n "$merged" ]]; then
                    merged+=",${entry}"
                else
                    merged="${entry}"
                fi
                ;;
        esac
    done

    printf '%s' "$merged"
}

export AI_NO_PROXY="$(merge_no_proxy_list)"
export NO_PROXY="$AI_NO_PROXY"
export no_proxy="$AI_NO_PROXY"

export OLLAMA_TAGS_API="${OLLAMA_HOST%/}/api/tags"
export OLLAMA_GENERATE_API="${OLLAMA_HOST%/}/api/generate"

if [[ -f "$_AI_CFG_DIR/risk_policy.sh" ]]; then
    # shellcheck disable=SC1091
    source "$_AI_CFG_DIR/risk_policy.sh"
fi
if declare -F policy_get >/dev/null 2>&1; then
    export GLOBAL_REQUEST_COOLDOWN_SEC="${GLOBAL_REQUEST_COOLDOWN_SEC:-$(policy_get global_request_cooldown_sec '0.2')}"
else
    export GLOBAL_REQUEST_COOLDOWN_SEC="${GLOBAL_REQUEST_COOLDOWN_SEC:-0.2}"
fi

ollama_curl() {
    curl --noproxy "${AI_NO_PROXY:-localhost,127.0.0.1,::1}" "$@"
}

ollama_check() {
    ollama_curl -fsS -m "${AI_HTTP_TIMEOUT:-2}" "${OLLAMA_TAGS_API}" >/dev/null
}

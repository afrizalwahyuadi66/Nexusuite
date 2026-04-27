# ==============================================================================
# Error & Signal Handling (Ctrl+S, Ctrl+X, Cleanup)
# ==============================================================================

# Setup Custom Keybindings & Cleanup
if [ -t 0 ]; then
    ORIG_STTY=$(stty -g)
    stty -ixon     # Free up Ctrl+S from flow control
    stty intr ^S   # Map SIGINT (Interrupt/Skip) to Ctrl+S
    stty quit ^X   # Map SIGQUIT (Force Close) to Ctrl+X
fi

CLEANUP_CMDS=()
cleanup() {
    rm -f "${TMPDIR:-/tmp}/owasp_pause_render" 2>/dev/null || true
    for cmd in "${CLEANUP_CMDS[@]}"; do
        eval "$cmd" 2>/dev/null || true
    done
    if [ -t 0 ] && [ -n "${ORIG_STTY:-}" ]; then
        stty "$ORIG_STTY" 2>/dev/null || true
    fi
}
trap cleanup EXIT

add_cleanup() {
    CLEANUP_CMDS+=("$1")
}

force_close() {
    echo -e "\n\033[1;31m[!] Force closing scanner...\033[0m"
    pkill -P $$ 2>/dev/null || true
    exit 1
}
trap force_close SIGQUIT

# Prevent main script from exiting on SIGINT (Ctrl+S) so background jobs can handle it
global_sigint_handler() {
    # Block signals during menu
    trap '' SIGINT
    
    if [ ! -t 0 ]; then
        trap global_sigint_handler SIGINT
        return
    fi

    echo -e "\n\033[1;33m[!] Interactive Skip Menu (Ctrl+S)\033[0m"
    
    if [[ -z "${OUTPUT_BASE:-}" || ! -d "$OUTPUT_BASE/.status" ]]; then
        echo -e "\033[1;31mNo active scans yet.\033[0m"
        trap global_sigint_handler SIGINT
        return
    fi

    local options=()
    local pids=()
    local targets=()
    local steps=()
    local target_safes=()
    
    for sfile in "$OUTPUT_BASE/.status/"*.active; do
        [[ -f "$sfile" ]] || continue
        IFS='|' read -r tgt step state cpid < "$sfile" || true
        if [[ -n "$cpid" && "$state" == "Running" ]]; then
            if kill -0 "$cpid" 2>/dev/null; then
                options+=("$tgt - $step")
                pids+=("$cpid")
                targets+=("$tgt")
                steps+=("$step")
                target_safes+=("$(basename "$sfile" .active)")
            fi
        fi
    done
    
    if [[ ${#options[@]} -eq 0 ]]; then
        gum style --foreground 214 "No active tools to skip right now."
        sleep 1
        trap global_sigint_handler SIGINT
        return
    fi
    
    options+=("Skip entire domain..." "Cancel")
    
    local choice
    choice=$(gum choose --header "Select tool to SKIP:" "${options[@]}" < /dev/tty)
    
    if [[ "$choice" == "Cancel" || -z "$choice" ]]; then
        echo "Cancelled."
    elif [[ "$choice" == "Skip entire domain..." ]]; then
        local domain_opts=()
        for t in "${targets[@]}"; do
            domain_opts+=("$t")
        done
        domain_opts=($(printf "%s\n" "${domain_opts[@]}" | sort -u))
        domain_opts+=("Cancel")
        
        local dom_choice
        dom_choice=$(gum choose --header "Select DOMAIN to skip completely:" "${domain_opts[@]}" < /dev/tty)
        
        if [[ "$dom_choice" != "Cancel" && -n "$dom_choice" ]]; then
            for i in "${!targets[@]}"; do
                if [[ "${targets[$i]}" == "$dom_choice" ]]; then
                    local selected_pid="${pids[$i]}"
                    local safe="${target_safes[$i]}"
                    printf '%s\n' "$dom_choice" > "$OUTPUT_BASE/.status/${safe}.skip_domain"
                    pkill -P "$selected_pid" 2>/dev/null || true
                    kill -9 "$selected_pid" 2>/dev/null || true
                fi
            done
        fi
    else
        for i in "${!options[@]}"; do
            if [[ "${options[$i]}" == "$choice" ]]; then
                local selected_pid="${pids[$i]}"
                local safe="${target_safes[$i]}"
                printf '%s\n' "${steps[$i]}" > "$OUTPUT_BASE/.status/${safe}.skip_tool"
                pkill -P "$selected_pid" 2>/dev/null || true
                kill -9 "$selected_pid" 2>/dev/null || true
                break
            fi
        done
    fi
    
    trap global_sigint_handler SIGINT
}
trap global_sigint_handler SIGINT

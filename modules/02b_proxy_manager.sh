# ==============================================================================
# Proxy Management System
# ==============================================================================

PROXY_LOCK_FILE="${TMPDIR:-/tmp}/owasp_proxy_$$.lock"
export PROXY_LOCK_FILE
add_cleanup 'rm -f "$PROXY_LOCK_FILE"'

get_proxy() {
    if [[ "$USE_PROXY" != "true" ]]; then
        echo ""
        return
    fi
    
    (
        flock 200
        local proxy=""
        
        # Check active proxies
        if [[ -s "$PROXY_LIST_FILE" ]]; then
            proxy=$(head -n 1 "$PROXY_LIST_FILE")
            # Move to used
            tail -n +2 "$PROXY_LIST_FILE" > "${PROXY_LIST_FILE}.tmp" && mv "${PROXY_LIST_FILE}.tmp" "$PROXY_LIST_FILE"
            echo "$proxy" >> "$PROXY_USED_FILE"
            echo "$proxy"
            return
        fi
        
        # If no active proxies, try to recycle used ones that are not dead
        if [[ -s "$PROXY_USED_FILE" ]]; then
            # Filter out dead proxies
            if [[ -s "$PROXY_DEAD_FILE" ]]; then
                grep -vFf "$PROXY_DEAD_FILE" "$PROXY_USED_FILE" > "$PROXY_LIST_FILE" || true
            else
                cat "$PROXY_USED_FILE" > "$PROXY_LIST_FILE"
            fi
            
            # Clear used file
            > "$PROXY_USED_FILE"
            
            if [[ -s "$PROXY_LIST_FILE" ]]; then
                proxy=$(head -n 1 "$PROXY_LIST_FILE")
                tail -n +2 "$PROXY_LIST_FILE" > "${PROXY_LIST_FILE}.tmp" && mv "${PROXY_LIST_FILE}.tmp" "$PROXY_LIST_FILE"
                echo "$proxy" >> "$PROXY_USED_FILE"
                echo "$proxy"
                return
            fi
        fi
        
        # No proxy available
        echo ""
    ) 200>"$PROXY_LOCK_FILE"
}

mark_proxy_dead() {
    local proxy="$1"
    [[ -z "$proxy" ]] && return
    (
        flock 200
        echo "$proxy" >> "$PROXY_DEAD_FILE"
    ) 200>"$PROXY_LOCK_FILE"
}

set_proxy_env() {
    local proxy="$1"
    if [[ -n "$proxy" ]]; then
        export HTTP_PROXY="$proxy"
        export HTTPS_PROXY="$proxy"
        export http_proxy="$proxy"
        export https_proxy="$proxy"
        export ALL_PROXY="$proxy"
    else
        export HTTP_PROXY=""
        export HTTPS_PROXY=""
        export http_proxy=""
        export https_proxy=""
        export ALL_PROXY=""
    fi
}

rotate_proxy() {
    local target="$1"
    if [[ "$USE_PROXY" == "true" ]]; then
        log_msg "↻" "\033[1;33m" "$TARGET_DISPLAY" "Proxy" "Rotating proxy due to failure..."
        mark_proxy_dead "$CURRENT_PROXY"
        CURRENT_PROXY=$(get_proxy)
        if [[ -n "$CURRENT_PROXY" ]]; then
            TARGET_DISPLAY="$target [$CURRENT_PROXY]"
            log_msg ">" "\033[1;36m" "$TARGET_DISPLAY" "Proxy" "Assigned new proxy: $CURRENT_PROXY"
            set_proxy_env "$CURRENT_PROXY"
        else
            TARGET_DISPLAY="$target"
            log_msg "!" "\033[1;33m" "$TARGET_DISPLAY" "Proxy" "No proxies available. Running without proxy."
            set_proxy_env ""
        fi
    fi
}

ensure_proxy_alive() {
    local target="$1"
    local step="$2"
    
    if [[ "$USE_PROXY" != "true" || -z "$CURRENT_PROXY" ]]; then
        return 0
    fi

    log_msg ">" "\033[1;36m" "$TARGET_DISPLAY" "Proxy" "Pinging proxy for $step..."
    
    # Ping check using curl with proxy against the target
    if curl -x "$CURRENT_PROXY" -s -k -m 10 -o /dev/null "http://$target" || curl -x "$CURRENT_PROXY" -s -k -m 10 -o /dev/null "https://$target"; then
        log_msg "✓" "\033[1;32m" "$TARGET_DISPLAY" "Proxy" "Proxy ping successful for $step."
        return 0
    else
        log_msg "!" "\033[1;31m" "$TARGET_DISPLAY" "Proxy" "Proxy ping failed for $step. Eliminating proxy."
        rotate_proxy "$target"
        
        # After rotation, if there's still a proxy available, verify it recursively
        if [[ -n "$CURRENT_PROXY" ]]; then
            ensure_proxy_alive "$target" "$step"
        fi
    fi
}
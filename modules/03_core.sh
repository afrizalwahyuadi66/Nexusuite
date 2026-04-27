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
    local TARGET_SAFE=$(echo "$TARGET" | sed 's/[^a-zA-Z0-9.-]/_/g')

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
        if [[ "${PROXY_STRICT:-false}" == "true" ]]; then
            echo "Policy: Strict Proxy-Only"
        else
            echo "Policy: Best Effort"
        fi
        echo "------------------------------------------------------------"
    } > "$PROXY_AUDIT_FILE"
    local skip_domain_flag=0
    local current_cmd_pid=""
    
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

    if declare -F scope_guard_target >/dev/null 2>&1; then
        if ! scope_guard_target "$TARGET"; then
            log_msg "!" "\033[1;31m" "$TARGET_DISPLAY" "ScopeGuard" "Target diblokir policy. Target dilewati."
            echo "[$TARGET] Scope guard blocked target." >> "$OUTPUT_BASE/failed_tasks.txt"
            abort_target_scan
            return 0
        fi
    fi

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
        local max_retries=2
        local retry_count=0
        local cmd_pid=""
        local exit_code=1
        local start_time=$(date +%s)
        local attempt_no=1
        FORCE_SKIP_TOOL=0

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

    # ========== PHASE 1: RECONNAISSANCE ==========
    # Subfinder hanya dieksekusi jika alat tersebut ada di SELECTED_TOOLS (sudah difilter di prompts.sh)
    if echo "$SELECTED_TOOLS" | grep -q "subfinder"; then
        run_step "Subfinder" subfinder -d "$TARGET" -silent __PROXY__ -o "$TARGET_DIR/recon/subfinder.txt" || { abort_target_scan; return 0; }
    fi

    # WAFW00F (WAF Detector)
    if echo "$SELECTED_TOOLS" | grep -q "wafw00f"; then
        # Menggunakan bash -c dan tee untuk menghindari bug upstream wafw00f (crash saat host down dengan flag -o)
        run_step "Wafw00f" bash -c "wafw00f '$TARGET' | tee '$TARGET_DIR/recon/waf.txt'" || { abort_target_scan; return 0; }
    fi

    if [[ "$FULL_AUTO_MODE" != "true" ]] && echo "$SELECTED_TOOLS" | grep -q "httpx"; then
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

    if echo "$SELECTED_TOOLS" | grep -q "nmap"; then
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

    if echo "$SELECTED_TOOLS" | grep -q "gau"; then
        run_step "GAU" gau "$TARGET" --subs --o "$TARGET_DIR/recon/gau_urls.txt" || { abort_target_scan; return 0; }
    fi

    if echo "$SELECTED_TOOLS" | grep -q "katana" && [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
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
        else
            > "$TARGET_DIR/recon/all_urls.txt"
            log_msg "!" "\033[1;33m" "$TARGET" "Filter" "No URL with status 200 found. Skipping further URL-based tests."
        fi
        # Buat juga file auditable URLs (dengan parameter) untuk referensi manual
        grep -E '(\?|=)' "$TARGET_DIR/recon/all_urls.txt" 2>/dev/null > "$TARGET_DIR/recon/auditable_urls.txt" || true
    else
        > "$TARGET_DIR/recon/all_urls.txt"
    fi

    if echo "$SELECTED_TOOLS" | grep -q "paramspider"; then
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

    if echo "$SELECTED_TOOLS" | grep -q "arjun" && [[ -s "$TARGET_DIR/recon/all_urls.txt" ]]; then
        head -n 50 "$TARGET_DIR/recon/all_urls.txt" | run_step "Arjun" arjun -i /dev/stdin -oT "$TARGET_DIR/recon/params.txt" -q || { abort_target_scan; return 0; }
    fi

    # Menambahkan FFUF untuk Directory & File Discovery
    if echo "$SELECTED_TOOLS" | grep -q "ffuf" && [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
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

    # ========== PHASE 2: VULNERABILITY SCANNING ==========
    if echo "$SELECTED_TOOLS" | grep -q "nuclei" && [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
        IFS=' ' read -ra nuclei_rl_arr <<< "$NUCLEI_RL"
        run_step "Nuclei" nuclei -l "$TARGET_DIR/recon/alive.txt" -silent "${nuclei_rl_arr[@]}" __PROXY__ -o "$TARGET_DIR/vulnerabilities/nuclei.txt" || { abort_target_scan; return 0; }
    fi

    # Dalfox hanya jika ada URL valid dengan parameter
    if echo "$SELECTED_TOOLS" | grep -q "dalfox" && [[ -s "$TARGET_DIR/recon/urls_with_params.txt" ]]; then
        IFS=' ' read -ra dalfox_rl_arr <<< "$DALFOX_RL"
        run_step "Dalfox" dalfox file "$TARGET_DIR/recon/urls_with_params.txt" --silence "${dalfox_rl_arr[@]}" __PROXY__ --output "$TARGET_DIR/vulnerabilities/xss.txt" || { abort_target_scan; return 0; }
    fi

    if echo "$SELECTED_TOOLS" | grep -q "wapiti" && [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
        while IFS= read -r host; do
            [[ "$host" =~ ^https?:// ]] || continue
            safe_host=$(echo "$host" | md5sum | cut -d' ' -f1)
            # Wapiti checks for multiple vulns (SQLi, XSS, File Inclusion, SSRF, CRLF, XXE)
            run_step "Wapiti ($host)" wapiti -u "$host" --flush-session -m "sql,xss,file,xxe,ssrf,crlf" -f txt -o "$TARGET_DIR/vulnerabilities/wapiti_${safe_host}.txt" || { abort_target_scan; return 0; }
        done < "$TARGET_DIR/recon/alive.txt"
    fi

    # MODIFIKASI 3: SQLMap dengan argumen kustom dan hanya URL valid dengan parameter
    if echo "$SELECTED_TOOLS" | grep -q "sqlmap" && [[ -s "$TARGET_DIR/recon/urls_with_params.txt" ]]; then
        IFS=' ' read -ra sqlmap_args <<< "$SQLMAP_ARGS"
        IFS=' ' read -ra sqlmap_rl_arr <<< "$SQLMAP_RL"
        # Cek apakah pengguna menggunakan -u (single URL) dalam argumen
        if [[ "${sqlmap_args[*]}" == *"-u"* ]]; then
            # Mode satu per satu URL
            while IFS= read -r url; do
                run_step "SQLMap ($url)" sqlmap -u "$url" "${sqlmap_args[@]}" "${sqlmap_rl_arr[@]}" __PROXY__ --output-dir="$TARGET_DIR/vulnerabilities/sqlmap" || { abort_target_scan; return 0; }
            done < "$TARGET_DIR/recon/urls_with_params.txt"
        else
            # Mode batch dengan file (-m)
            run_step "SQLMap" sqlmap -m "$TARGET_DIR/recon/urls_with_params.txt" "${sqlmap_args[@]}" "${sqlmap_rl_arr[@]}" __PROXY__ --output-dir="$TARGET_DIR/vulnerabilities/sqlmap" || { abort_target_scan; return 0; }
        fi
    fi

    # ========== PHASE 3: FINAL (NIKTO) ==========
    if echo "$SELECTED_TOOLS" | grep -q "nikto" && [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
        while IFS= read -r host; do
            [[ "$host" =~ ^https?:// ]] || continue
            run_step "Nikto ($host)" nikto -h "$host" -output "$TARGET_DIR/scans/nikto_$(echo "$host" | md5sum | cut -d' ' -f1).txt" || { abort_target_scan; return 0; }
        done < "$TARGET_DIR/recon/alive.txt"
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

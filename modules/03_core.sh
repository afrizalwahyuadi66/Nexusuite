# ==============================================================================
# Pre-scan Internet Check
# ==============================================================================
if ! check_internet; then
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
    local skip_domain_flag=0
    local current_cmd_pid=""
    
    local TARGET_DISPLAY="$TARGET"

    local STATUS_FILE="$OUTPUT_BASE/.status/${TARGET_SAFE}.active"
    echo "$TARGET|INIT|Starting|$TARGET_LOG" > "$STATUS_FILE"
    log_msg ">" "\033[1;36m" "$TARGET_DISPLAY" "INIT" "Starting scan..."

    # Proxy Allocation and Checking
    local CURRENT_PROXY=""
    local TARGET_DISPLAY="$TARGET"

    if [[ "$USE_PROXY" == "true" ]]; then
        CURRENT_PROXY=$(get_proxy)
        
        if [[ -n "$CURRENT_PROXY" ]]; then
            TARGET_DISPLAY="$TARGET [$CURRENT_PROXY]"
            set_proxy_env "$CURRENT_PROXY"
            ensure_proxy_alive "$TARGET" "INIT"
        else
            log_msg "!" "\033[1;33m" "$TARGET_DISPLAY" "Proxy" "No proxies available. Running without proxy."
            set_proxy_env ""
        fi
    fi

    run_cmd() {
        local step="$1"; shift
        local max_retries=2
        local retry_count=0
        local cmd_pid=""
        local exit_code=1
        local start_time=$(date +%s)
        FORCE_SKIP_TOOL=0

        while [[ $retry_count -le $max_retries ]]; do
            if [[ "$FORCE_SKIP_TOOL" -eq 1 ]]; then
                log_msg "!" "\033[1;33m" "$TARGET_DISPLAY" "$step" "Skipped manually by user."
                FORCE_SKIP_TOOL=0
                return 0
            fi

            if [[ $retry_count -gt 0 ]]; then
                log_msg "↻" "\033[1;33m" "$TARGET_DISPLAY" "$step" "Retry $retry_count/$max_retries"
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
            for arg in "$@"; do
                if [[ "$arg" != "__PROXY__" ]]; then
                    cmd+=("$arg")
                fi
            done

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

            # Cek apakah target ini ditandai untuk diskip
            if [[ -f "$OUTPUT_BASE/.status/${TARGET_SAFE}.skip_tool" ]]; then
                rm -f "$OUTPUT_BASE/.status/${TARGET_SAFE}.skip_tool"
                log_msg "!" "\033[1;33m" "$TARGET_DISPLAY" "$step" "Skipped manually by user."
                return 0
            fi

            if [[ -f "$OUTPUT_BASE/.status/${TARGET_SAFE}.skip_domain" ]]; then
                log_msg "→" "\033[1;36m" "$TARGET_DISPLAY" "System" "Skipping entire domain..."
                echo "$TARGET" >> "$SKIP_DOMAIN_FILE"
                exit 2
            fi

            if [[ "$FORCE_SKIP_TOOL" -eq 1 ]]; then
                log_msg "!" "\033[1;33m" "$TARGET_DISPLAY" "$step" "Skipped manually by user."
                FORCE_SKIP_TOOL=0
                return 0
            fi

            local end_time=$(date +%s)
            local duration=$((end_time - start_time))

            if [[ $exit_code -eq 0 ]]; then
                log_msg "✓" "\033[1;32m" "$TARGET_DISPLAY" "$step" "Completed (${duration}s)"
                return 0
            elif [[ $exit_code -eq 124 ]]; then
                log_msg "!" "\033[1;31m" "$TARGET_DISPLAY" "$step" "Unresponsive/Too long (${timeout_sec}s). Skipping."
                echo "[$TARGET_DISPLAY] $step - Skipped (Unresponsive/Timeout)" >> "$OUTPUT_BASE/failed_tasks.txt"
                return 0
            elif [[ $exit_code -eq 137 || $exit_code -eq 139 ]]; then
                # 137 (SIGKILL) usually Out of Memory, 139 (SIGSEGV) usually Segmentation Fault
                log_msg "!" "\033[1;31m" "$TARGET_DISPLAY" "$step" "System Crash/OOM (exit $exit_code). Skipping to prevent freeze."
                echo "[$TARGET_DISPLAY] $step - Skipped (Crash/OOM - Exit $exit_code)" >> "$OUTPUT_BASE/failed_tasks.txt"
                return 0
            else
                log_msg "!" "\033[1;31m" "$TARGET_DISPLAY" "$step" "Failed (exit $exit_code, ${duration}s)"
                rotate_proxy "$TARGET"
                
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

    # ==============================================================================
    # SET SPEED/RATE LIMIT ARGUMENTS BASED ON USER CHOICE
    # ==============================================================================
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
        run_cmd "Subfinder" subfinder -d "$TARGET" -silent __PROXY__ -o "$TARGET_DIR/recon/subfinder.txt"
    fi

    # WAFW00F (WAF Detector)
    if echo "$SELECTED_TOOLS" | grep -q "wafw00f"; then
        # Menggunakan bash -c dan tee untuk menghindari bug upstream wafw00f (crash saat host down dengan flag -o)
        run_cmd "Wafw00f" bash -c "wafw00f '$TARGET' | tee '$TARGET_DIR/recon/waf.txt'"
    fi

    if [[ "$FULL_AUTO_MODE" != "true" ]] && echo "$SELECTED_TOOLS" | grep -q "httpx"; then
        if [[ -s "$TARGET_DIR/recon/subfinder.txt" ]]; then
            HOSTS_FILE="$TARGET_DIR/recon/subfinder.txt"
        else
            echo "$TARGET" > "$TARGET_DIR/recon/temp_host.txt"
            HOSTS_FILE="$TARGET_DIR/recon/temp_host.txt"
        fi
        run_cmd "httpx" httpx -l "$HOSTS_FILE" -silent -td -title -status-code -ip __PROXY__ -o "$TARGET_DIR/recon/alive.txt"
    else
        echo "$TARGET" > "$TARGET_DIR/recon/alive.txt"
    fi

    if echo "$SELECTED_TOOLS" | grep -q "nmap"; then
        IFS=' ' read -ra nmap_args <<< "$NMAP_ARGS"
        local nmap_target=""
        if [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
            sed -e 's#^http://##' -e 's#^https://##' -e 's#/.*##' "$TARGET_DIR/recon/alive.txt" | sort -u > "$TARGET_DIR/recon/hosts_nmap.txt"
            nmap_target="-iL $TARGET_DIR/recon/hosts_nmap.txt"
        else
            nmap_target="$TARGET"
        fi
        
        run_cmd "Nmap" nmap $nmap_target "${nmap_args[@]}" -oA "$TARGET_DIR/scans/nmap"
        
        # Cek jika nmap gagal menemukan host up (biasanya karena block ICMP)
        if grep -q "0 hosts up" "$TARGET_DIR/scans/nmap.nmap" 2>/dev/null; then
            log_msg "i" "\033[1;33m" "$TARGET" "Nmap" "0 hosts up detected. Retrying with -Pn (No Ping)..."
            run_cmd "Nmap (Fallback -Pn)" nmap $nmap_target -Pn "${nmap_args[@]}" -oA "$TARGET_DIR/scans/nmap_pn"
        fi
    fi

    if echo "$SELECTED_TOOLS" | grep -q "gau"; then
        run_cmd "GAU" gau "$TARGET" --subs --o "$TARGET_DIR/recon/gau_urls.txt"
    fi

    if echo "$SELECTED_TOOLS" | grep -q "katana" && [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
        run_cmd "Katana" katana -u "$TARGET_DIR/recon/alive.txt" -silent -jc -kf all __PROXY__ -o "$TARGET_DIR/recon/katana_urls.txt"
    fi

    # Gabungkan URL dari gau dan katana
    cat "$TARGET_DIR/recon"/{gau_urls,katana_urls}.txt 2>/dev/null | sort -u > "$TARGET_DIR/recon/all_urls_raw.txt" 2>/dev/null || true

    # MODIFIKASI 1: Filter URL dengan httpx (hanya yang status 200)
    if [[ -s "$TARGET_DIR/recon/all_urls_raw.txt" ]]; then
        run_cmd "Probe URLs (filter 200)" httpx -l "$TARGET_DIR/recon/all_urls_raw.txt" -silent -status-code -mc 200 __PROXY__ -o "$TARGET_DIR/recon/all_urls_200.txt"
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
        run_cmd "ParamSpider" bash -c "
            cd '$TARGET_DIR/recon' || exit 1
            paramspider -d '$TARGET' --quiet 2>/dev/null
            if [[ -f 'results/$TARGET.txt' ]]; then
                mv 'results/$TARGET.txt' paramspider.txt
                rm -rf results
            elif [[ -f 'results/${TARGET}.txt' ]]; then
                mv 'results/${TARGET}.txt' paramspider.txt
                rm -rf results
            fi
        "
        if [[ -s "$TARGET_DIR/recon/paramspider.txt" ]]; then
            grep -oP '[\?&]\K[^=&\s]+' "$TARGET_DIR/recon/paramspider.txt" | sort -u > "$TARGET_DIR/recon/params_wordlist.txt" || true
        else
            log_msg "!" "\033[1;33m" "$TARGET" "ParamSpider" "ParamSpider produced no output."
        fi
    fi

    if echo "$SELECTED_TOOLS" | grep -q "arjun" && [[ -s "$TARGET_DIR/recon/all_urls.txt" ]]; then
        head -n 50 "$TARGET_DIR/recon/all_urls.txt" | run_cmd "Arjun" arjun -i /dev/stdin -oT "$TARGET_DIR/recon/params.txt" -q
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
                run_cmd "FFUF ($host)" ffuf -u "$host/FUZZ" -w "$wordlist" "${ffuf_rl_arr[@]}" -mc 200,204,301,302,307,401 -s __PROXY__ -o "$TARGET_DIR/recon/ffuf_${safe_host}.json"
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
        run_cmd "Nuclei" nuclei -l "$TARGET_DIR/recon/alive.txt" -silent "${nuclei_rl_arr[@]}" __PROXY__ -o "$TARGET_DIR/vulnerabilities/nuclei.txt"
    fi

    # Dalfox hanya jika ada URL valid dengan parameter
    if echo "$SELECTED_TOOLS" | grep -q "dalfox" && [[ -s "$TARGET_DIR/recon/urls_with_params.txt" ]]; then
        IFS=' ' read -ra dalfox_rl_arr <<< "$DALFOX_RL"
        run_cmd "Dalfox" dalfox file "$TARGET_DIR/recon/urls_with_params.txt" --silence "${dalfox_rl_arr[@]}" __PROXY__ --output "$TARGET_DIR/vulnerabilities/xss.txt"
    fi

    if echo "$SELECTED_TOOLS" | grep -q "wapiti" && [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
        while IFS= read -r host; do
            [[ "$host" =~ ^https?:// ]] || continue
            safe_host=$(echo "$host" | md5sum | cut -d' ' -f1)
            # Wapiti checks for multiple vulns (SQLi, XSS, File Inclusion, SSRF, CRLF, XXE)
            run_cmd "Wapiti ($host)" wapiti -u "$host" --flush-session -m "sql,xss,file,xxe,ssrf,crlf" -f txt -o "$TARGET_DIR/vulnerabilities/wapiti_${safe_host}.txt"
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
                run_cmd "SQLMap ($url)" sqlmap -u "$url" "${sqlmap_args[@]}" "${sqlmap_rl_arr[@]}" __PROXY__ --output-dir="$TARGET_DIR/vulnerabilities/sqlmap"
            done < "$TARGET_DIR/recon/urls_with_params.txt"
        else
            # Mode batch dengan file (-m)
            run_cmd "SQLMap" sqlmap -m "$TARGET_DIR/recon/urls_with_params.txt" "${sqlmap_args[@]}" "${sqlmap_rl_arr[@]}" __PROXY__ --output-dir="$TARGET_DIR/vulnerabilities/sqlmap"
        fi
    fi

    # ========== PHASE 3: FINAL (NIKTO) ==========
    if echo "$SELECTED_TOOLS" | grep -q "nikto" && [[ -s "$TARGET_DIR/recon/alive.txt" ]]; then
        while IFS= read -r host; do
            [[ "$host" =~ ^https?:// ]] || continue
            run_cmd "Nikto ($host)" nikto -h "$host" -output "$TARGET_DIR/scans/nikto_$(echo "$host" | md5sum | cut -d' ' -f1).txt"
        done < "$TARGET_DIR/recon/alive.txt"
    fi

    # Done with this target
    echo "$TARGET" >> "$COMPLETED_FILE"
    echo -e "\n=== Scan finished for: $TARGET ===" >> "$TARGET_LOG"

    # --- INTEGRASI AUTONOMOUS AI PENTESTER (OPSIONAL) ---
    if [[ "$USE_AI" == "y" || "$USE_AI" == "Y" ]]; then
        echo -e "\n[🤖] Mengecek koneksi ke AI Agent lokal (Ollama)..." | tee -a "$TARGET_LOG"
        
        # Cek apakah Ollama berjalan di localhost:11434 menggunakan curl (timeout 2 detik)
        if curl -s -m 2 http://localhost:11434 > /dev/null; then
            echo -e "[🤖] Ollama terdeteksi! Menyerahkan hasil scan ke AI Agent untuk dianalisis dan dieksploitasi..." | tee -a "$TARGET_LOG"
            
            # Deteksi path lokasi script agar kompatibel di Windows/Linux/Termux
            AI_SCRIPT="$(dirname "$(dirname "$BASH_SOURCE")")/ai_rag_tool/autonomous_pentester.py"
            
            python3 "$AI_SCRIPT" --target "$TARGET" --log-dir "$TARGET_DIR" >> "$TARGET_LOG" 2>&1 || \
            python "$AI_SCRIPT" --target "$TARGET" --log-dir "$TARGET_DIR" >> "$TARGET_LOG" 2>&1
            
            echo "[🤖] Analisis AI selesai." | tee -a "$TARGET_LOG"
        else
            echo -e "[!] Ollama tidak terdeteksi berjalan di localhost:11434. Melewati analisis AI." | tee -a "$TARGET_LOG"
        fi
    fi

    trap - SIGINT
}
export -f process_target

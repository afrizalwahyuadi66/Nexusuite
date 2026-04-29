# ==============================================================================
# Automated Vulnerability Auditing & Triage
# ==============================================================================

set -euo pipefail
shopt -s nullglob

gum style --margin "1 0" --foreground 212 "## 🔍 Starting Automated Auditing & Triage..."

AI_TOOL_DIR="$(dirname "$(dirname "$BASH_SOURCE")")/ai_rag_tool"
if [[ -f "$AI_TOOL_DIR/ai_config.sh" ]]; then
    # shellcheck disable=SC1090
    source "$AI_TOOL_DIR/ai_config.sh"
fi

export TOTAL_CONFIRMED_BUGS=0
AUDIT_SUMMARY_FILE="$OUTPUT_BASE/audited_summary.txt"
: > "$AUDIT_SUMMARY_FILE"
GLOBAL_AUDIT_JSONL="$OUTPUT_BASE/audited_findings_all.jsonl"
GLOBAL_AUDIT_JSON="$OUTPUT_BASE/audited_findings_all.json"
: > "$GLOBAL_AUDIT_JSONL"

extract_first_url() {
    local line="$1"
    printf '%s' "$line" | grep -oE 'https?://[^[:space:]]+' | head -n 1 || true
}

extract_first_param() {
    local url="$1"
    printf '%s' "$url" | sed -n 's/.*[?&]\([^=&?#]*\)=.*/\1/p'
}

append_audit_finding() {
    local txt_file="$1"
    local jsonl_file="$2"
    local target="$3"
    local source="$4"
    local severity="$5"
    local url="$6"
    local param="$7"
    local evidence="$8"
    local repro_command="$9"
    local line=""

    [[ -z "$url" || "$url" == "null" ]] && url="N/A"
    [[ -z "$param" || "$param" == "null" ]] && param="N/A"
    [[ -z "$repro_command" || "$repro_command" == "null" ]] && repro_command="manual_verification_required"

    line="[$source][$severity] $evidence | URL: $url | Param: $param | Repro: $repro_command"
    echo "$line" >> "$txt_file"

    jq -nc \
      --arg target "$target" \
      --arg url "$url" \
      --arg param "$param" \
      --arg evidence "$evidence" \
      --arg severity "$severity" \
      --arg repro_command "$repro_command" \
      '{target:$target,url:$url,param:$param,evidence:$evidence,severity:$severity,repro_command:$repro_command}' \
      >> "$jsonl_file"
}

score_line() {
    local line="$1"
    local score=35
    [[ "$line" == *"[Nuclei]"* ]] && score=$((score + 25))
    [[ "$line" == *"[SQLi]"* ]] && score=$((score + 30))
    [[ "$line" == *"[XSS]"* ]] && score=$((score + 20))
    [[ "$line" == *"[FFUF]"* ]] && score=$((score + 12))
    [[ "$line" == *"[Nmap]"* ]] && score=$((score + 10))
    [[ "$line" == *"[critical]"* || "$line" == *"[CRITICAL]"* ]] && score=$((score + 25))
    [[ "$line" == *"[high]"* || "$line" == *"[HIGH]"* ]] && score=$((score + 15))
    [[ "$line" == *"CVE-"* ]] && score=$((score + 15))
    (( score > 100 )) && score=100
    printf '%s' "$score"
}

for target_dir in "$OUTPUT_BASE/targets/"*; do
    [[ -d "$target_dir" ]] || continue
    target_name="$(basename "$target_dir")"
    
    AUDIT_FILE="$target_dir/vulnerabilities/audited_confirmed.txt"
    AUDIT_JSONL_FILE="$target_dir/vulnerabilities/audit_findings.jsonl"
    AUDIT_JSON_FILE="$target_dir/vulnerabilities/audit_findings.json"
    : > "$AUDIT_FILE"
    : > "$AUDIT_JSONL_FILE"
    
    log_msg ">" "\033[1;36m" "$target_name" "AUDIT" "Verifying raw vulnerability logs..."
    
    # 1. Audit SQLMap: Mencari indikasi injeksi sukses ([CRITICAL] atau adanya file target.txt)
    if [[ -d "$target_dir/vulnerabilities/sqlmap" ]]; then
        while IFS= read -r logfile; do
            # Validasi ketat: Hanya setuju jika berhasil mengekstrak nama database (bukti eksploitasi bisa dijalankan)
            if grep -qE "fetching database names|available databases|\[\*\] information_schema" "$logfile"; then
                # Ekstrak URL dan parameter dari file target.txt jika ada
                targetfile="$(dirname "$logfile")/target.txt"
                target_url="N/A"
                param="Unknown"
                if [[ -f "$targetfile" ]]; then
                    target_url="$(head -n 1 "$targetfile")"
                    param="$(grep "Parameter:" "$logfile" | head -n 1 | awk -F "Parameter: " '{print $2}' | awk '{print $1}')"
                    [[ -z "$param" ]] && param="Unknown"
                fi
                append_audit_finding \
                    "$AUDIT_FILE" "$AUDIT_JSONL_FILE" "$target_name" "SQLi" "critical" \
                    "$target_url" "$param" \
                    "Confirmed SQL Injection (database extraction evidence found)." \
                    "sqlmap -u \"$target_url\" -p \"$param\" --batch --dbs"
            fi
        done < <(find "$target_dir/vulnerabilities/sqlmap" -name "log" -type f 2>/dev/null)
        
        # Jika ada file target.txt, pastikan log aslinya juga menunjukkan database
        while IFS= read -r targetfile; do
            logfile="$(dirname "$targetfile")/log"
            if [[ -f "$logfile" ]] && grep -qE "fetching database names|available databases" "$logfile"; then
                target_url="$(head -n 1 "$targetfile")"
                param="$(grep "Parameter:" "$logfile" | head -n 1 | awk -F "Parameter: " '{print $2}' | awk '{print $1}')"
                [[ -z "$param" ]] && param="Unknown"
                # Hindari duplikat jika sudah dimasukkan oleh loop sebelumnya
                if ! grep -qF "URL: $target_url | Param: $param" "$AUDIT_FILE"; then
                    append_audit_finding \
                        "$AUDIT_FILE" "$AUDIT_JSONL_FILE" "$target_name" "SQLi" "critical" \
                        "$target_url" "$param" \
                        "Confirmed SQL Injection (duplicate-safe SQLMap confirmation)." \
                        "sqlmap -u \"$target_url\" -p \"$param\" --batch --dbs"
                fi
            fi
        done < <(find "$target_dir/vulnerabilities/sqlmap" -name "target.txt" -type f 2>/dev/null)
    fi
    
    # 2. Audit Dalfox (XSS): Hanya menyimpan yang benar-benar memiliki status POC (Proof of Concept)
    if [[ -s "$target_dir/vulnerabilities/xss.txt" ]]; then
        while IFS= read -r xss_line; do
            # Mencoba mengekstrak URL dari output Dalfox (biasanya diawali http)
            xss_url="$(extract_first_url "$xss_line")"
            xss_param="$(extract_first_param "$xss_url")"
            [[ -z "$xss_param" ]] && xss_param="Unknown"
            append_audit_finding \
                "$AUDIT_FILE" "$AUDIT_JSONL_FILE" "$target_name" "XSS" "high" \
                "${xss_url:-N/A}" "$xss_param" \
                "Confirmed Cross-Site Scripting POC from Dalfox logs." \
                "dalfox url \"${xss_url:-http://$target_name}\""
        done < <(grep -E "POC|Vulnerable" "$target_dir/vulnerabilities/xss.txt" || true)
    fi
    
    # 3. Audit Nuclei: Menyaring hanya temuan [critical] dan [high] untuk mengabaikan false-positive/informational
    if [[ -s "$target_dir/vulnerabilities/nuclei.txt" ]]; then
        while IFS= read -r line; do
            nuclei_url="$(extract_first_url "$line")"
            sev="high"
            echo "$line" | grep -qi '\[critical\]' && sev="critical"
            append_audit_finding \
                "$AUDIT_FILE" "$AUDIT_JSONL_FILE" "$target_name" "Nuclei" "$sev" \
                "${nuclei_url:-N/A}" "N/A" \
                "Confirmed ${sev} severity finding: $line" \
                "nuclei -u \"${nuclei_url:-http://$target_name}\" -severity high,critical -silent"
        done < <(grep -iE '\[(high|critical)\]' "$target_dir/vulnerabilities/nuclei.txt" || true)
    fi
    
    # 4. Audit Wapiti: Mencari kata kunci Vulnerability yang valid (bukan sekedar info)
    for wfile in "$target_dir/vulnerabilities"/wapiti_*.txt; do
        [[ -f "$wfile" ]] || continue
        if grep -qi "Vulnerability found" "$wfile" || grep -qi "\[+\]" "$wfile"; then
            append_audit_finding \
                "$AUDIT_FILE" "$AUDIT_JSONL_FILE" "$target_name" "Wapiti" "medium" \
                "N/A" "N/A" \
                "Potential injection confirmed in Wapiti logs ($(basename "$wfile"))." \
                "wapiti -u \"http://$target_name\" -f txt"
        fi
    done
    
    # 5. Audit FFUF: Memeriksa direktori/file penting yang ditemukan (Status 200 OK)
    for ffile in "$target_dir/recon"/ffuf_*.json; do
        [[ -f "$ffile" ]] || continue
        # Menggunakan jq untuk mencari endpoint dengan status 200
        while IFS= read -r sensitive_url; do
            append_audit_finding \
                "$AUDIT_FILE" "$AUDIT_JSONL_FILE" "$target_name" "FFUF" "medium" \
                "$sensitive_url" "N/A" \
                "Confirmed exposed sensitive path from FFUF output." \
                "ffuf -u \"$sensitive_url\" -w <wordlist>"
        done < <(jq -r '.results[] | select(.status == 200) | .url' "$ffile" 2>/dev/null | grep -iE '(admin|config|backup|api|secret|login|db|sql|env|\.git|\.bak|\.old|\.zip|\.tar)' || true)
    done

    # 6. Audit NMAP: Mengekstrak CVE, Exploit, dan skor kerentanan
    if [[ -f "$target_dir/scans/nmap.nmap" ]]; then
        # Menggunakan grep dengan regex yang lebih longgar untuk menangkap CVE dan vulners
        while IFS= read -r nmap_vuln; do
            # Bersihkan output (hapus karakter | dan spasi berlebih di awal)
            clean_vuln="$(echo "$nmap_vuln" | sed 's/^[|[:space:]]*//')"
            nmap_sev="medium"
            echo "$clean_vuln" | grep -qE 'CVE-[0-9]{4}-[0-9]+' && nmap_sev="high"
            append_audit_finding \
                "$AUDIT_FILE" "$AUDIT_JSONL_FILE" "$target_name" "Nmap" "$nmap_sev" \
                "$target_name" "N/A" \
                "Nmap vulnerability signal: $clean_vuln" \
                "nmap -sV --script vuln $target_name"
        done < <(grep -iE "VULNERABLE|EXPLOIT|vulners:|CVE-[0-9]{4}-[0-9]+" "$target_dir/scans/nmap.nmap" || true)
    fi

    # Menghitung hasil dan merapikan output
    if [[ -s "$AUDIT_FILE" ]]; then
        # Buang duplikat log (sort -u) jika tools mendeteksi hal yang sama berkali-kali
        sort -u -o "$AUDIT_FILE" "$AUDIT_FILE"
        if [[ -s "$AUDIT_JSONL_FILE" ]]; then
            jq -s 'unique_by(.target,.url,.param,.evidence,.severity,.repro_command)' "$AUDIT_JSONL_FILE" > "$AUDIT_JSON_FILE" || echo "[]" > "$AUDIT_JSON_FILE"
            jq -c '.[]' "$AUDIT_JSON_FILE" >> "$GLOBAL_AUDIT_JSONL"
        else
            echo "[]" > "$AUDIT_JSON_FILE"
        fi

        SCORED_FILE="$target_dir/vulnerabilities/scored_findings.tsv"
        DEDUP_FILE="$target_dir/vulnerabilities/dedup_findings.txt"
        {
            echo -e "score\tsource\tfinding"
            while IFS= read -r finding; do
                [[ -n "$finding" ]] || continue
                score="$(score_line "$finding")"
                src="$(echo "$finding" | sed -n 's/^\[\([^]]*\)\].*/\1/p')"
                [[ -z "$src" ]] && src="Unknown"
                printf "%s\t%s\t%s\n" "$score" "$src" "$finding"
            done < "$AUDIT_FILE"
        } | sort -t$'\t' -k1,1nr > "$SCORED_FILE"

        awk -F'\t' 'NR==1{next} {
            key=$3
            gsub(/https?:\/\/[^ ]+/, "<url>", key)
            gsub(/[0-9]{1,6}/, "<n>", key)
            if (!(key in seen)) {
                seen[key]=1
                print $3
            }
        }' "$SCORED_FILE" > "$DEDUP_FILE"

        bug_count=$(wc -l < "$AUDIT_FILE")
        
        log_msg "✓" "\033[1;32m" "$target_name" "AUDIT" "Found $bug_count confirmed vulnerabilities!"
        log_msg "i" "\033[1;36m" "$target_name" "AUDIT" "Standardized JSON saved: vulnerabilities/audit_findings.json"
        
        echo "--- $target_name ---" >> "$AUDIT_SUMMARY_FILE"
        cat "$AUDIT_FILE" >> "$AUDIT_SUMMARY_FILE"
        echo "" >> "$AUDIT_SUMMARY_FILE"
        
        ((TOTAL_CONFIRMED_BUGS += bug_count))
    else
        log_msg "✓" "\033[1;32m" "$target_name" "AUDIT" "Clean. No critical bugs confirmed."
        rm -f "$AUDIT_FILE"
        echo "[]" > "$AUDIT_JSON_FILE"
    fi

    # --- INTEGRASI AUTONOMOUS AI PENTESTER ---
    # Dijalankan secara sinkron pada fase Audit sehingga output bisa langsung terlihat
    if [[ "$USE_AI" == "y" || "$USE_AI" == "Y" ]]; then
        if [[ "${DRY_RUN:-false}" == "true" ]]; then
            log_msg "i" "\033[1;35m" "$target_name" "AI AGENT" "DRY-RUN aktif, analisis AI dilewati."
            continue
        fi

        log_msg "🤖" "\033[1;35m" "$target_name" "AI AGENT" "Memulai Analisis AI Pentester..."
        
        # Cek apakah Ollama aktif sesuai konfigurasi terpusat
        if ollama_check; then
            if [[ "${AI_ORCHESTRATOR_MODE:-false}" == "true" || "${AI_ORCHESTRATOR_MODE:-false}" == "1" ]]; then
                ORCH_SCRIPT="$(dirname "$(dirname "$BASH_SOURCE")")/ai_rag_tool/ai_orchestrator_safe.sh"
                chmod +x "$ORCH_SCRIPT" 2>/dev/null || true
                log_msg "AI" "\033[1;35m" "$target_name" "ORCHESTRATOR" "Menjalankan discovery pasif (dorking, parameter, IDOR candidate)..."
                if [[ "${AI_DORK_USE_PROXY:-${AI_PROXY_FOR_INTEL:-false}}" == "true" || "${AI_DORK_USE_PROXY:-${AI_PROXY_FOR_INTEL:-false}}" == "1" ]]; then
                    bash "$ORCH_SCRIPT" --target "$target_name" --log-dir "$target_dir" >> "$target_dir/scan.log" 2>&1 || true
                else
                    env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy \
                        bash "$ORCH_SCRIPT" --target "$target_name" --log-dir "$target_dir" >> "$target_dir/scan.log" 2>&1 || true
                fi
            fi

            # Menggunakan skrip BASH agar terhindar dari masalah modul Python!
            AI_SCRIPT="$(dirname "$(dirname "$BASH_SOURCE")")/ai_rag_tool/autonomous_pentester.sh"
            chmod +x "$AI_SCRIPT" 2>/dev/null || true
            
            # Kita gunakan file log target agar AI bisa menyimpan analisanya
            TARGET_LOG="$target_dir/scan.log"
            AI_RESULT_FILE="$target_dir/vulnerabilities/ai_recommendation.txt"
            : > "$AI_RESULT_FILE"
            echo -e "\n[🤖] Menyerahkan hasil scan ke AI Agent untuk dianalisis dan dieksploitasi..." | tee -a "$TARGET_LOG"
            
            # Eksekusi AI versi BASH dan tampilkan langsung di terminal sambil mencatat di log
            if [[ "${AI_PROXY_FOR_INTEL:-false}" == "true" || "${AI_PROXY_FOR_INTEL:-false}" == "1" ]]; then
                bash "$AI_SCRIPT" \
                    --target "$target_name" \
                    --log-dir "$target_dir" \
                    --plan-file "$target_dir/vulnerabilities/ai_attack_graph.json" \
                    --model "${OLLAMA_MODEL:-deepseek-r1:8b}" \
                    --host "${OLLAMA_HOST:-http://localhost:11434}" | tee -a "$TARGET_LOG" "$AI_RESULT_FILE"
            else
                env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy \
                    bash "$AI_SCRIPT" \
                    --target "$target_name" \
                    --log-dir "$target_dir" \
                    --plan-file "$target_dir/vulnerabilities/ai_attack_graph.json" \
                    --model "${OLLAMA_MODEL:-deepseek-r1:8b}" \
                    --host "${OLLAMA_HOST:-http://localhost:11434}" | tee -a "$TARGET_LOG" "$AI_RESULT_FILE"
            fi

            ai_exit=${PIPESTATUS[0]}
            if [[ $ai_exit -eq 0 ]]; then
                log_msg "🤖" "\033[1;35m" "$target_name" "AI AGENT" "Analisis AI selesai."
            else
                log_msg "!" "\033[1;31m" "$target_name" "AI AGENT" "Analisis AI gagal (exit $ai_exit). Periksa log AI."
            fi

            # --- FASE 4: AI TERMINAL OVERLORD (EXPLOSIVE DYNAMIC CONTROL) ---
            if [[ "${AI_ENABLE_OVERLORD:-false}" == "true" || "${AI_ENABLE_OVERLORD:-false}" == "1" ]]; then
                log_msg "🔥" "\033[1;31m" "$target_name" "OVERLORD" "Memasuki Fase 4: AI Terminal Overlord (Kontrol Penuh Dinamis)!"
                OVERLORD_SCRIPT="$(dirname "$(dirname "$BASH_SOURCE")")/ai_rag_tool/ai_terminal_overlord.sh"
                chmod +x "$OVERLORD_SCRIPT" 2>/dev/null || true
                
                # Biarkan AI Overlord mengambil alih terminal sementara waktu
                # Tambahkan tee agar output muncul di terminal dan juga tersimpan di TARGET_LOG
                bash "$OVERLORD_SCRIPT" --target "$target_name" --log-dir "$target_dir" 2>&1 | tee -a "$TARGET_LOG" || true
                log_msg "🏁" "\033[1;32m" "$target_name" "OVERLORD" "Fase 4: Overlord selesai. Menyerahkan kembali kendali ke sistem."
            fi
        else
            log_msg "!" "\033[1;31m" "$target_name" "AI AGENT" "Ollama tidak aktif (${OLLAMA_HOST:-http://localhost:11434}). AI dilewati."
        fi
    fi
done

if [[ -s "$GLOBAL_AUDIT_JSONL" ]]; then
    jq -s '.' "$GLOBAL_AUDIT_JSONL" > "$GLOBAL_AUDIT_JSON" || echo "[]" > "$GLOBAL_AUDIT_JSON"
else
    echo "[]" > "$GLOBAL_AUDIT_JSON"
fi

if [[ $TOTAL_CONFIRMED_BUGS -gt 0 ]]; then
    gum style --foreground 46 --border normal --border-foreground 46 --padding "0 2" "🎯 Automated Auditing Complete! $TOTAL_CONFIRMED_BUGS valid bugs confirmed."
else
    gum style --foreground 240 --border normal --border-foreground 240 --padding "0 2" "🛡️ Automated Auditing Complete! No high/critical bugs passed verification."
fi

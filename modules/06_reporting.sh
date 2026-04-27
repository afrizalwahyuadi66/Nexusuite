# ==============================================================================
# Centralized Report Generation
# ==============================================================================

set +e

REPORT_DIR="$OUTPUT_BASE/report"
mkdir -p "$REPORT_DIR"

gum style --margin "1 0" --foreground 212 "## 📊 Generating Report..."

write_section() { echo -e "\n\n### $1 ###\n" >> "$REPORT_DIR/full_report.txt"; }

# Helper function to reliably extract domain name from any deep path
get_domain() { echo "$1" | awk -F'/targets/' '{print $2}' | cut -d'/' -f1; }

{
    echo "OWASP SCAN REPORT - $(date)"
    echo "======================================="
} > "$REPORT_DIR/full_report.txt"

# 1. Subdomains enumerated
write_section "ENUMERATED SUBDOMAINS"
if [[ -f "$OUTPUT_BASE/all_subdomains.txt" ]]; then
    cat "$OUTPUT_BASE/all_subdomains.txt" >> "$REPORT_DIR/full_report.txt"
    echo "Total: $(wc -l < "$OUTPUT_BASE/all_subdomains.txt") subdomains" >> "$REPORT_DIR/full_report.txt"
else
    find "$OUTPUT_BASE/targets" -name "subfinder.txt" -type f -exec cat {} \; 2>/dev/null | sort -u >> "$REPORT_DIR/full_report.txt"
fi

# 2. Alive hosts
write_section "ALIVE HOSTS"
if [[ -f "$OUTPUT_BASE/alive_hosts.txt" ]]; then
    cat "$OUTPUT_BASE/alive_hosts.txt" >> "$REPORT_DIR/full_report.txt"
    echo "Total: $(wc -l < "$OUTPUT_BASE/alive_hosts.txt") alive hosts" >> "$REPORT_DIR/full_report.txt"
else
    find "$OUTPUT_BASE/targets" -name "alive.txt" -type f -exec cat {} \; 2>/dev/null | sort -u >> "$REPORT_DIR/full_report.txt"
fi

# 2.5 WAF Fingerprinting (wafw00f)
write_section "WAF FINGERPRINTING"
WAF_SUMMARY="$REPORT_DIR/waf_summary.txt"
: > "$WAF_SUMMARY"
find "$OUTPUT_BASE/targets" -name "waf.txt" -type f 2>/dev/null | while read -r wfile; do
    domain_name=$(get_domain "$wfile")
    grep -iE "is behind|No WAF detected" "$wfile" 2>/dev/null | while read -r line; do
        echo "[$domain_name] $line" >> "$WAF_SUMMARY"
    done
done
if [[ -s "$WAF_SUMMARY" ]]; then
    echo "WAF Fingerprints:" | tee -a "$REPORT_DIR/full_report.txt"
    cat "$WAF_SUMMARY" >> "$REPORT_DIR/full_report.txt"
else
    echo "No WAF Fingerprints available." >> "$REPORT_DIR/full_report.txt"
fi

# 3. Interesting URLs (dari all_urls.txt yang sudah difilter)
write_section "INTERESTING URLS (with parameters / script extensions, status 200)"
INTERESTING_URLS="$REPORT_DIR/interesting_urls.txt"
: > "$INTERESTING_URLS"
find "$OUTPUT_BASE/targets" -name "all_urls.txt" -type f 2>/dev/null | while read -r urlfile; do
    domain_name=$(get_domain "$urlfile")
    grep -E '(\?|=|\.php|\.asp|\.aspx|\.jsp|\.cgi|\.pl|\.py)' "$urlfile" 2>/dev/null | \
        grep -viE '\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|pdf|zip|tar|gz|mp4|mp3|webm|txt|xml|json)(\?|$)' | \
        while read -r line; do echo "[$domain_name] $line"; done || true
done | sort -u > "$INTERESTING_URLS"

if [[ -s "$INTERESTING_URLS" ]]; then
    echo "Found $(wc -l < "$INTERESTING_URLS") interesting URLs." | tee -a "$REPORT_DIR/full_report.txt"
    cat "$INTERESTING_URLS" >> "$REPORT_DIR/full_report.txt"
else
    echo "No interesting URLs found." >> "$REPORT_DIR/full_report.txt"
fi

# 4. SQLMap findings
write_section "SQL INJECTION FINDINGS"
SQLMAP_FINDINGS="$REPORT_DIR/sqlmap_vulns.txt"
: > "$SQLMAP_FINDINGS"
find "$OUTPUT_BASE/targets" -path "*/vulnerabilities/sqlmap/*/log" -type f 2>/dev/null | while read -r logfile; do
    domain_name=$(get_domain "$logfile")
    if grep -q "\[CRITICAL\]" "$logfile" 2>/dev/null || grep -q "vulnerable" "$logfile" 2>/dev/null; then
        echo "--- $domain_name ---" >> "$SQLMAP_FINDINGS"
        grep -E "Parameter:|Type:|Title:|Payload:|\[CRITICAL\]|database:" "$logfile" | head -20 >> "$SQLMAP_FINDINGS"
        echo "" >> "$SQLMAP_FINDINGS"
    fi
done
find "$OUTPUT_BASE/targets" -path "*/vulnerabilities/sqlmap/*/target.txt" -type f 2>/dev/null | while read -r targetfile; do
    domain_name=$(get_domain "$targetfile")
    echo "--- $domain_name (confirmed) ---" >> "$SQLMAP_FINDINGS"
    cat "$targetfile" >> "$SQLMAP_FINDINGS"
    echo "" >> "$SQLMAP_FINDINGS"
done
if [[ -s "$SQLMAP_FINDINGS" ]]; then
    echo "SQL injection vulnerabilities found!" | tee -a "$REPORT_DIR/full_report.txt"
    cat "$SQLMAP_FINDINGS" >> "$REPORT_DIR/full_report.txt"
else
    echo "No SQL injection vulnerabilities detected." >> "$REPORT_DIR/full_report.txt"
fi

# 5. Nuclei (Medium+)
write_section "NUCLEI VULNERABILITIES (Medium+ Severity)"
NUCLEI_FINDINGS="$REPORT_DIR/nuclei_vulns.txt"
: > "$NUCLEI_FINDINGS"
find "$OUTPUT_BASE/targets" -name "nuclei.txt" -type f 2>/dev/null | while read -r nfile; do
    domain_name=$(get_domain "$nfile")
    grep -iE '\[(medium|high|critical)\]' "$nfile" 2>/dev/null | while read -r line; do
        echo "[$domain_name] $line"
    done
done | sort -u > "$NUCLEI_FINDINGS"
if [[ -s "$NUCLEI_FINDINGS" ]]; then
    echo "Nuclei found $(wc -l < "$NUCLEI_FINDINGS") medium+ issues." | tee -a "$REPORT_DIR/full_report.txt"
    cat "$NUCLEI_FINDINGS" >> "$REPORT_DIR/full_report.txt"
else
    echo "No medium+ severity Nuclei findings." >> "$REPORT_DIR/full_report.txt"
fi

# 6. XSS (Dalfox)
write_section "XSS VULNERABILITIES (Dalfox)"
DALFOX_FINDINGS="$REPORT_DIR/xss_vulns.txt"
: > "$DALFOX_FINDINGS"
find "$OUTPUT_BASE/targets" -name "xss.txt" -type f 2>/dev/null | while read -r xfile; do
    domain_name=$(get_domain "$xfile")
    if [[ -s "$xfile" ]]; then
        echo "--- $domain_name ---" >> "$DALFOX_FINDINGS"
        cat "$xfile" >> "$DALFOX_FINDINGS"
        echo "" >> "$DALFOX_FINDINGS"
    fi
done
if [[ -s "$DALFOX_FINDINGS" ]]; then
    echo "XSS vulnerabilities found!" | tee -a "$REPORT_DIR/full_report.txt"
    cat "$DALFOX_FINDINGS" >> "$REPORT_DIR/full_report.txt"
else
    echo "No XSS vulnerabilities detected." >> "$REPORT_DIR/full_report.txt"
fi

# Wapiti findings
write_section "WAPITI INJECTION VULNERABILITIES"
WAPITI_FINDINGS="$REPORT_DIR/wapiti_vulns.txt"
: > "$WAPITI_FINDINGS"
find "$OUTPUT_BASE/targets" -name "wapiti_*.txt" -type f 2>/dev/null | while read -r wfile; do
    domain_name=$(get_domain "$wfile")
    if grep -qi "Vulnerability" "$wfile" 2>/dev/null || grep -q "\[+\]" "$wfile" 2>/dev/null; then
        echo "--- $domain_name ---" >> "$WAPITI_FINDINGS"
        grep -E "\[\+\]" "$wfile" | head -20 >> "$WAPITI_FINDINGS"
        echo "" >> "$WAPITI_FINDINGS"
    fi
done
if [[ -s "$WAPITI_FINDINGS" ]]; then
    echo "Wapiti injection vulnerabilities found!" | tee -a "$REPORT_DIR/full_report.txt"
    cat "$WAPITI_FINDINGS" >> "$REPORT_DIR/full_report.txt"
else
    echo "No Wapiti vulnerabilities detected." >> "$REPORT_DIR/full_report.txt"
fi

# 7. Nmap vuln scripts
write_section "NMAP VULNERABILITY SCRIPT RESULTS"
NMAP_VULN="$REPORT_DIR/nmap_vulns.txt"
: > "$NMAP_VULN"
find "$OUTPUT_BASE/targets" -name "nmap.nmap" -type f 2>/dev/null | while read -r nmapfile; do
    domain_name=$(get_domain "$nmapfile")
    grep -iE "VULNERABLE|EXPLOIT|vulners:|CVE-[0-9]{4}-[0-9]+" "$nmapfile" 2>/dev/null | while read -r line; do
        # Membersihkan format dari spasi kosong dan karakter pipe (|)
        clean_line=$(echo "$line" | sed 's/^[|[:space:]]*//')
        echo "[$domain_name] $clean_line"
    done
done | sort -u > "$NMAP_VULN"
if [[ -s "$NMAP_VULN" ]]; then
    echo "Nmap vulnerability script findings:" | tee -a "$REPORT_DIR/full_report.txt"
    cat "$NMAP_VULN" >> "$REPORT_DIR/full_report.txt"
else
    echo "No Nmap script vulnerability findings." >> "$REPORT_DIR/full_report.txt"
fi

# 8. Arjun parameters
write_section "ARJUN PARAMETER DISCOVERY"
ARJUN_FINDINGS="$REPORT_DIR/arjun_params.txt"
: > "$ARJUN_FINDINGS"
find "$OUTPUT_BASE/targets" -name "params.txt" -type f 2>/dev/null | while read -r pfile; do
    domain_name=$(get_domain "$pfile")
    if [[ -s "$pfile" ]]; then
        echo "--- $domain_name ---" >> "$ARJUN_FINDINGS"
        cat "$pfile" >> "$ARJUN_FINDINGS"
        echo "" >> "$ARJUN_FINDINGS"
    fi
done
if [[ -s "$ARJUN_FINDINGS" ]]; then
    echo "Arjun discovered parameters:" | tee -a "$REPORT_DIR/full_report.txt"
    cat "$ARJUN_FINDINGS" >> "$REPORT_DIR/full_report.txt"
fi

# 9. Nikto findings (summary)
write_section "NIKTO FINDINGS (Summary)"
NIKTO_SUMMARY="$REPORT_DIR/nikto_summary.txt"
: > "$NIKTO_SUMMARY"
find "$OUTPUT_BASE/targets" -name "nikto_*.txt" -type f 2>/dev/null | while read -r nfile; do
    domain_name=$(get_domain "$nfile")
    echo "--- $domain_name ($(basename "$nfile")) ---" >> "$NIKTO_SUMMARY"
    grep -E "^\+" "$nfile" 2>/dev/null | head -20 >> "$NIKTO_SUMMARY"
    echo "" >> "$NIKTO_SUMMARY"
done
if [[ -s "$NIKTO_SUMMARY" ]]; then
    echo "Nikto findings (first 20 lines per target):" | tee -a "$REPORT_DIR/full_report.txt"
    cat "$NIKTO_SUMMARY" >> "$REPORT_DIR/full_report.txt"
fi

# 10. FFUF Directory Fuzzing
write_section "FFUF DIRECTORY DISCOVERY"
FFUF_SUMMARY="$REPORT_DIR/ffuf_summary.txt"
: > "$FFUF_SUMMARY"
find "$OUTPUT_BASE/targets" -name "ffuf_*.json" -type f 2>/dev/null | while read -r ffile; do
    domain_name=$(get_domain "$ffile")
    if jq -e '.results | length > 0' "$ffile" > /dev/null 2>&1; then
        echo "--- $domain_name ---" >> "$FFUF_SUMMARY"
        jq -r '.results[] | "[\(.status)] \(.url)"' "$ffile" >> "$FFUF_SUMMARY"
        echo "" >> "$FFUF_SUMMARY"
    fi
done
if [[ -s "$FFUF_SUMMARY" ]]; then
    echo "FFUF found hidden endpoints/directories:" | tee -a "$REPORT_DIR/full_report.txt"
    cat "$FFUF_SUMMARY" >> "$REPORT_DIR/full_report.txt"
fi

# 11. AI Recommendations
write_section "AI RECOMMENDATIONS"
AI_RECOMMENDATIONS="$REPORT_DIR/ai_recommendations.txt"
: > "$AI_RECOMMENDATIONS"
find "$OUTPUT_BASE/targets" -name "ai_recommendation.txt" -type f 2>/dev/null | while read -r afile; do
    domain_name=$(get_domain "$afile")
    if [[ -s "$afile" ]]; then
        echo "--- $domain_name ---" >> "$AI_RECOMMENDATIONS"
        cat "$afile" >> "$AI_RECOMMENDATIONS"
        echo "" >> "$AI_RECOMMENDATIONS"
    fi
done
if [[ -s "$AI_RECOMMENDATIONS" ]]; then
    echo "AI recommendations generated for $(grep -c '^--- ' "$AI_RECOMMENDATIONS") target(s)." | tee -a "$REPORT_DIR/full_report.txt"
    cat "$AI_RECOMMENDATIONS" >> "$REPORT_DIR/full_report.txt"
else
    echo "No AI recommendation output available." >> "$REPORT_DIR/full_report.txt"
fi

# 11.1 AI Attack Graph (post-vulnerability planning)
write_section "AI ATTACK GRAPH (POST-VULNERABILITY PLAN)"
AI_ATTACK_GRAPH_SUMMARY="$REPORT_DIR/ai_attack_graph_summary.txt"
: > "$AI_ATTACK_GRAPH_SUMMARY"
find "$OUTPUT_BASE/targets" -name "ai_attack_graph.txt" -type f 2>/dev/null | while read -r gfile; do
    domain_name=$(get_domain "$gfile")
    echo "--- $domain_name ---" >> "$AI_ATTACK_GRAPH_SUMMARY"
    cat "$gfile" >> "$AI_ATTACK_GRAPH_SUMMARY"
    echo "" >> "$AI_ATTACK_GRAPH_SUMMARY"
done
if [[ -s "$AI_ATTACK_GRAPH_SUMMARY" ]]; then
    cat "$AI_ATTACK_GRAPH_SUMMARY" >> "$REPORT_DIR/full_report.txt"
else
    echo "No AI attack graph output available." >> "$REPORT_DIR/full_report.txt"
fi

# 11.2 Dorking Intelligence
write_section "AI DORKING INTELLIGENCE"
AI_DORKING_SUMMARY="$REPORT_DIR/ai_dorking_summary.txt"
: > "$AI_DORKING_SUMMARY"
find "$OUTPUT_BASE/targets" -path "*/recon/ai_orchestrator/summary.txt" -type f 2>/dev/null | while read -r sfile; do
    domain_name=$(get_domain "$sfile")
    echo "--- $domain_name ---" >> "$AI_DORKING_SUMMARY"
    cat "$sfile" >> "$AI_DORKING_SUMMARY"
    echo "" >> "$AI_DORKING_SUMMARY"
done
if [[ -s "$AI_DORKING_SUMMARY" ]]; then
    cat "$AI_DORKING_SUMMARY" >> "$REPORT_DIR/full_report.txt"
else
    echo "No AI dorking summary available." >> "$REPORT_DIR/full_report.txt"
fi

# 11.3 Campaign Memory (cross-target learning)
write_section "AI CAMPAIGN MEMORY (CROSS-TARGET LEARNING)"
AI_CAMPAIGN_MEMORY_TXT="$REPORT_DIR/ai_campaign_memory.txt"
: > "$AI_CAMPAIGN_MEMORY_TXT"
if [[ -s "$OUTPUT_BASE/ai_memory/campaign_memory.jsonl" ]]; then
    jq -r '
      "timestamp\ttarget\tcve\trisk\tpersona\tphase2_focus\ttechnique",
      (. | fromjson? // .) as $x
      | "\($x.timestamp // "NA")\t\($x.target // "NA")\t\($x.cve // "None")\t\($x.risk // "NA")\t\($x.persona // "NA")\t\($x.phase2_focus // "NA")\t\($x.technique // "NA")"
    ' "$OUTPUT_BASE/ai_memory/campaign_memory.jsonl" > "$AI_CAMPAIGN_MEMORY_TXT" 2>/dev/null || true
fi
if [[ -s "$AI_CAMPAIGN_MEMORY_TXT" ]]; then
    cat "$AI_CAMPAIGN_MEMORY_TXT" >> "$REPORT_DIR/full_report.txt"
else
    echo "No campaign memory entries yet." >> "$REPORT_DIR/full_report.txt"
fi

# 11.5 Confidence Scoring & Dedup
write_section "CONFIDENCE-SCORED FINDINGS"
SCORED_SUMMARY="$REPORT_DIR/scored_findings_summary.tsv"
DEDUP_SUMMARY="$REPORT_DIR/dedup_findings_summary.txt"
: > "$SCORED_SUMMARY"
: > "$DEDUP_SUMMARY"
echo -e "target\tscore\tsource\tfinding" >> "$SCORED_SUMMARY"
find "$OUTPUT_BASE/targets" -name "scored_findings.tsv" -type f 2>/dev/null | while read -r sfile; do
    domain_name=$(get_domain "$sfile")
    awk -F'\t' -v t="$domain_name" 'NR>1 {print t "\t" $0}' "$sfile" >> "$SCORED_SUMMARY"
done
if [[ -s "$SCORED_SUMMARY" ]]; then
    tmp_scored="$(mktemp)"
    {
        head -n 1 "$SCORED_SUMMARY"
        tail -n +2 "$SCORED_SUMMARY" | sort -t$'\t' -k2,2nr
    } > "$tmp_scored"
    mv "$tmp_scored" "$SCORED_SUMMARY"
    cat "$SCORED_SUMMARY" >> "$REPORT_DIR/full_report.txt"
fi
find "$OUTPUT_BASE/targets" -name "dedup_findings.txt" -type f 2>/dev/null | while read -r dfile; do
    domain_name=$(get_domain "$dfile")
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        echo "[$domain_name] $line"
    done < "$dfile"
done | sort -u > "$DEDUP_SUMMARY"
if [[ -s "$DEDUP_SUMMARY" ]]; then
    write_section "DEDUPLICATED FINDINGS"
    cat "$DEDUP_SUMMARY" >> "$REPORT_DIR/full_report.txt"
fi

# 11.6 Baseline Profiling
write_section "BASELINE RESPONSE PROFILE"
BASELINE_SUMMARY="$REPORT_DIR/baseline_profiles.tsv"
: > "$BASELINE_SUMMARY"
echo -e "target\turl\tstatus\tserver\tcontent_type\tbody_sha256" >> "$BASELINE_SUMMARY"
find "$OUTPUT_BASE/targets" -name "baseline_profile.tsv" -type f 2>/dev/null | while read -r bfile; do
    domain_name=$(get_domain "$bfile")
    awk -F'\t' -v t="$domain_name" 'NR>1 {print t "\t" $0}' "$bfile" >> "$BASELINE_SUMMARY"
done
if [[ -s "$BASELINE_SUMMARY" ]]; then
    cat "$BASELINE_SUMMARY" >> "$REPORT_DIR/full_report.txt"
fi

# 11.7 AI Decision Timeline (raw)
write_section "AI DECISION TIMELINE"
AI_TIMELINE_TXT="$REPORT_DIR/ai_timeline.txt"
: > "$AI_TIMELINE_TXT"
find "$OUTPUT_BASE/targets" -name "ai_decisions.log" -type f 2>/dev/null | while read -r tfile; do
    domain_name=$(get_domain "$tfile")
    echo "--- $domain_name ---" >> "$AI_TIMELINE_TXT"
    cat "$tfile" >> "$AI_TIMELINE_TXT"
    echo "" >> "$AI_TIMELINE_TXT"
done
if [[ -s "$AI_TIMELINE_TXT" ]]; then
    cat "$AI_TIMELINE_TXT" >> "$REPORT_DIR/full_report.txt"
fi

# 12. Proxy Routing Audit
write_section "PROXY ROUTING AUDIT"
PROXY_AUDIT_SUMMARY="$REPORT_DIR/proxy_routing_summary.txt"
: > "$PROXY_AUDIT_SUMMARY"
find "$OUTPUT_BASE/targets" -name "proxy_report.txt" -type f 2>/dev/null | while read -r pfile; do
    domain_name=$(get_domain "$pfile")
    if [[ -s "$pfile" ]]; then
        echo "--- $domain_name ---" >> "$PROXY_AUDIT_SUMMARY"
        cat "$pfile" >> "$PROXY_AUDIT_SUMMARY"
        echo "" >> "$PROXY_AUDIT_SUMMARY"
    fi
done
if [[ -s "$PROXY_AUDIT_SUMMARY" ]]; then
    echo "Proxy routing audit generated for $(grep -c '^--- ' "$PROXY_AUDIT_SUMMARY") target(s)." | tee -a "$REPORT_DIR/full_report.txt"
    cat "$PROXY_AUDIT_SUMMARY" >> "$REPORT_DIR/full_report.txt"
else
    echo "No proxy routing audit output available." >> "$REPORT_DIR/full_report.txt"
fi

# 13. Output Navigator (human-readable path map)
OUTPUT_NAV_FILE="$OUTPUT_BASE/README_OUTPUT.txt"
TARGETS_NAV_FILE="$REPORT_DIR/targets_navigator.txt"
FILE_MAP_CSV="$REPORT_DIR/file_map.csv"

{
    echo "target,key,path,status"
} > "$FILE_MAP_CSV"

{
    echo "TARGETS NAVIGATOR"
    echo "================="
    echo "Generated: $(date)"
    echo ""
} > "$TARGETS_NAV_FILE"

for target_dir in "$OUTPUT_BASE/targets/"*; do
    [[ -d "$target_dir" ]] || continue
    domain_name=$(basename "$target_dir")
    {
        echo "[$domain_name]"
        [[ -f "$target_dir/README_TARGET.txt" ]] && echo "- Navigator          : targets/$domain_name/README_TARGET.txt"
        [[ -f "$target_dir/recon/alive.txt" ]] && echo "- Alive Hosts        : targets/$domain_name/recon/alive.txt"
        [[ -f "$target_dir/recon/all_urls.txt" ]] && echo "- All URLs           : targets/$domain_name/recon/all_urls.txt"
        [[ -f "$target_dir/vulnerabilities/nuclei.txt" ]] && echo "- Nuclei             : targets/$domain_name/vulnerabilities/nuclei.txt"
        [[ -f "$target_dir/vulnerabilities/xss.txt" ]] && echo "- Dalfox XSS         : targets/$domain_name/vulnerabilities/xss.txt"
        [[ -f "$target_dir/proxy_report.txt" ]] && echo "- Proxy Audit        : targets/$domain_name/proxy_report.txt"
        [[ -f "$target_dir/scan.log" ]] && echo "- Scan Log           : targets/$domain_name/scan.log"
        echo ""
    } >> "$TARGETS_NAV_FILE"

    for item in \
        "navigator|$target_dir/README_TARGET.txt" \
        "alive_hosts|$target_dir/recon/alive.txt" \
        "all_urls|$target_dir/recon/all_urls.txt" \
        "nuclei|$target_dir/vulnerabilities/nuclei.txt" \
        "xss|$target_dir/vulnerabilities/xss.txt" \
        "proxy_audit|$target_dir/proxy_report.txt" \
        "scan_log|$target_dir/scan.log"; do
        key="${item%%|*}"
        path_abs="${item#*|}"
        path_rel="${path_abs#$OUTPUT_BASE/}"
        if [[ -f "$path_abs" ]]; then
            echo "$domain_name,$key,$path_rel,available" >> "$FILE_MAP_CSV"
        else
            echo "$domain_name,$key,$path_rel,missing" >> "$FILE_MAP_CSV"
        fi
    done
done

{
    echo "NEXUSUITE OUTPUT NAVIGATOR"
    echo "=========================="
    echo "Generated      : $(date)"
    echo "Session Folder : $OUTPUT_BASE"
    echo ""
    echo "[Start Here]"
    echo "- Main Summary (Text)  : report/full_report.txt"
    echo "- Dashboard (HTML)     : report/index.html"
    echo "- Findings Snapshot    : report/interesting_urls.txt"
    echo ""
    echo "[Audit & Intelligence]"
    echo "- Proxy Audit Summary  : report/proxy_routing_summary.txt"
    echo "- AI Recommendations   : report/ai_recommendations.txt"
    echo "- AI Attack Graph      : report/ai_attack_graph_summary.txt"
    echo "- AI Dorking Intel     : report/ai_dorking_summary.txt"
    echo "- AI Campaign Memory   : report/ai_campaign_memory.txt"
    echo ""
    echo "[Target Navigation]"
    echo "- Per-target quick map : report/targets_navigator.txt"
    echo "- Machine-readable map : report/file_map.csv"
    echo "- Per-target readme    : targets/<target>/README_TARGET.txt"
    echo ""
    echo "[Runtime]"
    echo "- Global log           : scan.log"
    echo "- Failed tasks         : failed_tasks.txt"
    echo "- Completed targets    : completed_targets.txt"
} > "$OUTPUT_NAV_FILE"

# --- Summary ---
gum format -- "## ✅ Report saved to: \`$REPORT_DIR\`"
if [[ -f "$OUTPUT_BASE/all_subdomains.txt" ]]; then
    TOTAL_SUBS=$(wc -l < "$OUTPUT_BASE/all_subdomains.txt")
else
    TOTAL_SUBS="N/A"
fi
if [[ -f "$OUTPUT_BASE/alive_hosts.txt" ]]; then
    TOTAL_ALIVE=$(wc -l < "$OUTPUT_BASE/alive_hosts.txt")
else
    TOTAL_ALIVE="N/A"
fi

gum style --margin "1 0" --foreground 240 "$(cat <<EOF
📊 Summary of Findings:
- Subdomains enumerated: $TOTAL_SUBS
- Alive hosts: $TOTAL_ALIVE
- Interesting URLs: $(wc -l < "$INTERESTING_URLS" 2>/dev/null || echo 0)
- SQL Injection: $(grep -c "---" "$SQLMAP_FINDINGS" 2>/dev/null || echo 0) domain(s) affected
- Wapiti (Injections): $(grep -c "---" "$WAPITI_FINDINGS" 2>/dev/null || echo 0) domain(s) affected
- Nuclei (M/H/C): $(wc -l < "$NUCLEI_FINDINGS" 2>/dev/null || echo 0) issues
- XSS: $(grep -c "---" "$DALFOX_FINDINGS" 2>/dev/null || echo 0) domain(s) affected
- Nmap vulns: $(wc -l < "$NMAP_VULN" 2>/dev/null || echo 0) findings
- AI Recommendations: $(grep -c "^---" "$AI_RECOMMENDATIONS" 2>/dev/null || echo 0) target(s)
- AI Attack Graph: $(grep -c "^---" "$AI_ATTACK_GRAPH_SUMMARY" 2>/dev/null || echo 0) target(s)
- AI Dorking Intel: $(grep -c "^---" "$AI_DORKING_SUMMARY" 2>/dev/null || echo 0) target(s)
- Proxy Audit: $(grep -c "^---" "$PROXY_AUDIT_SUMMARY" 2>/dev/null || echo 0) target(s)
- Confirmed/Audited Bugs: ${TOTAL_CONFIRMED_BUGS:-0}
- Output Navigator: README_OUTPUT.txt + report/targets_navigator.txt
EOF
)"

# ==============================================================================
# TERMINAL HIGHLIGHTS
# ==============================================================================
gum style --margin "1 0" --foreground 212 "## 🚨 Critical Findings Highlights"

found_critical=0

if [[ -s "$SQLMAP_FINDINGS" ]]; then
    gum style --foreground 196 "🔴 SQL Injection Found:"
    head -n 15 "$SQLMAP_FINDINGS" | while read -r line; do gum style --foreground 204 "  $line"; done
    [[ $(wc -l < "$SQLMAP_FINDINGS") -gt 15 ]] && gum style --foreground 240 "  ... and more (see full report)"
    echo ""
    found_critical=1
fi

if [[ -s "$WAPITI_FINDINGS" ]]; then
    gum style --foreground 196 "🔴 Wapiti Injections Found:"
    head -n 15 "$WAPITI_FINDINGS" | while read -r line; do gum style --foreground 204 "  $line"; done
    [[ $(wc -l < "$WAPITI_FINDINGS") -gt 15 ]] && gum style --foreground 240 "  ... and more (see full report)"
    echo ""
    found_critical=1
fi

if [[ -s "$DALFOX_FINDINGS" ]]; then
    gum style --foreground 208 "🟠 XSS Vulnerabilities Found (Dalfox):"
    head -n 15 "$DALFOX_FINDINGS" | while read -r line; do gum style --foreground 214 "  $line"; done
    [[ $(wc -l < "$DALFOX_FINDINGS") -gt 15 ]] && gum style --foreground 240 "  ... and more (see full report)"
    echo ""
    found_critical=1
fi

if [[ -s "$NUCLEI_FINDINGS" ]]; then
    gum style --foreground 220 "🟡 Nuclei Findings (Medium+):"
    head -n 15 "$NUCLEI_FINDINGS" | while read -r line; do gum style --foreground 226 "  $line"; done
    [[ $(wc -l < "$NUCLEI_FINDINGS") -gt 15 ]] && gum style --foreground 240 "  ... and more (see full report)"
    echo ""
    found_critical=1
fi

if [[ $found_critical -eq 0 ]]; then
    gum style --foreground 46 "🟢 No critical vulnerabilities (SQLi, Wapiti, XSS, Nuclei M+) detected in this scan."
    echo ""
fi

gum style --border double --align center --width 70 --margin "1" --padding "1 2" \
    --foreground 212 "✅ Scan Complete!"
gum format -- "# 📁 Results saved in: \`$OUTPUT_BASE\`"
gum format -- "- Batch summary: \`batch_summary.txt\`"
gum format -- "- Report directory: \`$REPORT_DIR\`"
gum format -- "- HTML Dashboard: \`$REPORT_DIR/index.html\`"
gum format -- "- Output Navigator: \`$OUTPUT_NAV_FILE\`"

if command -v tree &> /dev/null; then
    gum style --foreground 240 "$(tree -L 2 "$OUTPUT_BASE" | head -n 20)"
else
    gum style --foreground 240 "$(ls -la "$OUTPUT_BASE")"
fi

# ==============================================================================
# HTML Dashboard Generator
# ==============================================================================

set +e

REPORT_DIR="$OUTPUT_BASE/report"
HTML_FILE="$REPORT_DIR/index.html"

gum style --margin "1 0" --foreground 212 "## 🌐 Generating HTML Dashboard..."

cat << 'EOF' > "$HTML_FILE"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OWASP TUI Scanner Report</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1, h2, h3 { color: #ff79c6; }
        .card { background-color: #1e1e1e; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); border-left: 4px solid #ff79c6; }
        .critical { border-left-color: #ff5555; }
        .high { border-left-color: #ffb86c; }
        .medium { border-left-color: #f1fa8c; }
        .info { border-left-color: #8be9fd; }
        pre { background-color: #282a36; padding: 15px; border-radius: 5px; overflow-x: auto; color: #f8f8f2; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #444; }
        th { background-color: #282a36; color: #ff79c6; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
        .badge-critical { background-color: #ff5555; color: white; }
        .badge-high { background-color: #ffb86c; color: #282a36; }
        .badge-medium { background-color: #f1fa8c; color: #282a36; }
        .badge-info { background-color: #8be9fd; color: #282a36; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ OWASP TUI Scanner Dashboard</h1>
EOF

echo "<p>Generated on: $(date)</p>" >> "$HTML_FILE"

# Stats Summary
TOTAL_SUBS=$(wc -l < "$OUTPUT_BASE/all_subdomains.txt" 2>/dev/null || echo "0")
TOTAL_ALIVE=$(wc -l < "$OUTPUT_BASE/alive_hosts.txt" 2>/dev/null || echo "0")
TOTAL_SQLI=$(grep -c "---" "$REPORT_DIR/sqlmap_vulns.txt" 2>/dev/null || echo 0)
TOTAL_XSS=$(grep -c "---" "$REPORT_DIR/xss_vulns.txt" 2>/dev/null || echo 0)
TOTAL_AI=$(grep -c "^---" "$REPORT_DIR/ai_recommendations.txt" 2>/dev/null || echo 0)
TOTAL_AI_GRAPH=$(grep -c "^---" "$REPORT_DIR/ai_attack_graph_summary.txt" 2>/dev/null || echo 0)
TOTAL_DORK_INTEL=$(grep -c "^---" "$REPORT_DIR/ai_dorking_summary.txt" 2>/dev/null || echo 0)
TOTAL_PROXY_AUDIT=$(grep -c "^---" "$REPORT_DIR/proxy_routing_summary.txt" 2>/dev/null || echo 0)

cat << EOF >> "$HTML_FILE"
        <div style="display: flex; gap: 20px; margin-bottom: 20px;">
            <div class="card info" style="flex: 1;"><h3>Alive Hosts</h3><p style="font-size: 24px;">$TOTAL_ALIVE</p></div>
            <div class="card critical" style="flex: 1;"><h3>SQLi Found</h3><p style="font-size: 24px;">$TOTAL_SQLI</p></div>
            <div class="card high" style="flex: 1;"><h3>XSS Found</h3><p style="font-size: 24px;">$TOTAL_XSS</p></div>
            <div class="card medium" style="flex: 1;"><h3>AI Reports</h3><p style="font-size: 24px;">$TOTAL_AI</p></div>
            <div class="card medium" style="flex: 1;"><h3>AI Graphs</h3><p style="font-size: 24px;">$TOTAL_AI_GRAPH</p></div>
            <div class="card info" style="flex: 1;"><h3>Dork Intel</h3><p style="font-size: 24px;">$TOTAL_DORK_INTEL</p></div>
            <div class="card info" style="flex: 1;"><h3>Proxy Audits</h3><p style="font-size: 24px;">$TOTAL_PROXY_AUDIT</p></div>
        </div>
EOF

# WAF Findings
if [[ -f "$REPORT_DIR/waf_summary.txt" ]] && [[ -s "$REPORT_DIR/waf_summary.txt" ]]; then
    echo "<div class='card medium'><h2>🧱 WAF Fingerprint</h2><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/waf_summary.txt" >> "$HTML_FILE"
    echo "</pre></div>" >> "$HTML_FILE"
fi

# Nuclei Findings
if [[ -f "$REPORT_DIR/nuclei_vulns.txt" ]] && [[ -s "$REPORT_DIR/nuclei_vulns.txt" ]]; then
    echo "<div class='card critical'><h2>☢️ Nuclei Findings (Medium+)</h2><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/nuclei_vulns.txt" >> "$HTML_FILE"
    echo "</pre></div>" >> "$HTML_FILE"
fi

# SQLMap Findings
if [[ -f "$REPORT_DIR/sqlmap_vulns.txt" ]] && [[ -s "$REPORT_DIR/sqlmap_vulns.txt" ]]; then
    echo "<div class='card critical'><h2>💉 SQL Injection Findings</h2><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/sqlmap_vulns.txt" >> "$HTML_FILE"
    echo "</pre></div>" >> "$HTML_FILE"
fi

# XSS Findings
if [[ -f "$REPORT_DIR/xss_vulns.txt" ]] && [[ -s "$REPORT_DIR/xss_vulns.txt" ]]; then
    echo "<div class='card high'><h2>💥 XSS Findings (Dalfox)</h2><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/xss_vulns.txt" >> "$HTML_FILE"
    echo "</pre></div>" >> "$HTML_FILE"
fi

# Nmap Findings
if [[ -f "$REPORT_DIR/nmap_vulns.txt" ]] && [[ -s "$REPORT_DIR/nmap_vulns.txt" ]]; then
    echo "<div class='card medium'><h2>🗺️ Nmap Vulnerability Scripts</h2><pre>" >> "$HTML_FILE"
    # Use tr and awk to escape html safely across environments
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/nmap_vulns.txt" >> "$HTML_FILE"
    echo "</pre></div>" >> "$HTML_FILE"
fi

# FFUF Findings
if [[ -f "$REPORT_DIR/ffuf_summary.txt" ]] && [[ -s "$REPORT_DIR/ffuf_summary.txt" ]]; then
    echo "<div class='card info'><h2>📂 Directory/File Discovery (FFUF)</h2><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/ffuf_summary.txt" >> "$HTML_FILE"
    echo "</pre></div>" >> "$HTML_FILE"
fi

# AI Recommendations
if [[ -f "$REPORT_DIR/ai_recommendations.txt" ]] && [[ -s "$REPORT_DIR/ai_recommendations.txt" ]]; then
    echo "<div class='card high'><h2>🤖 AI Recommendations</h2><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/ai_recommendations.txt" >> "$HTML_FILE"
    echo "</pre></div>" >> "$HTML_FILE"
fi

# AI Attack Graph
if [[ -f "$REPORT_DIR/ai_attack_graph_summary.txt" ]] && [[ -s "$REPORT_DIR/ai_attack_graph_summary.txt" ]]; then
    echo "<div class='card critical'><h2>🧠 AI Attack Graph</h2><pre>" >> "$HTML_FILE"
    awk 'NR<=220 {gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/ai_attack_graph_summary.txt" >> "$HTML_FILE"
    echo "</pre></div>" >> "$HTML_FILE"
fi

# AI Dorking Intelligence
if [[ -f "$REPORT_DIR/ai_dorking_summary.txt" ]] && [[ -s "$REPORT_DIR/ai_dorking_summary.txt" ]]; then
    echo "<div class='card info'><h2>🛰️ AI Dorking Intelligence</h2><pre>" >> "$HTML_FILE"
    awk 'NR<=220 {gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/ai_dorking_summary.txt" >> "$HTML_FILE"
    echo "</pre></div>" >> "$HTML_FILE"
fi

# AI Campaign Memory
if [[ -f "$REPORT_DIR/ai_campaign_memory.txt" ]] && [[ -s "$REPORT_DIR/ai_campaign_memory.txt" ]]; then
    echo "<div class='card medium'><h2>🧬 AI Campaign Memory</h2><pre>" >> "$HTML_FILE"
    awk 'NR<=220 {gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/ai_campaign_memory.txt" >> "$HTML_FILE"
    echo "</pre></div>" >> "$HTML_FILE"
fi

# Confidence-Scored Findings
if [[ -f "$REPORT_DIR/scored_findings_summary.tsv" ]] && [[ -s "$REPORT_DIR/scored_findings_summary.tsv" ]]; then
    echo "<div class='card critical'><h2>🎯 Confidence-Scored Findings</h2><pre>" >> "$HTML_FILE"
    awk 'NR<=120 {gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/scored_findings_summary.tsv" >> "$HTML_FILE"
    echo "</pre></div>" >> "$HTML_FILE"
fi

# Baseline Profile
if [[ -f "$REPORT_DIR/baseline_profiles.tsv" ]] && [[ -s "$REPORT_DIR/baseline_profiles.tsv" ]]; then
    echo "<div class='card info'><h2>🧪 Baseline Response Profile</h2><pre>" >> "$HTML_FILE"
    awk 'NR<=120 {gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/baseline_profiles.tsv" >> "$HTML_FILE"
    echo "</pre></div>" >> "$HTML_FILE"
fi

# AI Timeline
if [[ -f "$REPORT_DIR/ai_timeline.txt" ]] && [[ -s "$REPORT_DIR/ai_timeline.txt" ]]; then
    echo "<div class='card medium'><h2>🕒 AI Decision Timeline</h2><pre>" >> "$HTML_FILE"
    awk 'NR<=200 {gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/ai_timeline.txt" >> "$HTML_FILE"
    echo "</pre></div>" >> "$HTML_FILE"
fi

# Proxy Routing Audit
if [[ -f "$REPORT_DIR/proxy_routing_summary.txt" ]] && [[ -s "$REPORT_DIR/proxy_routing_summary.txt" ]]; then
    echo "<div class='card info'><h2>🧭 Proxy Routing Audit</h2><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/proxy_routing_summary.txt" >> "$HTML_FILE"
    echo "</pre></div>" >> "$HTML_FILE"
fi

# Footer
cat << 'EOF' >> "$HTML_FILE"
    </div>
</body>
</html>
EOF

gum style --foreground 46 "✅ HTML Dashboard created at: $HTML_FILE"

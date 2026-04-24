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

cat << EOF >> "$HTML_FILE"
        <div style="display: flex; gap: 20px; margin-bottom: 20px;">
            <div class="card info" style="flex: 1;"><h3>Alive Hosts</h3><p style="font-size: 24px;">$TOTAL_ALIVE</p></div>
            <div class="card critical" style="flex: 1;"><h3>SQLi Found</h3><p style="font-size: 24px;">$TOTAL_SQLI</p></div>
            <div class="card high" style="flex: 1;"><h3>XSS Found</h3><p style="font-size: 24px;">$TOTAL_XSS</p></div>
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

# Footer
cat << 'EOF' >> "$HTML_FILE"
    </div>
</body>
</html>
EOF

gum style --foreground 46 "✅ HTML Dashboard created at: $HTML_FILE"
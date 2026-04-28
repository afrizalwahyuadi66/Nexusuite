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
    <title>Nexusuite | Autonomous Pentest Report</title>
    <style>
        :root {
            --bg-color: #0d1117;
            --card-bg: #161b22;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --accent: #58a6ff;
            --border-color: #30363d;
            --critical: #ff7b72;
            --high: #d2a8ff;
            --medium: #f2cc60;
            --info: #3fb950;
        }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; 
            background-color: var(--bg-color); 
            color: var(--text-main); 
            margin: 0; 
            padding: 0; 
            line-height: 1.6;
        }
        .header-bar {
            background-color: var(--card-bg);
            border-bottom: 1px solid var(--border-color);
            padding: 20px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header-bar h1 {
            margin: 0;
            font-size: 24px;
            color: var(--accent);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .header-bar p { margin: 0; color: var(--text-muted); font-size: 14px; }
        .container { max-width: 1400px; margin: 30px auto; padding: 0 20px; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .stat-card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            transition: transform 0.2s ease;
        }
        .stat-card:hover { transform: translateY(-5px); border-color: var(--accent); }
        .stat-card h3 { margin: 0 0 10px 0; font-size: 14px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }
        .stat-card p { margin: 0; font-size: 32px; font-weight: bold; }
        
        .card { 
            background-color: var(--card-bg); 
            border-radius: 8px; 
            border: 1px solid var(--border-color);
            margin-bottom: 24px; 
            overflow: hidden;
        }
        .card-header {
            padding: 15px 20px;
            border-bottom: 1px solid var(--border-color);
            font-weight: 600;
            font-size: 18px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .card-body { padding: 0; }
        
        .critical .card-header { background-color: rgba(255, 123, 114, 0.1); color: var(--critical); border-bottom-color: rgba(255, 123, 114, 0.2); }
        .high .card-header { background-color: rgba(210, 168, 255, 0.1); color: var(--high); border-bottom-color: rgba(210, 168, 255, 0.2); }
        .medium .card-header { background-color: rgba(242, 204, 96, 0.1); color: var(--medium); border-bottom-color: rgba(242, 204, 96, 0.2); }
        .info .card-header { background-color: rgba(63, 185, 80, 0.1); color: var(--info); border-bottom-color: rgba(63, 185, 80, 0.2); }
        
        .stat-card.critical p { color: var(--critical); }
        .stat-card.high p { color: var(--high); }
        .stat-card.medium p { color: var(--medium); }
        .stat-card.info p { color: var(--info); }

        pre { 
            background-color: transparent; 
            margin: 0; 
            padding: 20px; 
            overflow-x: auto; 
            color: #e6edf3;
            font-family: ui-monospace, SFMono-Regular, SF Mono, Menlo, Consolas, Liberation Mono, monospace;
            font-size: 13px;
        }
        
        /* Scrollbar styling */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: var(--bg-color); }
        ::-webkit-scrollbar-thumb { background: #484f58; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #6e7681; }
    </style>
</head>
<body>
    <div class="header-bar">
        <h1>🛡️ Nexusuite AI Report</h1>
EOF

echo "<p>Generated on: $(date)</p>" >> "$HTML_FILE"
echo "</div><div class=\"container\">" >> "$HTML_FILE"

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
        <div class="stats-grid">
            <div class="stat-card info"><h3>Alive Hosts</h3><p>$TOTAL_ALIVE</p></div>
            <div class="stat-card critical"><h3>SQLi Found</h3><p>$TOTAL_SQLI</p></div>
            <div class="stat-card high"><h3>XSS Found</h3><p>$TOTAL_XSS</p></div>
            <div class="stat-card medium"><h3>AI Reports</h3><p>$TOTAL_AI</p></div>
            <div class="stat-card medium"><h3>AI Graphs</h3><p>$TOTAL_AI_GRAPH</p></div>
            <div class="stat-card info"><h3>Dork Intel</h3><p>$TOTAL_DORK_INTEL</p></div>
            <div class="stat-card info"><h3>Proxy Audits</h3><p>$TOTAL_PROXY_AUDIT</p></div>
        </div>
EOF

# WAF Findings
if [[ -f "$REPORT_DIR/waf_summary.txt" ]] && [[ -s "$REPORT_DIR/waf_summary.txt" ]]; then
    echo "<div class='card medium'><div class='card-header'>🧱 WAF Fingerprint</div><div class='card-body'><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/waf_summary.txt" >> "$HTML_FILE"
    echo "</pre></div></div>" >> "$HTML_FILE"
fi

# Nuclei Findings
if [[ -f "$REPORT_DIR/nuclei_vulns.txt" ]] && [[ -s "$REPORT_DIR/nuclei_vulns.txt" ]]; then
    echo "<div class='card critical'><div class='card-header'>☢️ Nuclei Findings (Medium+)</div><div class='card-body'><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/nuclei_vulns.txt" >> "$HTML_FILE"
    echo "</pre></div></div>" >> "$HTML_FILE"
fi

# SQLMap Findings
if [[ -f "$REPORT_DIR/sqlmap_vulns.txt" ]] && [[ -s "$REPORT_DIR/sqlmap_vulns.txt" ]]; then
    echo "<div class='card critical'><div class='card-header'>💉 SQL Injection Findings</div><div class='card-body'><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/sqlmap_vulns.txt" >> "$HTML_FILE"
    echo "</pre></div></div>" >> "$HTML_FILE"
fi

# XSS Findings
if [[ -f "$REPORT_DIR/xss_vulns.txt" ]] && [[ -s "$REPORT_DIR/xss_vulns.txt" ]]; then
    echo "<div class='card high'><div class='card-header'>💥 XSS Findings (Dalfox)</div><div class='card-body'><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/xss_vulns.txt" >> "$HTML_FILE"
    echo "</pre></div></div>" >> "$HTML_FILE"
fi

# Nmap Findings
if [[ -f "$REPORT_DIR/nmap_vulns.txt" ]] && [[ -s "$REPORT_DIR/nmap_vulns.txt" ]]; then
    echo "<div class='card medium'><div class='card-header'>🗺️ Nmap Vulnerability Scripts</div><div class='card-body'><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/nmap_vulns.txt" >> "$HTML_FILE"
    echo "</pre></div></div>" >> "$HTML_FILE"
fi

# FFUF Findings
if [[ -f "$REPORT_DIR/ffuf_summary.txt" ]] && [[ -s "$REPORT_DIR/ffuf_summary.txt" ]]; then
    echo "<div class='card info'><div class='card-header'>📂 Directory/File Discovery (FFUF)</div><div class='card-body'><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/ffuf_summary.txt" >> "$HTML_FILE"
    echo "</pre></div></div>" >> "$HTML_FILE"
fi

# AI Recommendations
if [[ -f "$REPORT_DIR/ai_recommendations.txt" ]] && [[ -s "$REPORT_DIR/ai_recommendations.txt" ]]; then
    echo "<div class='card high'><div class='card-header'>🤖 AI Recommendations</div><div class='card-body'><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/ai_recommendations.txt" >> "$HTML_FILE"
    echo "</pre></div></div>" >> "$HTML_FILE"
fi

# AI Attack Graph
if [[ -f "$REPORT_DIR/ai_attack_graph_summary.txt" ]] && [[ -s "$REPORT_DIR/ai_attack_graph_summary.txt" ]]; then
    echo "<div class='card critical'><div class='card-header'>🧠 AI Attack Graph</div><div class='card-body'><pre>" >> "$HTML_FILE"
    awk 'NR<=220 {gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/ai_attack_graph_summary.txt" >> "$HTML_FILE"
    echo "</pre></div></div>" >> "$HTML_FILE"
fi

# AI Dorking Intelligence
if [[ -f "$REPORT_DIR/ai_dorking_summary.txt" ]] && [[ -s "$REPORT_DIR/ai_dorking_summary.txt" ]]; then
    echo "<div class='card info'><div class='card-header'>🛰️ AI Dorking Intelligence</div><div class='card-body'><pre>" >> "$HTML_FILE"
    awk 'NR<=220 {gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/ai_dorking_summary.txt" >> "$HTML_FILE"
    echo "</pre></div></div>" >> "$HTML_FILE"
fi

# AI Campaign Memory
if [[ -f "$REPORT_DIR/ai_campaign_memory.txt" ]] && [[ -s "$REPORT_DIR/ai_campaign_memory.txt" ]]; then
    echo "<div class='card medium'><div class='card-header'>🧬 AI Campaign Memory</div><div class='card-body'><pre>" >> "$HTML_FILE"
    awk 'NR<=220 {gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/ai_campaign_memory.txt" >> "$HTML_FILE"
    echo "</pre></div></div>" >> "$HTML_FILE"
fi

# Confidence-Scored Findings
if [[ -f "$REPORT_DIR/scored_findings_summary.tsv" ]] && [[ -s "$REPORT_DIR/scored_findings_summary.tsv" ]]; then
    echo "<div class='card critical'><div class='card-header'>🎯 Confidence-Scored Findings</div><div class='card-body'><pre>" >> "$HTML_FILE"
    awk 'NR<=120 {gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/scored_findings_summary.tsv" >> "$HTML_FILE"
    echo "</pre></div></div>" >> "$HTML_FILE"
fi

# Baseline Profile
if [[ -f "$REPORT_DIR/baseline_profiles.tsv" ]] && [[ -s "$REPORT_DIR/baseline_profiles.tsv" ]]; then
    echo "<div class='card info'><div class='card-header'>🧪 Baseline Response Profile</div><div class='card-body'><pre>" >> "$HTML_FILE"
    awk 'NR<=120 {gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/baseline_profiles.tsv" >> "$HTML_FILE"
    echo "</pre></div></div>" >> "$HTML_FILE"
fi

# AI Timeline
if [[ -f "$REPORT_DIR/ai_timeline.txt" ]] && [[ -s "$REPORT_DIR/ai_timeline.txt" ]]; then
    echo "<div class='card medium'><div class='card-header'>🕒 AI Decision Timeline</div><div class='card-body'><pre>" >> "$HTML_FILE"
    awk 'NR<=200 {gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/ai_timeline.txt" >> "$HTML_FILE"
    echo "</pre></div></div>" >> "$HTML_FILE"
fi

# Proxy Routing Audit
if [[ -f "$REPORT_DIR/proxy_routing_summary.txt" ]] && [[ -s "$REPORT_DIR/proxy_routing_summary.txt" ]]; then
    echo "<div class='card info'><div class='card-header'>🧭 Proxy Routing Audit</div><div class='card-body'><pre>" >> "$HTML_FILE"
    awk '{gsub(/&/,"\&amp;"); gsub(/</,"\&lt;"); gsub(/>/,"\&gt;"); print}' "$REPORT_DIR/proxy_routing_summary.txt" >> "$HTML_FILE"
    echo "</pre></div></div>" >> "$HTML_FILE"
fi

# Footer
cat << 'EOF' >> "$HTML_FILE"
    </div>
</body>
</html>
EOF

gum style --foreground 46 "✅ HTML Dashboard created at: $HTML_FILE"

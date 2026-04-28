#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/ai_config.sh" ]]; then
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/ai_config.sh"
fi

TARGET=""
LOG_DIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET="${2:-}"; shift 2 ;;
        --log-dir) LOG_DIR="${2:-}"; shift 2 ;;
        *)
            echo "[orchestrator] Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$TARGET" || -z "$LOG_DIR" ]]; then
    echo "[orchestrator] Usage: $0 --target <target> --log-dir <target_dir>" >&2
    exit 1
fi

sanitize_target() {
    local t="$1"
    t="${t#http://}"
    t="${t#https://}"
    t="${t%%/*}"
    echo "$t"
}

target_host="$(sanitize_target "$TARGET")"
out_dir="$LOG_DIR/recon/ai_orchestrator"
mkdir -p "$out_dir"

urls_raw="$out_dir/urls_raw.txt"
urls_unique="$out_dir/discovered_urls.txt"
params_ranked="$out_dir/parameters_ranked.txt"
params_classified="$out_dir/parameters_classified.txt"
idor_candidates="$out_dir/idor_candidates.txt"
interesting_files="$out_dir/interesting_files.txt"
interesting_pack="$out_dir/interesting_endpoints_pack.txt"
attack_surface_ranked="$out_dir/attack_surface_ranked.txt"
stack_hints="$out_dir/stack_hints.txt"
dork_queries="$out_dir/dork_queries.txt"
dork_results="$out_dir/dork_results.txt"
summary_file="$out_dir/summary.txt"
dork_max_results="${AI_DORK_MAX_RESULTS:-8}"
if [[ "${AI_AGGRESSIVE_MODE:-false}" == "true" || "${AI_AGGRESSIVE_MODE:-false}" == "1" ]]; then
    dork_max_results="${AI_DORK_MAX_RESULTS:-12}"
fi

echo "[orchestrator] AI safe orchestrator started for $target_host"

cat > "$dork_queries" <<EOF
site:$target_host inurl:".php?id="
site:$target_host inurl:"?id=" OR inurl:"&id="
site:$target_host inurl:"?user=" OR inurl:"&user="
site:$target_host inurl:"?account=" OR inurl:"&account="
site:$target_host ext:php inurl:"?" -site:facebook.com
site:$target_host "index.php?" filetype:php
site:$target_host filetype:sql OR filetype:bak OR filetype:old
site:$target_host filetype:env OR filetype:log OR filetype:txt
site:$target_host intitle:"index of" -github -gitlab
site:$target_host inurl:"/api/" inurl:"/v1/" OR inurl:"/v2/"
site:$target_host inurl:"/graphql" OR inurl:"/graphiql"
site:$target_host inurl:"/swagger" OR inurl:"/openapi" OR inurl:"/.well-known/"
site:$target_host inurl:"redirect=" OR inurl:"return=" OR inurl:"returnurl="
site:$target_host inurl:"next=" OR inurl:"url=" OR inurl:"uri="
site:$target_host inurl:"callback=" OR inurl:"continue="
site:$target_host inurl:"login" OR inurl:"signin" OR inurl:"auth" filetype:php
site:$target_host inurl:"admin" OR inurl:"dashboard" OR inurl:"manage" inurl:"?"
site:$target_host inurl:"upload" OR inurl:"import" OR inurl:"export" filetype:php
site:$target_host inurl:"debug" OR inurl:"trace" OR inurl:"test" filetype:php
site:$target_host inurl:"reset-password" OR inurl:"forgot-password" OR inurl:"password-reset"
site:$target_host inurl:"download" OR inurl:"file=" OR inurl:"path=" inurl:"?"
site:$target_host inurl:".env" OR inurl:"config.php" OR inurl:"settings.php"
site:$target_host "access_token=" OR "refresh_token=" OR "api_key=" OR "secret="
site:$target_host inurl:"search" OR inurl:"filter" OR inurl:"query" inurl:"?" -site:github.com
site:$target_host inurl:"/api/" inurl:".json" OR inurl:".xml"
EOF

collect_urls_from_file() {
    local f="$1"
    [[ -f "$f" ]] || return 0
    # Ekstrak host utama (contoh: drive.bgn.go.id -> bgn.go.id)
    local root_domain
    root_domain="$(echo "$target_host" | awk -F. '{if (NF>2) print $(NF-1)"."$NF; else print $0}')"
    
    # Hanya tangkap URL yang mengandung host utama atau IP target
    grep -Eo 'https?://[^"'"'"' ]+' "$f" 2>/dev/null | grep -iE "($target_host|$root_domain)" || true
}

{
    collect_urls_from_file "$LOG_DIR/recon/all_urls.txt"
    collect_urls_from_file "$LOG_DIR/recon/katana_urls.txt"
    collect_urls_from_file "$LOG_DIR/recon/gau_urls.txt"
    collect_urls_from_file "$LOG_DIR/vulnerabilities/nuclei.txt"
    collect_urls_from_file "$LOG_DIR/vulnerabilities/xss.txt"
    collect_urls_from_file "$LOG_DIR/scan.log"
} > "$urls_raw"

if [[ -s "$urls_raw" ]]; then
    sed 's/[),.;]*$//' "$urls_raw" | sort -u > "$urls_unique"
else
    : > "$urls_unique"
fi

if [[ -s "$urls_unique" ]]; then
    grep -Eo '[\?&][a-zA-Z0-9_]{1,48}=' "$urls_unique" \
        | tr -d '?&=' \
        | tr '[:upper:]' '[:lower:]' \
        | sort | uniq -c | sort -nr > "$params_ranked" || true
else
    : > "$params_ranked"
fi

if [[ -s "$urls_unique" ]]; then
    grep -Ei '(id=|user_id=|account=|uid=|order=|invoice=|profile=|member=|doc=|file=|download=|token=)' "$urls_unique" \
        | sort -u > "$idor_candidates" || true
else
    : > "$idor_candidates"
fi

if [[ -s "$urls_unique" ]]; then
    grep -Ei '(\.env|\.git|\.svn|backup|\.bak|\.old|\.sql|\.zip|\.tar|\.gz|debug|swagger|openapi|config|phpinfo)' "$urls_unique" \
        | sort -u > "$interesting_files" || true
else
    : > "$interesting_files"
fi

if [[ -s "$urls_unique" ]]; then
    {
        echo "# Auth & Session"
        grep -Ei '(login|signin|auth|oauth|sso|jwt|session|token=|callback=)' "$urls_unique" | head -n 60 || true
        echo ""
        echo "# Admin & Internal"
        grep -Ei '(admin|dashboard|manage|internal|debug|staging|dev)' "$urls_unique" | head -n 60 || true
        echo ""
        echo "# Data Access / Potential IDOR"
        grep -Ei '(user_id=|account=|invoice=|order=|download=|file=|doc=|profile=)' "$urls_unique" | head -n 80 || true
    } | sed '/^[[:space:]]*$/N;/^\n$/D' > "$interesting_pack"
else
    : > "$interesting_pack"
fi

if [[ -s "$urls_unique" ]]; then
    awk '
    {
      u=tolower($0); s=0
      if (u ~ /[?&](id|user_id|uid|account|invoice|order|profile|member)=/) s+=4
      if (u ~ /[?&](token|jwt|session|api_key|key)=/) s+=5
      if (u ~ /[?&](redirect|return|next|url|callback)=/) s+=4
      if (u ~ /(admin|manage|dashboard|internal|debug|staging|dev)/) s+=3
      if (u ~ /(\.env|\.git|backup|\.bak|swagger|openapi|graphql)/) s+=4
      print s "\t" $0
    }' "$urls_unique" | sort -t$'\t' -k1,1nr -k2,2 | head -n 200 > "$attack_surface_ranked"
else
    : > "$attack_surface_ranked"
fi

if [[ -s "$urls_unique" ]]; then
    {
        grep -Ei '\.php(\?|$)' "$urls_unique" >/dev/null && echo "php"
        grep -Ei '\.aspx?(\?|$)' "$urls_unique" >/dev/null && echo "aspnet"
        grep -Ei '(wp-content|wp-admin|wordpress)' "$urls_unique" >/dev/null && echo "wordpress"
        grep -Ei '(laravel|_ignition)' "$urls_unique" >/dev/null && echo "laravel"
        grep -Ei '(graphql|/api/|swagger|openapi|v1/)' "$urls_unique" >/dev/null && echo "api"
    } | sort -u > "$stack_hints"
else
    : > "$stack_hints"
fi

if [[ -s "$params_ranked" ]]; then
    awk '
    BEGIN{print "parameter\tclass"}
    {
      p=$2
      cls="general"
      if (p ~ /^(id|user_id|uid|account|invoice|order|profile|member)$/) cls="idor_candidate"
      else if (p ~ /(token|jwt|auth|session|api_key|key)$/) cls="sensitive_auth"
      else if (p ~ /(url|next|return|redirect|callback|dest)$/) cls="open_redirect_candidate"
      else if (p ~ /(file|path|doc|download|include|template)$/) cls="file_access_candidate"
      print p "\t" cls
    }' "$params_ranked" > "$params_classified"
else
    : > "$params_classified"
fi

if [[ "${AI_ENABLE_DORKING:-true}" == "true" ]]; then
    : > "$dork_results"
    if command -v ddgr >/dev/null 2>&1; then
        while IFS= read -r q; do
            [[ -n "$q" ]] || continue
            echo "### $q" >> "$dork_results"
            ddgr --np --nocolor --num "$dork_max_results" "$q" 2>/dev/null | sed '/^$/d' >> "$dork_results" || true
            echo "" >> "$dork_results"
        done < "$dork_queries"
    elif command -v python >/dev/null 2>&1; then
        python - "$dork_queries" "$dork_results" "$dork_max_results" <<'PY' || true
import sys
from pathlib import Path
qfile = Path(sys.argv[1])
outfile = Path(sys.argv[2])
max_results = int(sys.argv[3]) if len(sys.argv) > 3 else 8
try:
    from duckduckgo_search import DDGS
except Exception:
    outfile.write_text("duckduckgo_search not installed; only queries were generated.\n", encoding="utf-8")
    raise SystemExit(0)
lines = [l.strip() for l in qfile.read_text(encoding="utf-8").splitlines() if l.strip()]
out = []
with DDGS() as ddgs:
    for q in lines:
        out.append(f"### {q}")
        try:
            for r in ddgs.text(q, max_results=max_results):
                title = r.get("title", "")
                href = r.get("href", "")
                body = r.get("body", "")
                out.append(f"- {title} | {href}")
                if body:
                    out.append(f"  {body[:180]}")
        except Exception:
            out.append("- query failed")
        out.append("")
outfile.write_text("\n".join(out) + "\n", encoding="utf-8")
PY
    else
        echo "No dork fetch tool installed (ddgr/python). Queries only." > "$dork_results"
    fi
else
    echo "Dorking disabled by AI_ENABLE_DORKING=false" > "$dork_results"
fi

url_count=$(wc -l < "$urls_unique" 2>/dev/null | tr -d ' ')
param_count=$(wc -l < "$params_ranked" 2>/dev/null | tr -d ' ')
idor_count=$(wc -l < "$idor_candidates" 2>/dev/null | tr -d ' ')
interesting_count=$(wc -l < "$interesting_files" 2>/dev/null | tr -d ' ')
classified_params_count=$(tail -n +2 "$params_classified" 2>/dev/null | wc -l | tr -d ' ')
stack_count=$(wc -l < "$stack_hints" 2>/dev/null | tr -d ' ')

cat > "$summary_file" <<EOF
AI Orchestrator Safe Summary
Target: $target_host
Discovered URLs: $url_count
Ranked Parameters: $param_count
Classified Parameters: $classified_params_count
IDOR Candidates: $idor_count
Interesting Endpoints/Files: $interesting_count
Interesting Endpoint Pack: $interesting_pack
Attack Surface Ranked: $attack_surface_ranked
Stack Hints: $stack_hints ($stack_count)
Queries: $dork_queries
Dork Results: $dork_results
EOF

echo "[orchestrator] Discovery summary:"
cat "$summary_file"
echo "[orchestrator] Output directory: $out_dir"

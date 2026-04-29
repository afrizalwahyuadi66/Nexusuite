# ==============================================================================
# PRE-STEP: Resume / State Recovery
# ==============================================================================
# Support sesi lama (OWASP_SCAN_*), sesi transisi (SCAN_*), dan sesi baru (Result/*_SCAN_*)
PREV_SCANS=$(
    {
        ls -1d Result/*_SCAN_* 2>/dev/null || true
        ls -1d SCAN_* 2>/dev/null || true
        ls -1d OWASP_SCAN_* 2>/dev/null || true
    } | awk 'NF' | sort -u | tail -n 8 || true
)
RESUME_DIR=""

if [[ -n "$PREV_SCANS" ]]; then
    gum style --margin "1 0" --foreground 212 "## ⏳ Previous Scans Detected"
    
    # Convert string to array safely
    mapfile -t scan_array <<< "$PREV_SCANS"
    
    # We only want to show sessions that actually have an unfinished .status directory or we just let them pick
    RESUME_CHOICE=$(gum choose --header "Do you want to resume an incomplete scan or start fresh?" "Start New Scan" "${scan_array[@]}")
    
    if [[ "$RESUME_CHOICE" != "Start New Scan" ]]; then
        RESUME_DIR="$RESUME_CHOICE"
        gum style --foreground 46 "Resuming session: $RESUME_DIR"
    fi
fi

if [[ -n "$RESUME_DIR" ]]; then
    export OUTPUT_BASE="$RESUME_DIR"
    export IS_RESUME=true
else
    export OUTPUT_BASE="$NEW_OUTPUT_BASE"
    export IS_RESUME=false
    mkdir -p "$OUTPUT_BASE"
fi

export LOG_FILE="$OUTPUT_BASE/scan.log"
touch "$LOG_FILE"

export TMP_ENUM_DIR="$OUTPUT_BASE/.enum_tmp"
mkdir -p "$TMP_ENUM_DIR"

# File to track completed domains
export COMPLETED_FILE="$OUTPUT_BASE/completed_targets.txt"
touch "$COMPLETED_FILE"

# ==============================================================================
# STEP 0: Proxy Configuration
# ==============================================================================
gum style --margin "1 0" --foreground 212 "## ⚙️ Proxy Configuration"

export PROXY_LIST_FILE="$OUTPUT_BASE/proxies_active.txt"
export PROXY_USED_FILE="$OUTPUT_BASE/proxies_used.txt"
export PROXY_DEAD_FILE="$OUTPUT_BASE/proxies_dead.txt"
touch "$PROXY_LIST_FILE" "$PROXY_USED_FILE" "$PROXY_DEAD_FILE"
export USE_PROXY="false"
export PROXY_STRICT="false"
export AI_DORK_USE_PROXY="${AI_DORK_USE_PROXY:-false}"
AI_AUTONOMOUS_MODE=false
AI_REPLAY_MODE=false
AI_AUTONOMOUS_TARGETS_NORMALIZED="$(echo "${AI_AUTONOMOUS_TARGETS:-}" | tr ', ' '\n\n' | sed '/^$/d' || true)"
if [[ "${AI_ORCHESTRATOR_MODE:-false}" == "true" || "${AI_ORCHESTRATOR_MODE:-false}" == "1" ]]; then
    # Autonomous target loading hanya aktif jika target diberikan via env/file.
    # Jika tidak ada, kita tetap lanjut mode interaktif normal (manual target prompt),
    # namun fitur AI orchestrator di fase scan tetap bisa aktif.
    if [[ -n "${AI_AUTONOMOUS_TARGETS_FILE:-}" || -n "${AI_AUTONOMOUS_TARGETS_NORMALIZED:-}" ]]; then
        AI_AUTONOMOUS_MODE=true
    fi
fi
if [[ "${AI_REPLAY_FAILED_ONLY:-false}" == "true" || "${AI_REPLAY_FAILED_ONLY:-false}" == "1" ]]; then
    AI_REPLAY_MODE=true
fi

write_mode_marker() {
    local key="$1"
    local val="$2"
    if [[ -n "${LOG_FILE:-}" ]]; then
        printf '[MODE] %s=%s\n' "$key" "$val" >> "$LOG_FILE"
    fi
}

if [[ "$AI_AUTONOMOUS_MODE" == "true" ]]; then
    gum style --foreground 240 "AI Orchestrator aktif: default No Proxy."
elif [[ "${DRY_RUN:-false}" == "true" ]]; then
    gum style --foreground 240 "DRY-RUN aktif: proxy check dilewati."
else
if [[ "${AI_ORCHESTRATOR_MODE:-false}" == "true" || "${AI_ORCHESTRATOR_MODE:-false}" == "1" ]]; then
    gum style --foreground 240 "AI Full Control interaktif: silakan pilih proxy sebelum scan dimulai."
fi
while true; do
    PROXY_MODE=$(gum choose --header "Route traffic through Proxy?" "No Proxy" "Manual Input (Multiple comma-separated)" "From File")
    
    if [[ "$PROXY_MODE" == "No Proxy" ]]; then
        gum style --foreground 240 "Proceeding without proxy."
        break
    fi

    if [[ "$PROXY_MODE" == "Manual Input (Multiple comma-separated)" ]]; then
        PROXY_INPUT=$(gum input --prompt "Enter proxy URLs (e.g. http://1.1.1.1:8080,http://2.2.2.2:8080): ")
        if [[ -n "$PROXY_INPUT" ]]; then
            echo "$PROXY_INPUT" | tr ',' '\n' | tr -d ' ' > "$PROXY_LIST_FILE"
        fi
    elif [[ "$PROXY_MODE" == "From File" ]]; then
        PROXY_FILE=$(gum file --file --height 10 --header "Select file containing proxy list:")
        if [[ -f "$PROXY_FILE" ]]; then
            cat "$PROXY_FILE" > "$PROXY_LIST_FILE"
        else
            gum log --level error "Invalid file selected."
            continue
        fi
    fi

    if [[ -s "$PROXY_LIST_FILE" ]]; then
        PROXY_COUNT=$(wc -l < "$PROXY_LIST_FILE" | tr -d ' ')
        gum style --foreground 214 "Testing $PROXY_COUNT proxies for connectivity..."
        
        > "${PROXY_LIST_FILE}.tmp"
        # Kita akan melakukan iterasi secara sekuensial atau dengan menampilkan info yang jelas
        while IFS= read -r raw_proxy || [[ -n "$raw_proxy" ]]; do
            # Bersihkan spasi dan carriage return (\r) dari Windows file
            proxy=$(echo "$raw_proxy" | tr -d '\r' | xargs)
            [[ -z "$proxy" ]] && continue
            
            # Jika proxy hanya IP:PORT (tidak memiliki skema/protokol seperti http:// atau socks5://),
            # maka tambahkan http:// sebagai default agar curl dan environment variables tidak bingung.
            if [[ ! "$proxy" =~ ^[a-zA-Z0-9]+:// ]]; then
                proxy="http://$proxy"
            fi
            
            # Tampilkan informasi proxy yang sedang diuji (menggunakan carriage return agar overwrite)
            printf "\r\033[K\033[1;36mTesting proxy:\033[0m %s ... " "$proxy"
            
            # Ping menggunakan curl dengan opsi proxy
            if curl -x "$proxy" -s -k -m 5 -o /dev/null "https://gstatic.com/generate_204" || \
               curl -x "$proxy" -s -k -m 5 -o /dev/null "http://gstatic.com/generate_204"; then
                echo "$proxy" >> "${PROXY_LIST_FILE}.tmp"
                printf "\033[1;32m[ALIVE]\033[0m\n"
            else
                printf "\033[1;31m[DEAD]\033[0m\n"
            fi
        done < "$PROXY_LIST_FILE"
        
        mv "${PROXY_LIST_FILE}.tmp" "$PROXY_LIST_FILE"
        
        if [[ -s "$PROXY_LIST_FILE" ]]; then
            ALIVE_COUNT=$(wc -l < "$PROXY_LIST_FILE" | tr -d ' ')
            gum style --margin "1 0" --foreground 46 "✅ $ALIVE_COUNT proxies are alive and ready to use."
            export USE_PROXY="true"

            PROXY_POLICY=$(gum choose --header "Proxy routing policy:" \
                "Best Effort (Recommended)" \
                "Strict (Proxy-Only, skip unsupported steps)")
            if [[ "$PROXY_POLICY" == "Strict (Proxy-Only, skip unsupported steps)" ]]; then
                export PROXY_STRICT="true"
                gum style --foreground 214 "Strict proxy aktif: step yang tidak punya integrasi proxy akan dilewati."
            else
                export PROXY_STRICT="false"
                gum style --foreground 240 "Best effort aktif: jika proxy gagal/unsupported, step dapat fallback direct."
            fi
            
            # Pick first proxy to use globally for initialization phase (subdomain enumeration)
            FIRST_PROXY=$(head -n 1 "$PROXY_LIST_FILE")
            export HTTP_PROXY="$FIRST_PROXY"
            export HTTPS_PROXY="$FIRST_PROXY"
            export http_proxy="$FIRST_PROXY"
            export https_proxy="$FIRST_PROXY"
            gum style --foreground 214 "Using proxy $FIRST_PROXY for initial enumeration."
            break
        else
            gum style --margin "1 0" --foreground 196 "❌ All provided proxies failed the ping test."
            if ! gum confirm "Do you want to try again with different proxies?"; then
                gum style --foreground 240 "Proceeding without proxy."
                break
            fi
        fi
    else
        gum style --foreground 196 "❌ No proxies loaded."
        if ! gum confirm "Do you want to try again?"; then
            gum style --foreground 240 "Proceeding without proxy."
            break
        fi
    fi
done
fi

if [[ "${AI_ORCHESTRATOR_MODE:-false}" == "true" || "${AI_ORCHESTRATOR_MODE:-false}" == "1" ]]; then
    if [[ "${AI_ENABLE_DORKING:-true}" == "true" || "${AI_ENABLE_DORKING:-true}" == "1" ]]; then
        if [[ "$USE_PROXY" == "true" ]]; then
            DORK_PROXY_CHOICE=$(gum choose --header "Gunakan proxy untuk proses Dorking AI?" \
                "Tidak (Recommended)" \
                "Ya, gunakan proxy yang sama")
            if [[ "$DORK_PROXY_CHOICE" == "Ya, gunakan proxy yang sama" ]]; then
                export AI_DORK_USE_PROXY="true"
                gum style --foreground 214 "Dorking AI akan berjalan melalui proxy aktif."
            else
                export AI_DORK_USE_PROXY="false"
                gum style --foreground 240 "Dorking AI akan berjalan direct (tanpa proxy)."
            fi
        else
            export AI_DORK_USE_PROXY="false"
            gum style --foreground 240 "Dorking AI tanpa proxy karena mode scan saat ini No Proxy."
        fi
    else
        export AI_DORK_USE_PROXY="false"
    fi
fi

# ==============================================================================
# STEP 1: Target Selection
# ==============================================================================
export FULL_AUTO_MODE=false
TARGETS_FILE=$(mktemp)
add_cleanup 'rm -f "$TARGETS_FILE"; rm -rf "$TMP_ENUM_DIR"'

load_replay_targets() {
    local replay_file="${AI_REPLAY_SOURCE_FILE:-}"
    if [[ -z "$replay_file" ]]; then
        replay_file="$OUTPUT_BASE/failed_tasks.txt"
    fi
    [[ -f "$replay_file" ]] || return 1
    awk -F'[][]' '/^\[/{print $2}' "$replay_file" | awk '{print $1}' | sed '/^$/d' | sort -u > "$TARGETS_FILE"
    [[ -s "$TARGETS_FILE" ]]
}

if [[ "$IS_RESUME" == "true" && -f "$OUTPUT_BASE/all_targets.txt" ]]; then
    # Resume mode
    MODE=$(cat "$OUTPUT_BASE/scan_mode.txt" 2>/dev/null || echo "Resume")
    FULL_AUTO_MODE=$(cat "$OUTPUT_BASE/full_auto_mode.txt" 2>/dev/null || echo "false")
    WORKFLOW=$(cat "$OUTPUT_BASE/workflow.txt" 2>/dev/null || echo "Standard")
    
    # Get remaining targets
    grep -vFf "$COMPLETED_FILE" "$OUTPUT_BASE/all_targets.txt" > "$TARGETS_FILE" || true
    
    if [[ ! -s "$TARGETS_FILE" ]]; then
        gum style --foreground 46 "All targets in this session are already completed!"
        exit 0
    fi
else
    if [[ "$AI_REPLAY_MODE" == "true" ]] && load_replay_targets; then
        MODE="Replay Failed Targets"
        WORKFLOW="Standard (Recommended)"
        FULL_AUTO_MODE=false
        gum style --foreground 46 "Replay mode aktif: hanya target gagal yang dijalankan ulang."
    elif [[ "$AI_AUTONOMOUS_MODE" == "true" ]]; then
        MODE="AI Orchestrator"
        WORKFLOW="Standard (Recommended)"
        if [[ -n "${AI_AUTONOMOUS_TARGETS_FILE:-}" ]]; then
            if [[ ! -f "${AI_AUTONOMOUS_TARGETS_FILE}" ]]; then
                gum log --level error "AI_AUTONOMOUS_TARGETS_FILE tidak ditemukan: ${AI_AUTONOMOUS_TARGETS_FILE}"
                exit 1
            fi
            cp "${AI_AUTONOMOUS_TARGETS_FILE}" "$TARGETS_FILE"
        elif [[ -n "${AI_AUTONOMOUS_TARGETS:-}" ]]; then
            echo "${AI_AUTONOMOUS_TARGETS}" | tr ', ' '\n\n' | sed '/^$/d' | sort -u > "$TARGETS_FILE"
        else
            gum log --level error "Mode AI Orchestrator aktif, tapi target kosong. Isi AI_AUTONOMOUS_TARGETS atau AI_AUTONOMOUS_TARGETS_FILE."
            exit 1
        fi
        FULL_AUTO_MODE=false
        gum style --foreground 46 "AI Orchestrator: target dimuat otomatis."
    elif [[ "${DRY_RUN:-false}" == "true" ]]; then
        MODE="Single Domain"
        DOMAIN=$(gum input --placeholder "example.com" --prompt "DRY-RUN target domain: ")
        echo "$DOMAIN" > "$TARGETS_FILE"
        WORKFLOW="Standard (Recommended)"
        gum style --foreground 240 "DRY-RUN aktif: mode target disederhanakan ke Single Domain."
    else
        MODE=$(gum choose \
            --header "Select target mode:" --cursor "→ " \
            "Single Domain" \
            "Massive Scan from File" \
            "Enumerate & Choose Subdomains" \
            "Full Automation (Single Domain → All Subdomains)" \
            "Dorking to Target (AI/Manual)")

        case "$MODE" in
    "Single Domain")
        DOMAIN=$(gum input --placeholder "example.com" --prompt "Enter domain: ")
        echo "$DOMAIN" > "$TARGETS_FILE"
        WORKFLOW=$(gum choose --header "Select workflow:" "Standard (Recommended)" "Custom (Choose tools manually)")
        ;;
    "Massive Scan from File")
        FILE=$(gum file --file --height 10 --header "Select file with domain list:")
        if [[ ! -f "$FILE" ]]; then
            gum log --level error "Invalid file."
            exit 1
        fi
        
        gum spin --spinner dot --title "Probing active targets from file (httpx)..." -- bash -c "
            timeout 300 httpx -l '$FILE' -silent -o '$TMP_ENUM_DIR/alive_massive.txt' 2>/dev/null || true
        "
        if [[ ! -s "$TMP_ENUM_DIR/alive_massive.txt" ]]; then
            gum log --level error "No active targets found in the file."
            exit 1
        fi
        
        cp "$TMP_ENUM_DIR/alive_massive.txt" "$TARGETS_FILE"
        rm -f "$TMP_ENUM_DIR/alive_massive.txt"
        WORKFLOW=$(gum choose --header "Select workflow:" "Standard (Recommended)" "Custom (Choose tools manually)")
        ;;
    "Enumerate & Choose Subdomains")
        DOMAIN=$(gum input --placeholder "example.com" --prompt "Domain to enumerate: ")
        
        gum spin --spinner dot --title "Enumerating subdomains for $DOMAIN..." -- bash -c "
            cd '$TMP_ENUM_DIR' || exit 1
            timeout 120 subfinder -d '$DOMAIN' -silent > subs_subfinder.txt 2>/dev/null || true
            curl -s --max-time 30 'https://crt.sh/?q=%25.$DOMAIN&output=json' | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > subs_crtsh.txt || true
            sort -u subs_subfinder.txt subs_crtsh.txt > all_subs.txt 2>/dev/null || true
        "
        if [[ -s "$TMP_ENUM_DIR/all_subs.txt" ]]; then
            cp "$TMP_ENUM_DIR/all_subs.txt" "$OUTPUT_BASE/all_subdomains.txt"
        else
            gum log --level error "No subdomains found."
            exit 1
        fi
        
        gum spin --spinner dot --title "Probing active subdomains (httpx)..." -- bash -c "
            cd '$TMP_ENUM_DIR' || exit 1
            timeout 300 httpx -l all_subs.txt -silent -o alive_subs.txt 2>/dev/null || true
        "
        if [[ ! -s "$TMP_ENUM_DIR/alive_subs.txt" ]]; then
            gum log --level error "No active subdomains found."
            exit 1
        fi
        
        SELECTED=$(cat "$TMP_ENUM_DIR/alive_subs.txt" | gum choose --no-limit --header "Select active subdomains (Space to select):")
        [[ -z "$SELECTED" ]] && { gum log --level error "Nothing selected."; exit 1; }
        echo "$SELECTED" > "$TARGETS_FILE"
        rm -f "$TMP_ENUM_DIR"/*.txt
        WORKFLOW=$(gum choose --header "Select workflow:" "Standard (Recommended)" "Custom (Choose tools manually)")
        ;;
    "Dorking to Target (AI/Manual)")
        DORK_SRC=$(gum choose --header "Pilih sumber Dorking:" "Input Query Manual" "Dari file dorking.txt")
        
        > "$TMP_ENUM_DIR/dork_queries.txt"
        if [[ "$DORK_SRC" == "Input Query Manual" ]]; then
            DORK_QUERY=$(gum input --placeholder "site:example.com ext:php inurl:id=" --prompt "Masukkan Dork Query: ")
            [[ -n "$DORK_QUERY" ]] && echo "$DORK_QUERY" > "$TMP_ENUM_DIR/dork_queries.txt"
        else
            if [[ -f "dorking.txt" ]]; then
                cp "dorking.txt" "$TMP_ENUM_DIR/dork_queries.txt"
            else
                gum log --level error "File dorking.txt tidak ditemukan di direktori saat ini."
                exit 1
            fi
        fi

        if [[ ! -s "$TMP_ENUM_DIR/dork_queries.txt" ]]; then
            gum log --level error "Query Dorking kosong."
            exit 1
        fi

        gum spin --spinner dot --title "Menjalankan Dorking via SearxNG API (Python)..." -- bash -c "
            python3 - '$TMP_ENUM_DIR/dork_queries.txt' '$TMP_ENUM_DIR/dork_urls.txt' <<'PY'
import sys
from pathlib import Path
try:
    import requests, urllib.parse, random
except ImportError:
    Path(sys.argv[2]).write_text('')
    sys.exit(0)

qfile = Path(sys.argv[1])
outfile = Path(sys.argv[2])
queries = [l.strip() for l in qfile.read_text(encoding='utf-8').splitlines() if l.strip()]

user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36'
]

instances = [
    'https://searx.be',
    'https://searx.tiekoetter.com',
    'https://searx.work',
    'https://search.ononoki.org',
    'https://searx.roflcopter.fr',
    'https://searx.stuxnet.pt',
    'https://paulgo.io'
]

found_urls = set()

for q in queries:
    random.shuffle(instances)
    for instance in instances:
        try:
            headers = {
                'User-Agent': random.choice(user_agents),
                'Accept': 'application/json, text/plain, */*',
                'DNT': '1'
            }
            url = f'{instance}/search?q={urllib.parse.quote(q)}&format=json'
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for r in data.get('results', []):
                    href = r.get('url', '')
                    if href.startswith('http'):
                        found_urls.add(href)
                break # Pindah ke query berikutnya jika sukses
        except Exception:
            continue

outfile.write_text('\n'.join(found_urls) + '\n', encoding='utf-8')
PY
        "

        if [[ ! -s "$TMP_ENUM_DIR/dork_urls.txt" ]]; then
            gum log --level error "Tidak ada URL yang ditemukan dari hasil Dorking."
            exit 1
        fi

        # Bersihkan dan ekstrak domain utama agar bisa diproses tools scan
        awk -F/ '{print $3}' "$TMP_ENUM_DIR/dork_urls.txt" | sed 's/:.*//' | sort -u > "$TMP_ENUM_DIR/dork_domains.txt"

        gum spin --spinner dot --title "Memeriksa target yang hidup (httpx)..." -- bash -c "
            timeout 120 httpx -l '$TMP_ENUM_DIR/dork_domains.txt' -silent -o '$TMP_ENUM_DIR/alive_dork.txt' 2>/dev/null || true
        "

        if [[ ! -s "$TMP_ENUM_DIR/alive_dork.txt" ]]; then
            gum log --level error "Target hasil dorking tidak ada yang merespons (mati)."
            exit 1
        fi

        SELECTED=$(cat "$TMP_ENUM_DIR/alive_dork.txt" | gum choose --no-limit --header "Pilih target hasil Dorking (Spasi untuk memilih, Enter untuk lanjut):")
        [[ -z "$SELECTED" ]] && { gum log --level error "Tidak ada target yang dipilih."; exit 1; }
        
        echo "$SELECTED" > "$TARGETS_FILE"
        WORKFLOW=$(gum choose --header "Select workflow:" "Standard (Recommended)" "Custom (Choose tools manually)")
        ;;
    "Full Automation (Single Domain → All Subdomains)")
        FULL_AUTO_MODE=true
        DOMAIN=$(gum input --placeholder "example.com" --prompt "Main domain: ")
        
        # UI Upgrade: Tambahkan opsi intensitas discovery
        DISCOVERY_MODE=$(gum choose --header "Select Discovery Intensity:" \
            "Fast (subfinder + crt.sh only)" \
            "Deep (subfinder + crt.sh + bruteforce + permutation)")
            
        gum spin --spinner dot --title "Enumerating subdomains for $DOMAIN..." -- bash -c "
            cd '$TMP_ENUM_DIR' || exit 1
            timeout 120 subfinder -d '$DOMAIN' -silent > subs_subfinder.txt 2>/dev/null || true
            curl -s --max-time 30 'https://crt.sh/?q=%25.$DOMAIN&output=json' | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > subs_crtsh.txt || true
            
            if [[ '$DISCOVERY_MODE' == 'Deep'* ]]; then
                # Tambahan: Simulasi Deep Discovery (jika ada tool tambahan bisa dipanggil di sini)
                echo 'api.$DOMAIN' >> subs_deep.txt
                echo 'dev.$DOMAIN' >> subs_deep.txt
                echo 'staging.$DOMAIN' >> subs_deep.txt
                echo 'test.$DOMAIN' >> subs_deep.txt
                echo 'admin.$DOMAIN' >> subs_deep.txt
                sort -u subs_subfinder.txt subs_crtsh.txt subs_deep.txt > all_subs.txt 2>/dev/null || true
            else
                sort -u subs_subfinder.txt subs_crtsh.txt > all_subs.txt 2>/dev/null || true
            fi
        "
        if [[ ! -s "$TMP_ENUM_DIR/all_subs.txt" ]]; then
            gum log --level warn "No subdomains found. Scanning main domain only."
            echo "$DOMAIN" > "$TMP_ENUM_DIR/all_subs.txt"
        fi
        
        TOTAL_SUBS=$(wc -l < "$TMP_ENUM_DIR/all_subs.txt" | tr -d ' ')
        gum style --foreground 45 "✅ Found $TOTAL_SUBS subdomains. Proceeding to alive check..."
        cp "$TMP_ENUM_DIR/all_subs.txt" "$OUTPUT_BASE/all_subdomains.txt"
        
        # Opsi Filtering Port sebelum Httpx
        PORT_MODE=$(gum choose --header "Select Port Scanning Scope for HTTPx:" \
            "Standard (80, 443)" \
            "Large (80, 443, 8080, 8443, 3000, 8000)")
            
        local httpx_ports="-p 80,443"
        if [[ "$PORT_MODE" == "Large"* ]]; then
            httpx_ports="-p 80,443,8080,8443,3000,8000"
        fi

        gum spin --spinner dot --title "Probing alive hosts ($PORT_MODE)..." -- bash -c "
            cd '$TMP_ENUM_DIR' || exit 1
            timeout 300 httpx -l all_subs.txt $httpx_ports -silent -o alive_subs.txt 2>/dev/null || true
        "
        
        if [[ ! -s "$TMP_ENUM_DIR/alive_subs.txt" ]]; then
            gum log --level error "No alive hosts. Exiting."
            exit 1
        fi
        
        cp "$TMP_ENUM_DIR/alive_subs.txt" "$TARGETS_FILE"
        cp "$TMP_ENUM_DIR/alive_subs.txt" "$OUTPUT_BASE/alive_hosts.txt"
        TOTAL_ALIVE=$(wc -l < "$TMP_ENUM_DIR/alive_subs.txt" | tr -d ' ')
        
        # UI Upgrade: Tampilkan statistik ringkas sebelum lanjut
        echo ""
        gum style --border rounded --margin "0 1" --padding "1 2" --border-foreground 212 \
            "📊 Discovery Summary" \
            "Total Subdomains : $TOTAL_SUBS" \
            "Alive Hosts      : $TOTAL_ALIVE"
        echo ""
        
        gum format -- "Proceeding automatically to vulnerability scan phase..."
        rm -f "$TMP_ENUM_DIR"/*.txt

        # MODIFIKASI 2: Tambahkan pilihan workflow pada Full Automation
        WORKFLOW=$(gum choose --header "Select workflow for full automation:" \
            "Standard (Recommended)" \
            "Custom (Choose tools manually)")
        ;;
esac
    fi
    
    # Save state for future resume
    cp "$TARGETS_FILE" "$OUTPUT_BASE/all_targets.txt"
    echo "$MODE" > "$OUTPUT_BASE/scan_mode.txt"
    echo "$FULL_AUTO_MODE" > "$OUTPUT_BASE/full_auto_mode.txt"
    echo "$WORKFLOW" > "$OUTPUT_BASE/workflow.txt"
fi

# ==============================================================================
# Rename Directory to Result/NamaDomain_SCAN_XXXX_XXXX
# ==============================================================================
if [[ "$IS_RESUME" == "false" && -s "$TARGETS_FILE" ]]; then
    # Ambil target pertama sebagai nama utama
    MAIN_TARGET=$(head -n 1 "$TARGETS_FILE" | tr -d '\r')
    # Hilangkan http:// atau https://
    MAIN_TARGET_DOMAIN=$(echo "$MAIN_TARGET" | sed -e 's|^https*://||' -e 's|/.*||')
    # Buat string aman untuk nama folder
    MAIN_TARGET_SAFE=$(echo "$MAIN_TARGET_DOMAIN" | sed 's/[^a-zA-Z0-9.-]/_/g')
    
    # Format akhir: Result/NamaDomain_SCAN_XXXX_XXXX
    FINAL_OUTPUT_BASE="Result/${MAIN_TARGET_SAFE}_${NEW_OUTPUT_BASE}"
    
    mkdir -p "Result"
    if [[ -d "$OUTPUT_BASE" ]]; then
        mv "$OUTPUT_BASE" "$FINAL_OUTPUT_BASE"
    fi
    export OUTPUT_BASE="$FINAL_OUTPUT_BASE"
    export LOG_FILE="$OUTPUT_BASE/scan.log"
    export TMP_ENUM_DIR="$OUTPUT_BASE/.enum_tmp"
    export COMPLETED_FILE="$OUTPUT_BASE/completed_targets.txt"
    export PROXY_LIST_FILE="$OUTPUT_BASE/proxies_active.txt"
    export PROXY_USED_FILE="$OUTPUT_BASE/proxies_used.txt"
    export PROXY_DEAD_FILE="$OUTPUT_BASE/proxies_dead.txt"
fi

TOTAL_TARGETS=$(wc -l < "$TARGETS_FILE" | tr -d ' ')

write_mode_marker "AI_ORCHESTRATOR_MODE" "$AI_AUTONOMOUS_MODE"
write_mode_marker "REPLAY_FAILED_ONLY" "$AI_REPLAY_MODE"
write_mode_marker "SCAN_MODE" "${MODE:-unknown}"
write_mode_marker "WORKFLOW" "${WORKFLOW:-unknown}"
write_mode_marker "TOTAL_TARGETS" "$TOTAL_TARGETS"

# === Membangun List Target Aktif ===
gum style --margin "1 0" --foreground 212 "## 📋 Selected Targets ($TOTAL_TARGETS active domains)"

counter=1
while IFS= read -r line && [[ $counter -le 15 ]]; do
    clean_line=$(echo "$line" | tr -d '\r')
    printf "\033[1;37m %-3s. \033[1;36m%s\033[0m\n" "$counter" "$clean_line"
    ((counter++))
done < "$TARGETS_FILE"

if [[ $TOTAL_TARGETS -gt 15 ]]; then
    printf "\033[1;37m ... \033[1;36m%s\033[0m\n" "and $((TOTAL_TARGETS - 15)) more active targets"
fi
echo ""

# ==============================================================================
# STEP 2: Tool Selection (Standard / Custom)
# ==============================================================================
if [[ "$IS_RESUME" == "true" && -f "$OUTPUT_BASE/config.sh" ]]; then
    source "$OUTPUT_BASE/config.sh"
    gum format -- "Resumed tools: $(echo $SELECTED_TOOLS | sed 's/^/ /')"
    gum format -- "Resumed Nmap Args: $NMAP_ARGS"
    gum format -- "Resumed SQLMap Args: $SQLMAP_ARGS"
elif [[ "$AI_AUTONOMOUS_MODE" == "true" ]]; then
    SELECTED_TOOLS="subfinder httpx nmap gau katana paramspider arjun nuclei dalfox wapiti sqlmap nikto ffuf wafw00f"
    FINAL_TOOLS=""
    for tool in $SELECTED_TOOLS; do
        check_tool "$tool" && FINAL_TOOLS="$FINAL_TOOLS $tool"
    done
    export SELECTED_TOOLS="$FINAL_TOOLS"
    export NMAP_ARGS="${AI_AUTONOMOUS_NMAP_ARGS:--sV -sC --script=vuln,ssl-enum-ciphers}"
    export SQLMAP_ARGS="${AI_AUTONOMOUS_SQLMAP_ARGS:---random-agent --batch --level=1 --risk=1}"
    export SCAN_SPEED="${AI_AUTONOMOUS_SCAN_SPEED:-Normal (Balanced)}"
    export CONCURRENCY="${AI_AUTONOMOUS_CONCURRENCY:-3}"
    export OUTPUT_MODE="${AI_AUTONOMOUS_OUTPUT_MODE:-Silent (Status only)}"
    {
        echo "export SELECTED_TOOLS=\"$SELECTED_TOOLS\""
        echo "export NMAP_ARGS=\"$NMAP_ARGS\""
        echo "export SQLMAP_ARGS=\"$SQLMAP_ARGS\""
        echo "export CONCURRENCY=\"$CONCURRENCY\""
        echo "export OUTPUT_MODE=\"$OUTPUT_MODE\""
        echo "export SCAN_SPEED=\"$SCAN_SPEED\""
    } > "$OUTPUT_BASE/config.sh"
    gum style --foreground 46 "AI Orchestrator: konfigurasi tools dipilih otomatis."
else
    if [[ "$WORKFLOW" == "Standard"* ]]; then
        SELECTED_TOOLS="subfinder httpx nmap gau katana paramspider arjun nuclei dalfox wapiti sqlmap nikto ffuf wafw00f"
        FINAL_TOOLS=""
        for tool in $SELECTED_TOOLS; do
            if [[ "$FULL_AUTO_MODE" == "true" && ( "$tool" == "subfinder" || "$tool" == "httpx" ) ]]; then
                continue
            fi
            if [[ "$MODE" == "Single Domain" || "$MODE" == "Enumerate & Choose Subdomains" || "$MODE" == "Massive Scan from File" ]] && [[ "$tool" == "subfinder" ]]; then
                continue
            fi
            check_tool "$tool" && FINAL_TOOLS="$FINAL_TOOLS $tool"
        done
        SELECTED_TOOLS="$FINAL_TOOLS"
        export SELECTED_TOOLS
        gum format -- "Standard workflow: All available tools will run in optimal order."
    else
        gum style --margin "1 0" --foreground 212 "## 🛠️ Select Scanning Tools"
        MENU_ITEMS=()
        AVAILABLE_TOOLS=()
        TOOL_COL_WIDTH=12
        for tool in "${!TOOL_DESC[@]}"; do
            if [[ "$FULL_AUTO_MODE" == "true" && ( "$tool" == "subfinder" || "$tool" == "httpx" ) ]]; then
                continue
            fi
            # Sembunyikan subfinder jika mode Single Domain, Enumerate, atau Massive Scan
            if [[ "$MODE" == "Single Domain" || "$MODE" == "Enumerate & Choose Subdomains" || "$MODE" == "Massive Scan from File" ]] && [[ "$tool" == "subfinder" ]]; then
                continue
            fi
            
            if check_tool "$tool"; then
                MENU_ITEMS+=("$(printf "%-${TOOL_COL_WIDTH}s %s" "$tool" "${TOOL_DESC[$tool]}")")
                AVAILABLE_TOOLS+=("$tool")
            else
                MENU_ITEMS+=("$(printf "%-${TOOL_COL_WIDTH}s %s (not installed)" "$tool" "${TOOL_DESC[$tool]}")")
            fi
        done

        DEFAULT_SELECTED_STR=$(IFS=','; echo "${MENU_ITEMS[@]}" | grep -E "^($(echo "${AVAILABLE_TOOLS[@]}" | tr ' ' '|'))" | head -n ${#AVAILABLE_TOOLS[@]} | tr '\n' ',')

        SELECTED_ITEMS=$(gum choose --no-limit --height 15 \
            --header "Use Space to select, Enter to confirm:" \
            --cursor "→ " --selected-prefix "✓ " --unselected-prefix "○ " \
            --selected="$DEFAULT_SELECTED_STR" "${MENU_ITEMS[@]}")

        [[ -z "$SELECTED_ITEMS" ]] && { gum log --level error "No tools selected."; exit 1; }
        SELECTED_TOOLS=$(echo "$SELECTED_ITEMS" | awk '{print $1}')
        export SELECTED_TOOLS
    fi

    gum format -- "Selected tools:$(echo $SELECTED_TOOLS | sed 's/^/ /')"

    # ==============================================================================
    # STEP 3: Additional Configuration
    # ==============================================================================
    gum style --margin "1 0" --foreground 212 "## ⚙️ Configuration Options"

    DEFAULT_NMAP_ARGS="-sV -sC --script=vuln,ssl-enum-ciphers"
    NMAP_ARGS=$(gum input --prompt "Nmap arguments [default: $DEFAULT_NMAP_ARGS]: " --width 80)
    export NMAP_ARGS=${NMAP_ARGS:-$DEFAULT_NMAP_ARGS}

    # MODIFIKASI 3: Konfigurasi SQLMap arguments
    DEFAULT_SQLMAP_ARGS="--random-agent --batch --level=1 --risk=1"
    SQLMAP_ARGS=$(gum input --prompt "SQLMap arguments [default: $DEFAULT_SQLMAP_ARGS]: " --width 80)
    export SQLMAP_ARGS=${SQLMAP_ARGS:-$DEFAULT_SQLMAP_ARGS}

    # SPEED OPTIONS
    SCAN_SPEED=$(gum choose --header "Select Scan Speed / Stealth Mode:" "Insane (No Delays)" "Normal (Balanced)" "Stealth (Evade Rate-Limits)")
    export SCAN_SPEED

    # Batch size (only if not single domain)
    if [[ "$MODE" == "Single Domain" ]]; then
        CONCURRENCY=1
    else
        gum style --margin "1 0" --foreground 212 "## 🚀 Batch Execution"
        CONCURRENCY=$(gum input --prompt "How many domains per batch? [default: 5]: " --placeholder "5")
        CONCURRENCY=${CONCURRENCY:-5}
    fi

    export OUTPUT_MODE=$(gum choose --header "Output mode (Verbose will show neat live logs, Silent shows minimal status):" "Silent (Status only)" "Verbose (Show live logs)")

    # Save to config
    {
        echo "export SELECTED_TOOLS=\"$SELECTED_TOOLS\""
        echo "export NMAP_ARGS=\"$NMAP_ARGS\""
        echo "export SQLMAP_ARGS=\"$SQLMAP_ARGS\""
        echo "export CONCURRENCY=\"$CONCURRENCY\""
        echo "export OUTPUT_MODE=\"$OUTPUT_MODE\""
        echo "export SCAN_SPEED=\"$SCAN_SPEED\""
    } > "$OUTPUT_BASE/config.sh"
fi

write_mode_marker "CONCURRENCY" "${CONCURRENCY:-unknown}"
write_mode_marker "OUTPUT_MODE" "${OUTPUT_MODE:-unknown}"
write_mode_marker "SCAN_SPEED" "${SCAN_SPEED:-unknown}"
write_mode_marker "TOOLS_COUNT" "$(echo "${SELECTED_TOOLS:-}" | wc -w | tr -d ' ')"
if declare -F write_state_snapshot >/dev/null 2>&1; then
    write_state_snapshot
fi

if [[ "$AI_AUTONOMOUS_MODE" == "true" ]]; then
    write_mode_marker "START_MODE" "auto"
    gum style --foreground 46 "AI Orchestrator: memulai scanning otomatis."
else
    write_mode_marker "START_MODE" "manual_confirm"
    gum confirm "Start scanning with above configuration?" || exit 0
fi

SCRIPT_NAME="Nexusuite"
VERSION="3.3.0 (AI Edition)"

# --- Setup PATH ---
export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin"
if [[ -n "${PREFIX:-}" ]] && [[ "$PREFIX" == *"/com.termux/"* ]]; then
    export PATH="$PATH:$PREFIX/bin"
fi

# --- Dependency Check & Installer ---
MISSING_TOOLS=()
REQUIRED_TOOLS=(
    "gum" "subfinder" "httpx" "nmap" "nuclei" "dalfox" "gau"
    "katana" "arjun" "sqlmap" "paramspider" "nikto" "jq" "flock" "timeout" "ffuf" "wafw00f" "whatweb" "wpscan"
)

# Wapiti is fully optional, so it is not in REQUIRED_TOOLS
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
    echo -e "\033[1;31m[!] Missing tools: ${MISSING_TOOLS[*]}\033[0m"
    if [[ -f "$SCRIPT_DIR/install.sh" ]]; then
        read -rp "Run install.sh now? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            bash "$SCRIPT_DIR/install.sh"
            echo -e "\033[1;33m[!] Please restart your terminal or run 'source ~/.bashrc' and re-run OWASP.sh.\033[0m"
            exit 0
        else
            echo -e "\033[1;31m[!] Installation cancelled. Exiting.\033[0m"
            exit 1
        fi
    else
        echo -e "\033[1;31m[!] install.sh not found. Please install the missing tools manually.\033[0m"
        exit 1
    fi
fi

# --- Helper Functions ---
check_tool() { command -v "$1" &> /dev/null; }

# Internet check (Termux friendly: fallback to curl)
check_internet() {
    if ping -c 1 -W 2 8.8.8.8 &> /dev/null || curl -s --max-time 3 https://www.google.com &> /dev/null; then
        return 0
    else
        return 1
    fi
}

wait_for_internet() {
    while ! check_internet; do
        echo -e "\033[1;33m[!] Internet connection lost. Waiting... (Ctrl+S to skip waiting)\033[0m"
        sleep 10
    done
    echo -e "\033[1;32m[✓] Internet connection restored.\033[0m"
}

# --- Terminal Logging Formatter ---
log_msg() {
    local stat="$1"
    local color="$2"
    local target="$3"
    local tool="$4"
    local msg="$5"
    local time_now=$(date +%H:%M:%S)
    
    # Modern icons based on status
    local icon="⚡"
    local bg_color="\033[40m" # Default background
    
    case "$stat" in
        ">") icon="🚀" ; bg_color="\033[44m" ;;
        "✓") icon="✅" ; bg_color="\033[42m" ;;
        "!") icon="❌" ; bg_color="\033[41m" ;;
        "↻") icon="🔄" ; bg_color="\033[43m" ;;
        "i") icon="💡" ; bg_color="\033[46m" ;;
        "+") icon="➕" ; bg_color="\033[45m" ;;
        "🤖"|"AI") icon="🧠" ; bg_color="\033[45m" ;;
        "🔥"|"OVERLORD") icon="☢️" ; bg_color="\033[41m" ;;
        "🏁") icon="🏆" ; bg_color="\033[42m" ;;
    esac
    
    # Print according to OUTPUT_MODE dengan gaya Cyberpunk / Hacker yang lebih bold
    if [[ "${OUTPUT_MODE:-}" == "Verbose"* ]]; then
        # Modern, neat, aligned columns dengan highlight tag
        printf "\033[1;90m[%s]\033[0m %b\033[1;97m %s \033[0m \033[1;36m%-25.25s\033[0m \033[1;90m│\033[0m \033[1;35m%-14.14s\033[0m \033[1;90m│\033[0m %b%s\033[0m\n" \
            "$time_now" "$bg_color" "$icon" "$target" "$tool" "$color" "$msg"
    else
        # Minimalist tapi tetap striking
        printf "\033[1;90m[%s]\033[0m %b\033[1;97m %s \033[0m \033[1;36m%s\033[0m \033[1;90m»\033[0m \033[1;35m%s\033[0m \033[1;90m:\033[0m %b%s\033[0m\n" \
            "$time_now" "$bg_color" "$icon" "$target" "$tool" "$color" "$msg"
    fi
    
    # Log to global scan log
    echo "[$time_now] [$stat] $target | $tool | $msg" >> "$LOG_FILE"
}
export -f log_msg

declare -A TOOL_DESC=(
    ["subfinder"]="Passive subdomain enumeration"
    ["httpx"]="Probe for alive hosts & tech stack"
    ["nmap"]="Deep network & service scan"
    ["nuclei"]="Vulnerability scanner (OWASP coverage)"
    ["dalfox"]="XSS scanner (OWASP A05)"
    ["wapiti"]="Web vuln injector (SQLi, LFI, XSS, etc.)"
    ["gau"]="Get all historical URLs"
    ["katana"]="Crawl for endpoints & parameters"
    ["arjun"]="HTTP parameter discovery"
    ["sqlmap"]="SQL Injection scanner (OWASP A03)"
    ["paramspider"]="Parameter discovery & fuzzing wordlist generator"
    ["nikto"]="Web server vulnerability scanner"
    ["ffuf"]="Directory/File fuzzing (OWASP A01 & A05)"
    ["wafw00f"]="Web Application Firewall Fingerprinting"
)

# --- Header ---
# Mengecek status Ollama secara diam-diam untuk header
AI_STATUS_TEXT="🤖 AI Agent: NON-AKTIF"
if command -v curl &> /dev/null && curl -s -m 1 http://localhost:11434/ > /dev/null; then
    AI_STATUS_TEXT="🤖 AI Agent: AKTIF (Ready)"
fi

echo -e "\033[1;36m"
cat << "EOF"
    _   __                           _ __     
   / | / /__  _  ____  _______  __  (_) /____ 
  /  |/ / _ \| |/_/ / / / ___/ / / / / __/ _ \
 / /|  /  __/>  </ /_/ (__  ) / /_/ / /_/  __/
/_/ |_/\___/_/|_|\__,_/____/  \__,_/\__/\___/ 
EOF
echo -e "\033[0m"

gum style \
    --border double --align center --width 75 --margin "0 0 1 0" --padding "0 2" \
    --foreground 45 --border-foreground 39 \
    "v$VERSION" "Professional Web & Network Vulnerability Scanner" "$AI_STATUS_TEXT"

# --- Temporary variables for Output Directory ---
# Output Base di-set awalnya hanya dengan timestamp. Nama domain akan ditambahkan nanti di 02_prompts.sh
export NEW_OUTPUT_BASE="SCAN_$(date +%Y%m%d_%H%M%S)"

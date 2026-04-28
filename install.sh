#!/usr/bin/env bash
# ==============================================================================
# OWASP Scanner Dependency Installer
# Installs: gum, subfinder, httpx, nmap, nuclei, dalfox, wapiti, gau, katana,
#           arjun, sqlmap, paramspider, nikto, jq, flock, timeout
# Supports: Linux (apt, yum, pacman), macOS (brew), and Termux (pkg)
# ==============================================================================

set -euo pipefail

# Warna
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   OWASP Scanner Dependency Installer   ${NC}"
echo -e "${GREEN}========================================${NC}"

# Deteksi OS dan Package Manager
OS="$(uname -s)"
PKG_MANAGER=""
IS_TERMUX=false

if [[ -n "${PREFIX:-}" ]] && [[ "$PREFIX" == *"/com.termux/"* ]]; then
    IS_TERMUX=true
    PKG_MANAGER="pkg"
    echo -e "${GREEN}[+] Detected Environment: Termux${NC}"
elif [[ "$OS" == "Linux" ]]; then
    if command -v apt &> /dev/null; then
        PKG_MANAGER="apt"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    elif command -v pacman &> /dev/null; then
        PKG_MANAGER="pacman"
    else
        echo -e "${RED}Unsupported Linux distribution. Please install tools manually.${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] Detected OS: Linux, Package Manager: $PKG_MANAGER${NC}"
elif [[ "$OS" == "Darwin" ]]; then
    if command -v brew &> /dev/null; then
        PKG_MANAGER="brew"
    else
        echo -e "${RED}Homebrew not found. Please install Homebrew first: https://brew.sh/${NC}"
        exit 1
    fi
    echo -e "${GREEN}[+] Detected OS: macOS, Package Manager: $PKG_MANAGER${NC}"
else
    echo -e "${RED}Unsupported OS: $OS${NC}"
    exit 1
fi

# Setup GO_BIN path
if $IS_TERMUX; then
    GO_BIN="$PREFIX/bin"
    BASH_RC="$HOME/.bashrc"
    ZSH_RC="$HOME/.zshrc"
else
    GO_BIN="$HOME/go/bin"
    BASH_RC="$HOME/.bashrc"
    ZSH_RC="$HOME/.zshrc"
fi

# Fungsi instal paket dasar
install_pkg() {
    local pkg="$1"
    case "$PKG_MANAGER" in
        pkg)
            pkg install -y "$pkg"
            ;;
        apt)
            sudo apt update -qq || true
            sudo apt install -y "$pkg"
            ;;
        yum)
            sudo yum install -y "$pkg"
            ;;
        dnf)
            sudo dnf install -y "$pkg"
            ;;
        pacman)
            sudo pacman -S --noconfirm "$pkg"
            ;;
        brew)
            brew install "$pkg"
            ;;
    esac
}

# Update Termux repository if needed
if $IS_TERMUX; then
    echo -e "${YELLOW}[!] Updating Termux repositories...${NC}"
    pkg update -y
    pkg upgrade -y
fi

# Pastikan Go terinstall
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}[!] Go not found. Installing Go...${NC}"
    case "$PKG_MANAGER" in
        pkg)
            install_pkg golang
            ;;
        apt|yum|dnf)
            install_pkg golang-go
            ;;
        pacman)
            install_pkg go
            ;;
        brew)
            brew install go
            ;;
    esac
fi

# Tambahkan $GO_BIN ke PATH jika belum ada (Non-Termux biasanya butuh ini, Termux go bin biasanya di $PREFIX/bin atau ~/go/bin)
if ! $IS_TERMUX; then
    if [[ ":$PATH:" != *":$GO_BIN:"* ]]; then
        echo -e "${YELLOW}[!] Adding $GO_BIN to PATH...${NC}"
        echo "export PATH=\"\$PATH:$GO_BIN\"" >> "$BASH_RC"
        [[ -f "$ZSH_RC" ]] && echo "export PATH=\"\$PATH:$GO_BIN\"" >> "$ZSH_RC"
        export PATH="$PATH:$GO_BIN"
    fi
else
    # Di Termux, GOPATH bin mungkin tetap di ~/go/bin
    TERMUX_GO_BIN="$HOME/go/bin"
    if [[ ":$PATH:" != *":$TERMUX_GO_BIN:"* ]]; then
         echo "export PATH=\"\$PATH:$TERMUX_GO_BIN\"" >> "$BASH_RC"
         [[ -f "$ZSH_RC" ]] && echo "export PATH=\"\$PATH:$TERMUX_GO_BIN\"" >> "$ZSH_RC"
         export PATH="$PATH:$TERMUX_GO_BIN"
         GO_BIN="$TERMUX_GO_BIN"
    fi
fi

# Pastikan direktori Go bin ada
mkdir -p "$GO_BIN"

# ------------------------------------------------------------------------------
# Instalasi Paket Dasar (via Package Manager)
# ------------------------------------------------------------------------------
echo -e "${GREEN}[+] Installing base packages (gum, nmap, jq, curl, flock, coreutils, python3, pip, git)...${NC}"

# Install Git first
if ! command -v git &> /dev/null; then
    install_pkg git
fi

# Gum
if ! command -v gum &> /dev/null; then
    echo -e "${YELLOW}[!] Installing gum...${NC}"
    case "$PKG_MANAGER" in
        pkg)
            install_pkg gum
            ;;
        apt)
            sudo mkdir -p /etc/apt/keyrings
            curl -fsSL https://repo.charm.sh/apt/gpg.key | sudo gpg --dearmor -o /etc/apt/keyrings/charm.gpg
            echo "deb [signed-by=/etc/apt/keyrings/charm.gpg] https://repo.charm.sh/apt/ * *" | sudo tee /etc/apt/sources.list.d/charm.list
            sudo apt update -qq || true
            sudo apt install -y gum
            ;;
        yum|dnf)
            # Binary install
            curl -fsSL "https://github.com/charmbracelet/gum/releases/latest/download/gum_$(uname -s)_$(uname -m).tar.gz" | sudo tar xz -C /usr/local/bin gum
            ;;
        pacman)
            sudo pacman -S --noconfirm gum
            ;;
        brew)
            brew install gum
            ;;
    esac
fi

# Nmap, jq, curl, flock (util-linux), coreutils (untuk timeout), python3, pip
case "$PKG_MANAGER" in
        pkg)
             install_pkg nmap
             install_pkg jq
             install_pkg curl
             install_pkg util-linux
             install_pkg coreutils
             install_pkg python
             install_pkg rust
             install_pkg perl
             install_pkg procps
             install_pkg grep
             ;;
        apt)
            install_pkg nmap
            install_pkg jq
            install_pkg curl
            install_pkg util-linux
            install_pkg coreutils
            install_pkg python3
            install_pkg python3-pip
            install_pkg python3-venv
            install_pkg perl
            ;;
        yum|dnf)
            install_pkg nmap
            install_pkg jq
            install_pkg curl
            install_pkg util-linux
            install_pkg coreutils
            install_pkg python3
            install_pkg python3-pip
            install_pkg perl
            ;;
        pacman)
            install_pkg nmap
            install_pkg jq
            install_pkg curl
            install_pkg util-linux
            install_pkg coreutils
            install_pkg python
            install_pkg python-pip
            install_pkg perl
            ;;
        brew)
            brew install nmap
            brew install jq
            brew install curl
            brew install util-linux   # menyediakan flock di macOS
            brew install coreutils    # menyediakan timeout
            brew install python3
            brew install perl
            ;;
    esac

# ------------------------------------------------------------------------------
# Instalasi Go Tools
# ------------------------------------------------------------------------------
echo -e "${GREEN}[+] Installing Go tools (subfinder, httpx, nuclei, katana, dalfox, ffuf, gau)...${NC}"

# Setup Go environment flags for Termux
if $IS_TERMUX; then
    export CGO_ENABLED=0
fi

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || echo -e "${RED}[!] Failed to install subfinder${NC}"
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest || echo -e "${RED}[!] Failed to install httpx${NC}"
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || echo -e "${RED}[!] Failed to install nuclei${NC}"
go install -v github.com/projectdiscovery/katana/cmd/katana@latest || echo -e "${RED}[!] Failed to install katana${NC}"
go install -v github.com/hahwul/dalfox/v2@latest || echo -e "${RED}[!] Failed to install dalfox${NC}"
go install -v github.com/ffuf/ffuf/v2@latest || echo -e "${RED}[!] Failed to install ffuf${NC}"
go install -v github.com/lc/gau/v2/cmd/gau@latest || echo -e "${RED}[!] Failed to install gau${NC}"

# ------------------------------------------------------------------------------
# Instalasi Tools Python
# ------------------------------------------------------------------------------
echo -e "${GREEN}[+] Installing Python tools (arjun, sqlmap, paramspider, wapiti)...${NC}"

# PIP setup
PIP_CMD="pip3"
if ! command -v pip3 &> /dev/null; then
    PIP_CMD="pip"
fi

# Termux python needs special handling sometimes, or Debian needs --break-system-packages
PIP_ARGS="--user --upgrade"
if [[ "$PKG_MANAGER" == "apt" ]]; then
    PIP_ARGS="--user --upgrade --break-system-packages"
elif $IS_TERMUX; then
    PIP_ARGS="--upgrade" # Termux usually doesn't need --user
fi

# Arjun
$PIP_CMD install $PIP_ARGS arjun || echo -e "${RED}[!] Failed to install arjun via pip${NC}"

# Wapiti
$PIP_CMD install $PIP_ARGS wapiti3 || echo -e "${RED}[!] Failed to install wapiti via pip${NC}"

# Wafw00f
$PIP_CMD install $PIP_ARGS wafw00f || echo -e "${RED}[!] Failed to install wafw00f via pip${NC}"

# Tools Directory
TOOLS_DIR="$HOME/tools"
mkdir -p "$TOOLS_DIR"

# SQLMap
if [[ ! -d "$TOOLS_DIR/sqlmap" ]]; then
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git "$TOOLS_DIR/sqlmap"
fi
# Symlink
if [[ ! -L "$GO_BIN/sqlmap" ]]; then
    ln -sf "$TOOLS_DIR/sqlmap/sqlmap.py" "$GO_BIN/sqlmap"
    chmod +x "$GO_BIN/sqlmap"
fi

# ParamSpider
if [[ ! -d "$TOOLS_DIR/ParamSpider" ]]; then
    git clone https://github.com/devanshbatham/ParamSpider "$TOOLS_DIR/ParamSpider"
    $PIP_CMD install $PIP_ARGS -r "$TOOLS_DIR/ParamSpider/requirements.txt" || echo -e "${RED}[!] Failed to install ParamSpider requirements${NC}"
fi
if [[ ! -L "$GO_BIN/paramspider" ]]; then
    ln -sf "$TOOLS_DIR/ParamSpider/paramspider.py" "$GO_BIN/paramspider"
    chmod +x "$GO_BIN/paramspider"
fi

# ------------------------------------------------------------------------------
# Instalasi Nikto
# ------------------------------------------------------------------------------
echo -e "${GREEN}[+] Installing Nikto...${NC}"
if ! command -v nikto &> /dev/null; then
    case "$PKG_MANAGER" in
        pkg)
            # Termux doesn't have nikto in repo usually, install from git
            if [[ ! -d "$TOOLS_DIR/nikto" ]]; then
                git clone https://github.com/sullo/nikto.git "$TOOLS_DIR/nikto"
                ln -sf "$TOOLS_DIR/nikto/program/nikto.pl" "$GO_BIN/nikto"
                chmod +x "$GO_BIN/nikto"
            fi
            ;;
        apt|yum|dnf)
            install_pkg nikto
            ;;
        pacman)
            install_pkg nikto
            ;;
        brew)
            brew install nikto
            ;;
    esac
fi

# ------------------------------------------------------------------------------
# Update Nuclei Templates (opsional)
# ------------------------------------------------------------------------------
if command -v nuclei &> /dev/null; then
    echo -e "${GREEN}[+] Updating Nuclei templates...${NC}"
    nuclei -update-templates || true
fi

# ------------------------------------------------------------------------------
# Verifikasi Instalasi
# ------------------------------------------------------------------------------
echo -e "${GREEN}[+] Verifying installation...${NC}"
MISSING=()
TOOLS=(
    "gum" "subfinder" "httpx" "nmap" "nuclei" "dalfox" "gau"
    "katana" "arjun" "sqlmap" "paramspider" "nikto" "jq" "flock" "timeout" "ffuf" "wafw00f"
)

# Export PATH temporarily to check tools installed in GO_BIN
export PATH="$PATH:$GO_BIN"

for tool in "${TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING+=("$tool")
    fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    echo -e "${YELLOW}[!] Some tools may not have been installed correctly: ${MISSING[*]}${NC}"
    echo -e "${YELLOW}    You may need to restart your terminal or manually install them.${NC}"
else
    echo -e "${GREEN}[✓] All tools installed successfully!${NC}"
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}   Installation complete!               ${NC}"
if $IS_TERMUX; then
    echo -e "${GREEN}   Please restart your Termux app       ${NC}"
else
    echo -e "${GREEN}   Run 'source ~/.bashrc' or restart    ${NC}"
fi
echo -e "${GREEN}   terminal before using OWASP.sh.      ${NC}"
echo -e "${GREEN}========================================${NC}"

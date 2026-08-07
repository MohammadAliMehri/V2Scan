#!/usr/bin/env bash
set -e

# Colors
R='\033[0;31m' G='\033[0;32m' B='\033[0;34m' C='\033[0;36m' Y='\033[0;33m' W='\033[1;37m' N='\033[0m'

echo ""
echo -e "${C}============================================================${N}"
echo -e "${W}  V2Scan - Linux Environment Setup${N}"
echo -e "${C}============================================================${N}"
echo ""

# ── Detect package manager ──
PM=""
INSTALL_CMD=""
if command -v apt-get &>/dev/null; then
    PM="apt"
    INSTALL_CMD="sudo apt-get install -y"
elif command -v dnf &>/dev/null; then
    PM="dnf"
    INSTALL_CMD="sudo dnf install -y"
elif command -v pacman &>/dev/null; then
    PM="pacman"
    INSTALL_CMD="sudo pacman -S --noconfirm"
elif command -v brew &>/dev/null; then
    PM="brew"
    INSTALL_CMD="brew install"
else
    PM="unknown"
fi
echo -e "  Package manager: ${W}${PM}${N}"

# ── Step 1: Python ──
echo ""
echo -e "${B}[1/5] Checking Python...${N}"
PYTHON=""
for cmd in python3 python; do
    if command -v "$cmd" &>/dev/null; then
        PY_VER=$("$cmd" --version 2>&1 | grep -oP '\d+\.\d+')
        PYTHON="$cmd"
        echo -e "  ${G}[OK]${N} $PYTHON (version $PY_VER)"
        break
    fi
done

if [ -z "$PYTHON" ]; then
    echo -e "  ${R}[X]${N} Python not found. Installing..."
    case "$PM" in
        apt)    sudo apt-get update -qq && sudo apt-get install -y python3 python3-pip python3-venv ;;
        dnf)    sudo dnf install -y python3 python3-pip ;;
        pacman) sudo pacman -S --noconfirm python python-pip ;;
        brew)   brew install python3 ;;
        *)      echo "  Install Python 3.8+ manually: https://www.python.org/downloads/"; exit 1 ;;
    esac
    PYTHON="python3"
    echo -e "  ${G}[OK]${N} Python installed"
fi

# ── Step 2: pip ──
echo ""
echo -e "${B}[2/5] Checking pip...${N}"
if ! "$PYTHON" -m pip --version &>/dev/null; then
    echo -e "  ${Y}[!]${N} pip not found, installing..."
    case "$PM" in
        apt)    sudo apt-get install -y python3-pip || "$PYTHON" -m ensurepip --upgrade ;;
        dnf)    sudo dnf install -y python3-pip ;;
        pacman) sudo pacman -S --noconfirm python-pip ;;
        brew)   echo "  pip comes with brew python" ;;
    esac
fi
echo -e "  ${G}[OK]${N} pip is available"

# ── Step 3: Python packages ──
echo ""
echo -e "${B}[3/5] Installing Python packages...${N}"
"$PYTHON" -m pip install --upgrade pip --quiet 2>/dev/null || true
"$PYTHON" -m pip install "rich" "httpx[http2]" --quiet
echo -e "  ${G}[OK]${N} Python packages installed (rich, httpx)"

# ── Step 4: curl ──
echo ""
echo -e "${B}[4/5] Checking curl...${N}"
if command -v curl &>/dev/null; then
    echo -e "  ${G}[OK]${N} curl is available ($(curl --version | head -1 | cut -d' ' -f1-3))"
else
    echo -e "  ${Y}[!]${N} curl not found. Installing..."
    $INSTALL_CMD curl 2>/dev/null || echo "  Install curl manually for delay testing"
fi

# ── Step 5: sing-box ──
echo ""
echo -e "${B}[5/5] Checking sing-box...${N}"
if command -v sing-box &>/dev/null; then
    SB_VER=$(sing-box version 2>&1 | head -1)
    echo -e "  ${G}[OK]${N} sing-box found: $SB_VER"
else
    echo -e "  ${Y}[!]${N} sing-box not found."
    echo ""
    echo -e "  ${W}Option A${N} - Install from GitHub releases:"
    echo -e "    ${C}curl -sL https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-*-linux-amd64.tar.gz | sudo tar xz -C /usr/local/bin/ --strip-components=1${N}"
    echo ""
    echo -e "  ${W}Option B${N} - Install with package manager:"
    case "$PM" in
        apt)    echo "    # Add the SagerNet apt repo or download .deb from GitHub releases" ;;
        brew)   echo "    brew install sing-box" ;;
        *)      echo "    Download from: https://github.com/SagerNet/sing-box/releases" ;;
    esac
    echo ""
    echo -e "  ${W}Option C${N} - Pass path manually:"
    echo "    python v2_all_in_one.py delay -i configs.txt --singbox /path/to/sing-box"
    echo ""
    echo -e "  The ${W}fetch${N} command works without sing-box."
fi

# ── Done ──
echo ""
echo -e "${C}============================================================${N}"
echo -e "${G}  Setup complete!${N}"
echo -e "${C}============================================================${N}"
echo ""
echo -e "  Quick start:"
echo -e "    ${W}$PYTHON v2_all_in_one.py fetch${N}               # Fetch free configs from GitHub"
echo -e "    ${W}$PYTHON v2_all_in_one.py scan --parallel 5${N}    # Fetch + test all"
echo -e "    ${W}$PYTHON v2_all_in_one.py web --port 8686${N}      # Launch web UI"
echo -e "    ${W}$PYTHON v2_all_in_one.py delay -i configs.txt${N} # Test existing configs"
echo ""
echo -e "  Open ${C}http://127.0.0.1:8686${N} for the web dashboard."
echo ""

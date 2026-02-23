#!/usr/bin/env bash
# =============================================================================
# Network Traffic Analyzer — Linux Setup Script
#
# Usage:
#   chmod +x setup.sh
#   ./setup.sh              # install deps and grant capabilities (recommended)
#   ./setup.sh --sudo-only  # skip setcap; always run with sudo instead
# =============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'   # No Color

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
header()  { echo -e "\n${BOLD}$*${NC}"; }

SUDO_ONLY=false
for arg in "$@"; do
    [[ "$arg" == "--sudo-only" ]] && SUDO_ONLY=true
done

# ---------------------------------------------------------------------------
header "=== Network Traffic Analyzer Setup ==="
# ---------------------------------------------------------------------------

# 1. Detect Linux distribution
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    DISTRO="${ID:-unknown}"
    DISTRO_PRETTY="${PRETTY_NAME:-Linux}"
else
    DISTRO="unknown"
    DISTRO_PRETTY="Unknown Linux"
fi
info "Detected: $DISTRO_PRETTY"

# 2. Check Python 3.8+
header "Checking Python version..."
if ! command -v python3 &>/dev/null; then
    error "python3 not found. Install it first:"
    case "$DISTRO" in
        ubuntu|debian|linuxmint) echo "  sudo apt-get install python3 python3-pip python3-venv" ;;
        fedora|rhel|centos)      echo "  sudo dnf install python3 python3-pip" ;;
        arch|manjaro)            echo "  sudo pacman -S python python-pip" ;;
        *)                       echo "  Install python3 from https://python.org" ;;
    esac
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [[ "$PY_MAJOR" -lt 3 || ( "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 8 ) ]]; then
    error "Python 3.8+ required. Found: $PY_VERSION"
    exit 1
fi
success "Python $PY_VERSION found at $(which python3)"

# 3. Install system-level libpcap
header "Installing system dependencies (libpcap)..."
if command -v apt-get &>/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq libpcap-dev python3-dev build-essential
    success "apt-get: libpcap-dev installed"
elif command -v dnf &>/dev/null; then
    sudo dnf install -y -q libpcap-devel python3-devel gcc
    success "dnf: libpcap-devel installed"
elif command -v yum &>/dev/null; then
    sudo yum install -y -q libpcap-devel python3-devel gcc
    success "yum: libpcap-devel installed"
elif command -v pacman &>/dev/null; then
    sudo pacman -S --noconfirm --needed libpcap python
    success "pacman: libpcap installed"
elif command -v zypper &>/dev/null; then
    sudo zypper install -y libpcap-devel python3-devel
    success "zypper: libpcap-devel installed"
else
    warn "Could not detect package manager. Install libpcap manually:"
    echo "  - Ubuntu/Debian: sudo apt-get install libpcap-dev"
    echo "  - Fedora/RHEL:   sudo dnf install libpcap-devel"
    echo "  - Arch:          sudo pacman -S libpcap"
fi

# 4. Create virtual environment
header "Setting up Python virtual environment..."
VENV_DIR="$(pwd)/venv"
if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
    success "Created venv at $VENV_DIR"
else
    info "venv already exists at $VENV_DIR — skipping creation"
fi

# 5. Install Python dependencies
header "Installing Python dependencies..."
"$VENV_DIR/bin/pip" install --quiet --upgrade pip
"$VENV_DIR/bin/pip" install --quiet -r requirements.txt
success "Python packages installed"

# 6. Grant network capabilities OR print sudo instructions
header "Configuring packet capture privileges..."
PYTHON_BIN=$(readlink -f "$VENV_DIR/bin/python3")

if [[ "$SUDO_ONLY" == true ]]; then
    warn "--sudo-only flag set: skipping setcap."
    echo -e "  Run the tool with: ${CYAN}sudo $VENV_DIR/bin/python3 src/main.py${NC}"
else
    if ! command -v setcap &>/dev/null; then
        warn "setcap not found. Install libcap2-bin (Debian/Ubuntu) or libcap (Fedora)."
        warn "Falling back to sudo mode."
    else
        info "Granting cap_net_raw to $PYTHON_BIN ..."
        if sudo setcap cap_net_raw,cap_net_admin=eip "$PYTHON_BIN"; then
            success "Capability granted. You can now run WITHOUT sudo:"
            echo -e "  ${CYAN}$VENV_DIR/bin/python3 src/main.py --interface eth0${NC}"
        else
            warn "setcap failed. You will need to run with sudo:"
            echo -e "  ${CYAN}sudo $VENV_DIR/bin/python3 src/main.py --interface eth0${NC}"
        fi
    fi
fi

# 7. Quick smoke test (no network, no root needed)
header "Running unit tests (simulation mode)..."
if "$VENV_DIR/bin/python3" tests/test_alerts.py > /dev/null 2>&1; then
    success "All tests passed"
else
    warn "Tests produced output -- run manually to inspect:"
    echo -e "  ${CYAN}$VENV_DIR/bin/python3 tests/test_alerts.py${NC}"
fi

# ---------------------------------------------------------------------------
header "=== Setup Complete ==="
# ---------------------------------------------------------------------------
echo
echo "Activate the virtual environment:"
echo -e "  ${CYAN}source venv/bin/activate${NC}"
echo
echo "Usage examples:"
echo -e "  ${CYAN}python3 src/main.py --list-interfaces${NC}          # list network interfaces"
echo -e "  ${CYAN}python3 src/main.py --interface eth0${NC}           # live capture (needs root/cap)"
echo -e "  ${CYAN}python3 src/main.py --pcap capture.pcap${NC}        # replay a pcap file (no root)"
echo -e "  ${CYAN}python3 src/main.py --interface eth0 --bpf 'tcp port 443'${NC}   # with BPF filter"
echo -e "  ${CYAN}python3 src/main.py --export-pcap${NC}              # auto-dump pcap on HIGH alerts"
echo
#!/usr/bin/env bash
# VulnCore install script
# Usage: curl -sSL https://vulncore.sh/install | bash
# Or locally: bash install.sh

set -euo pipefail

INSTALL_DIR="/opt/vulncore"
SERVICE_USER="vulncore"
REPO="https://github.com/yourusername/vulncore"
GREEN="\033[0;32m"
CYAN="\033[0;36m"
RED="\033[0;31m"
RESET="\033[0m"

info()  { echo -e "${CYAN}→${RESET} $*"; }
ok()    { echo -e "${GREEN}✓${RESET} $*"; }
error() { echo -e "${RED}✗${RESET} $*"; exit 1; }

echo ""
echo "  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗ ██████╗ ██████╗ ██████╗ ███████╗"
echo "  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝"
echo "  ██║   ██║██║   ██║██║     ██╔██╗ ██║██║     ██║   ██║██████╔╝█████╗  "
echo "  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║     ██║   ██║██╔══██╗██╔══╝  "
echo "   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║╚██████╗╚██████╔╝██║  ██║███████╗"
echo "    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝"
echo ""
echo "   Linux Vulnerability Scanner — Open Source"
echo ""

# ── Check root ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
  error "This installer requires root. Run: sudo bash install.sh"
fi

# ── Check OS ─────────────────────────────────────────────────────────────────
if [[ ! -f /etc/os-release ]]; then
  error "Cannot detect Linux distribution"
fi

source /etc/os-release
info "Detected OS: $PRETTY_NAME"

# ── Install build dependencies ────────────────────────────────────────────────
info "Installing build dependencies..."

if command -v apt-get &>/dev/null; then
  apt-get update -q
  apt-get install -y -q curl gcc build-essential pkg-config libssl-dev
elif command -v dnf &>/dev/null; then
  dnf install -y curl gcc openssl-devel pkg-config
elif command -v pacman &>/dev/null; then
  pacman -Sy --noconfirm curl gcc openssl
elif command -v apk &>/dev/null; then
  apk add --no-cache curl gcc musl-dev openssl-dev
else
  error "Unsupported package manager"
fi

# ── Install Rust ──────────────────────────────────────────────────────────────
if ! command -v rustup &>/dev/null; then
  info "Installing Rust toolchain..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
  source "$HOME/.cargo/env"
else
  info "Rust already installed: $(rustc --version)"
fi

# ── Install Go ────────────────────────────────────────────────────────────────
if ! command -v go &>/dev/null; then
  info "Installing Go 1.22..."
  GO_VER="1.22.3"
  curl -sSL "https://go.dev/dl/go${GO_VER}.linux-amd64.tar.gz" | tar -C /usr/local -xz
  export PATH="$PATH:/usr/local/go/bin"
  echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/go.sh
else
  info "Go already installed: $(go version)"
fi

# ── Clone / update repo ───────────────────────────────────────────────────────
if [[ -d "$INSTALL_DIR/.git" ]]; then
  info "Updating existing installation..."
  cd "$INSTALL_DIR" && git pull
else
  info "Cloning VulnCore..."
  git clone "$REPO" "$INSTALL_DIR"
  cd "$INSTALL_DIR"
fi

# ── Build ─────────────────────────────────────────────────────────────────────
info "Building Rust scanner..."
make build-scanner

info "Building Go API..."
make build-api

# ── Create user ───────────────────────────────────────────────────────────────
if ! id "$SERVICE_USER" &>/dev/null; then
  info "Creating service user: $SERVICE_USER"
  useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
fi

# ── Setup directories ─────────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR/data"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"

# ── Install systemd service ───────────────────────────────────────────────────
if command -v systemctl &>/dev/null; then
  info "Installing systemd service..."
  cp configs/vulncore.service /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable vulncore
  systemctl restart vulncore
  ok "Service installed and started"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
ok "VulnCore installed successfully!"
echo ""
echo "  Dashboard → http://localhost:8080"
echo "  API       → http://localhost:8080/api"
echo "  Config    → $INSTALL_DIR/configs/vulncore.toml"
echo "  Logs      → journalctl -u vulncore -f"
echo ""

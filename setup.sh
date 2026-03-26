#!/usr/bin/env bash
# mobile-security-agent setup script
# Installs all required tools

set -e

echo "╔══════════════════════════════════════════════════════╗"
echo "║     📱 Mobile Security Agent — Setup                 ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

OS="$(uname -s)"
ARCH="$(uname -m)"

# ── Helpers ──────────────────────────────────────────────────────────────────

info()    { echo "  ℹ️  $*"; }
success() { echo "  ✅ $*"; }
warn()    { echo "  ⚠️  $*"; }
error()   { echo "  ❌ $*"; exit 1; }

has() { command -v "$1" &>/dev/null; }

# ── Check Prerequisites ───────────────────────────────────────────────────────

echo "── Checking prerequisites ──────────────────────────────"

has python3 && success "python3: $(python3 --version)" || error "python3 required"
has java    && success "java: $(java -version 2>&1 | head -1)" || warn "java not found (required for jadx)"
has curl    && success "curl found" || error "curl required"
has unzip   && success "unzip found" || error "unzip required"

echo ""
echo "── Installing tools ────────────────────────────────────"

# ── jadx ─────────────────────────────────────────────────────────────────────
if has jadx; then
    success "jadx already installed: $(jadx --version 2>/dev/null | head -1)"
else
    info "Installing jadx..."
    JADX_VERSION="1.5.0"
    JADX_ZIP="jadx-${JADX_VERSION}.zip"
    JADX_URL="https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/${JADX_ZIP}"

    curl -L -o "/tmp/${JADX_ZIP}" "$JADX_URL"
    sudo mkdir -p /opt/jadx
    sudo unzip -o "/tmp/${JADX_ZIP}" -d /opt/jadx
    sudo chmod +x /opt/jadx/bin/jadx /opt/jadx/bin/jadx-gui
    sudo ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx
    success "jadx installed"
fi

# ── apktool ───────────────────────────────────────────────────────────────────
if has apktool; then
    success "apktool already installed"
else
    info "Installing apktool..."
    APKTOOL_VERSION="2.9.3"
    APKTOOL_JAR="apktool_${APKTOOL_VERSION}.jar"
    APKTOOL_URL="https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/${APKTOOL_JAR}"

    curl -L -o "/tmp/${APKTOOL_JAR}" "$APKTOOL_URL"
    sudo cp "/tmp/${APKTOOL_JAR}" /usr/local/lib/apktool.jar

    cat > /tmp/apktool_wrapper << 'EOF'
#!/usr/bin/env bash
exec java -jar /usr/local/lib/apktool.jar "$@"
EOF
    sudo mv /tmp/apktool_wrapper /usr/local/bin/apktool
    sudo chmod +x /usr/local/bin/apktool
    success "apktool installed"
fi

# ── ripgrep ───────────────────────────────────────────────────────────────────
if has rg; then
    success "ripgrep already installed"
else
    info "Installing ripgrep..."
    if [[ "$OS" == "Darwin" ]]; then
        if has brew; then
            brew install ripgrep
        else
            warn "Homebrew not found. Install ripgrep manually: https://github.com/BurntSushi/ripgrep"
        fi
    elif [[ "$OS" == "Linux" ]]; then
        if has apt-get; then
            sudo apt-get install -y ripgrep 2>/dev/null || true
        elif has dnf; then
            sudo dnf install -y ripgrep 2>/dev/null || true
        fi
    fi
    has rg && success "ripgrep installed" || warn "ripgrep not installed (will fall back to grep)"
fi

# ── apkeep ───────────────────────────────────────────────────────────────────
if has apkeep; then
    success "apkeep already installed"
else
    info "Installing apkeep (APK downloader)..."
    APKEEP_URL="https://github.com/EFForg/apkeep/releases/latest/download/apkeep-x86_64-unknown-linux-gnu"
    if [[ "$OS" == "Darwin" ]]; then
        APKEEP_URL="https://github.com/EFForg/apkeep/releases/latest/download/apkeep-x86_64-apple-darwin"
    fi

    curl -L -o /tmp/apkeep "$APKEEP_URL" 2>/dev/null && \
    sudo mv /tmp/apkeep /usr/local/bin/apkeep && \
    sudo chmod +x /usr/local/bin/apkeep && \
    success "apkeep installed" || warn "apkeep install failed — APK download will use fallback"
fi

# ── semgrep ───────────────────────────────────────────────────────────────────
if has semgrep; then
    success "semgrep already installed"
else
    info "Installing semgrep (optional — static analysis)..."
    # Try pipx first (works on Kali/Debian externally-managed envs)
    if has pipx; then
        pipx install semgrep --quiet 2>/dev/null && success "semgrep installed via pipx" && \
        export PATH="$PATH:$HOME/.local/bin"
    # Try apt (Kali has semgrep package)
    elif has apt-get; then
        sudo apt-get install -y semgrep 2>/dev/null && success "semgrep installed via apt" || \
        { info "Trying pipx install..."; sudo apt-get install -y pipx 2>/dev/null; pipx install semgrep 2>/dev/null && success "semgrep installed via pipx" || warn "semgrep install failed — continuing without it"; }
    elif has pip3; then
        pip3 install semgrep --break-system-packages --quiet 2>/dev/null && \
        success "semgrep installed" || warn "semgrep install failed — continuing without it"
    else
        warn "semgrep not installed — continuing without it"
    fi
fi

# ── ipatool (iOS) ─────────────────────────────────────────────────────────────
if has ipatool; then
    success "ipatool already installed"
else
    info "ipatool not found (optional — required for iOS IPA download)"
    if [[ "$OS" == "Darwin" ]] && has brew; then
        warn "Install with: brew install majd/repo/ipatool"
    else
        warn "Install from: https://github.com/majd/ipatool"
    fi
fi

# ── Python dependencies ───────────────────────────────────────────────────────
echo ""
echo "── Python dependencies ─────────────────────────────────"
pip3 install --quiet requests beautifulsoup4 2>/dev/null || pip3 install --break-system-packages --quiet requests beautifulsoup4 2>/dev/null || true
success "Python dependencies ready"

# ── Directory structure ───────────────────────────────────────────────────────
echo ""
echo "── Creating directories ────────────────────────────────"
mkdir -p downloads output
success "downloads/ and output/ directories ready"

# ── Install as Claude Code plugin ─────────────────────────────────────────────
echo ""
echo "── Claude Code plugin ──────────────────────────────────"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Method 1: workspace .claude/plugins (Claude Code project-level)
WORKSPACE_CLAUDE="${SCRIPT_DIR}/../.claude"
# Method 2: global ~/.claude
GLOBAL_CLAUDE="${HOME}/.claude"

INSTALLED=false
for CLAUDE_DIR in "$WORKSPACE_CLAUDE" "$GLOBAL_CLAUDE"; do
    if [[ -d "$CLAUDE_DIR" ]]; then
        PLUGINS_DIR="${CLAUDE_DIR}/plugins"
        mkdir -p "$PLUGINS_DIR"
        ln -sf "$SCRIPT_DIR" "${PLUGINS_DIR}/mobile-security-agent"
        success "Claude Code plugin → ${PLUGINS_DIR}/mobile-security-agent"
        INSTALLED=true
        break
    fi
done

if [[ "$INSTALLED" == false ]]; then
    # Create .claude in current dir for Claude Code to pick up
    mkdir -p "${SCRIPT_DIR}/.claude/plugins"
    ln -sf "$SCRIPT_DIR" "${SCRIPT_DIR}/.claude/plugins/mobile-security-agent"
    info "Created .claude/plugins/ in tool directory"
    info "To use with Claude Code: open this folder as your workspace"
fi

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ✅ Setup complete!                                   ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║  Usage:                                               ║"
echo "║                                                       ║"
echo "║  # CLI                                                ║"
echo "║  python3 msa.py scan <play_store_url>                 ║"
echo "║  python3 msa.py scan <app_store_url>                  ║"
echo "║  python3 msa.py scan app.apk                          ║"
echo "║                                                       ║"
echo "║  # Claude Code                                        ║"
echo "║  /scan https://play.google.com/store/apps/details?.. ║"
echo "╚══════════════════════════════════════════════════════╝"

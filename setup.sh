#!/usr/bin/env bash
# mobile-security-agent setup script
# Installs all required tools and fixes project structure

set -e

echo "╔══════════════════════════════════════════════════════╗"
echo "║  📱 Mobile Security Agent — Setup v1.2               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

OS="$(uname -s)"
ARCH="$(uname -m)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo "  ℹ️  $*"; }
success() { echo "  ✅ $*"; }
warn()    { echo "  ⚠️  $*"; }
error()   { echo "  ❌ $*"; exit 1; }
has()     { command -v "$1" &>/dev/null; }

# ── Fix project structure (scripts/ package) ──────────────────────────────────
echo "── Fixing project structure ────────────────────────────"

mkdir -p "${SCRIPT_DIR}/scripts"
touch "${SCRIPT_DIR}/scripts/__init__.py"

# Move any .py modules that are still in root into scripts/
for f in fetcher unpacker hunter reviewer reporter analyze_permissions; do
    if [[ -f "${SCRIPT_DIR}/${f}.py" ]] && [[ ! -f "${SCRIPT_DIR}/scripts/${f}.py" ]]; then
        cp "${SCRIPT_DIR}/${f}.py" "${SCRIPT_DIR}/scripts/${f}.py"
        info "Moved ${f}.py → scripts/${f}.py"
    fi
done

success "scripts/ package ready"

# ── Check Prerequisites ───────────────────────────────────────────────────────
echo ""
echo "── Checking prerequisites ──────────────────────────────"
has python3 && success "python3: $(python3 --version)"  || error "python3 required"
has java    && success "java: $(java -version 2>&1 | head -1)" || warn "java not found (required for jadx/apktool)"
has curl    && success "curl found"   || error "curl required"
has unzip   && success "unzip found"  || error "unzip required"

# ── jadx ─────────────────────────────────────────────────────────────────────
echo ""
echo "── Installing tools ────────────────────────────────────"

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
        has brew && brew install ripgrep || warn "Install ripgrep: https://github.com/BurntSushi/ripgrep"
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
    if [[ "$OS" == "Darwin" ]]; then
        APKEEP_URL="https://github.com/EFForg/apkeep/releases/latest/download/apkeep-x86_64-apple-darwin"
    else
        APKEEP_URL="https://github.com/EFForg/apkeep/releases/latest/download/apkeep-x86_64-unknown-linux-gnu"
    fi
    curl -L -o /tmp/apkeep "$APKEEP_URL" 2>/dev/null && \
        sudo mv /tmp/apkeep /usr/local/bin/apkeep && \
        sudo chmod +x /usr/local/bin/apkeep && \
        success "apkeep installed" || warn "apkeep install failed — APK download will use fallback method"
fi

# ── semgrep ───────────────────────────────────────────────────────────────────
if has semgrep; then
    success "semgrep already installed"
else
    info "Installing semgrep (optional static analysis)..."
    if has pipx; then
        pipx install semgrep --quiet 2>/dev/null && success "semgrep installed via pipx" || true
    elif has apt-get; then
        sudo apt-get install -y semgrep 2>/dev/null && success "semgrep installed via apt" || \
            { pip3 install semgrep --break-system-packages --quiet 2>/dev/null && \
              success "semgrep installed via pip" || warn "semgrep install failed — continuing without it"; }
    elif has pip3; then
        pip3 install semgrep --break-system-packages --quiet 2>/dev/null && \
            success "semgrep installed" || warn "semgrep install failed — continuing without it"
    else
        warn "semgrep not installed — continuing without it"
    fi
fi

# ── ipatool (iOS, optional) ───────────────────────────────────────────────────
if has ipatool; then
    success "ipatool already installed"
else
    if [[ "$OS" == "Darwin" ]] && has brew; then
        warn "ipatool not found (iOS IPA download). Install: brew install majd/repo/ipatool"
    else
        info "ipatool not available on Linux (iOS scanning requires manual IPA)"
    fi
fi

# ── Python dependencies ───────────────────────────────────────────────────────
echo ""
echo "── Python dependencies ─────────────────────────────────"
pip3 install --quiet requests beautifulsoup4 2>/dev/null || \
    pip3 install --break-system-packages --quiet requests beautifulsoup4 2>/dev/null || true
success "Python dependencies ready (requests, beautifulsoup4)"

# ── Gemini CLI check ──────────────────────────────────────────────────────────
echo ""
echo "── AI Backend (Gemini CLI) ─────────────────────────────"
if has gemini; then
    success "gemini CLI found: $(gemini --version 2>/dev/null || echo 'installed')"
else
    warn "Gemini CLI not found"
    info "Install with:"
    info "  npm install -g @google/gemini-cli"
    info "  gemini   ← run once to authenticate with Google account"
fi

if has node; then
    success "node.js: $(node --version)"
else
    warn "node.js not found — required for Gemini CLI"
    if [[ "$OS" == "Linux" ]]; then
        info "Install: curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash - && sudo apt-get install -y nodejs"
    elif [[ "$OS" == "Darwin" ]]; then
        info "Install: brew install node"
    fi
fi

# ── Directory structure ───────────────────────────────────────────────────────
echo ""
echo "── Creating directories ────────────────────────────────"
mkdir -p "${SCRIPT_DIR}/downloads" "${SCRIPT_DIR}/output"
success "downloads/ and output/ directories ready"

# ── Final summary ─────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ✅ Setup complete!                                   ║"
echo "╠══════════════════════════════════════════════════════╣"
echo "║                                                      ║"
echo "║  Quick start:                                        ║"
echo "║                                                      ║"
echo "║  # Check AI backend status                          ║"
echo "║  python3 msa.py ai-info                             ║"
echo "║                                                      ║"
echo "║  # Scan from Play Store URL                         ║"
echo "║  python3 msa.py scan \                              ║"
echo "║    'https://play.google.com/store/apps/...'         ║"
echo "║                                                      ║"
echo "║  # Scan local APK                                   ║"
echo "║  python3 msa.py scan app.apk                        ║"
echo "║                                                      ║"
echo "║  # Scan without AI (faster)                         ║"
echo "║  python3 msa.py scan app.apk --no-ai                ║"
echo "║                                                      ║"
echo "╚══════════════════════════════════════════════════════╝"

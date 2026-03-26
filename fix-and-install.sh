#!/usr/bin/env bash
# fix-and-install.sh
# Kali mirror засаад gemini CLI суулгана

set -e

echo "╔══════════════════════════════════════════════════════╗"
echo "║   🔧 Kali Mirror Fix + Gemini CLI Install            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Step 1: Mirror солих ─────────────────────────────────────────────────────
echo "── Step 1: Kali mirror засах ───────────────────────────"

SOURCES="/etc/apt/sources.list"
BACKUP="/etc/apt/sources.list.bak.$(date +%s)"

sudo cp "$SOURCES" "$BACKUP"
echo "  ✅ Backup: $BACKUP"

# Хамгийн найдвартай official mirror ашиглах
sudo tee "$SOURCES" > /dev/null << 'EOF'
# Kali Linux Official Repository
deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware
EOF

echo "  ✅ Mirror → kali.download (CloudFlare CDN, дэлхий даяар)"
echo ""

# ── Step 2: apt update ───────────────────────────────────────────────────────
echo "── Step 2: apt update ──────────────────────────────────"
sudo apt-get update -q
echo "  ✅ apt update хийгдлээ"
echo ""

# ── Step 3: Node.js суулгах ──────────────────────────────────────────────────
echo "── Step 3: Node.js + npm суулгах ──────────────────────"

if command -v node &>/dev/null; then
    echo "  ✅ Node.js байна: $(node --version)"
    echo "  ✅ npm байна: $(npm --version)"
else
    echo "  ℹ️  Node.js суулгаж байна..."

    # Method 1: apt (Kali repo)
    if sudo apt-get install -y nodejs npm 2>/dev/null; then
        echo "  ✅ Node.js суулгагдлаа: $(node --version)"
    else
        # Method 2: NodeSource (LTS)
        echo "  ℹ️  NodeSource-с суулгаж байна..."
        curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
        sudo apt-get install -y nodejs
        echo "  ✅ Node.js суулгагдлаа: $(node --version)"
    fi
fi
echo ""

# ── Step 4: Gemini CLI суулгах ───────────────────────────────────────────────
echo "── Step 4: Gemini CLI суулгах ──────────────────────────"

if command -v gemini &>/dev/null; then
    echo "  ✅ Gemini CLI байна: $(gemini --version 2>/dev/null || echo 'installed')"
else
    echo "  ℹ️  npm install -g @google/gemini-cli ..."
    # npm global install — sudo шаардлагагүй байх тохиолдолд
    if npm install -g @google/gemini-cli 2>/dev/null; then
        echo "  ✅ Gemini CLI суулгагдлаа"
    else
        # Prefix тохируулж дахин оролдох
        mkdir -p "$HOME/.npm-global"
        npm config set prefix "$HOME/.npm-global"
        export PATH="$HOME/.npm-global/bin:$PATH"
        npm install -g @google/gemini-cli
        echo ""
        echo "  ⚠️  PATH нэмнэ үү ~/.bashrc файлд:"
        echo '      export PATH="$HOME/.npm-global/bin:$PATH"'
        echo "      source ~/.bashrc"
    fi
fi
echo ""

# ── Step 5: Gemini CLI login ─────────────────────────────────────────────────
echo "── Step 5: Gemini CLI нэвтрэх ──────────────────────────"

if command -v gemini &>/dev/null; then
    echo ""
    echo "  🔑 Gemini CLI нэвтрэх шаардлагатай (нэг удаа):"
    echo "     gemini"
    echo "     → Google account-аар нэвтэрнэ"
    echo "     → Нэвтэрсний дараа exit хийнэ"
    echo ""
    echo "  Эсвэл API key ашиглах бол:"
    echo "     export GEMINI_API_KEY=your_key_here"
    echo "     # Key авах: https://aistudio.google.com/apikey"
else
    echo "  ❌ Gemini CLI суулгагдаагүй — дээрх алдааг шалгана уу"
fi

# ── Дүгнэлт ──────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  Дараагийн алхамууд:                                  ║"
echo "║                                                       ║"
echo "║  1. gemini          ← нэвтрэх (нэг удаа)             ║"
echo "║                                                       ║"
echo "║  2. python3 msa.py ai-info   ← шалгах                ║"
echo "║                                                       ║"
echo "║  3. python3 msa.py scan \\                            ║"
echo '║    "https://play.google.com/...?id=com.example.app"  ║'
echo "╚══════════════════════════════════════════════════════╝"

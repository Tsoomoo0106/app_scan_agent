#!/usr/bin/env bash
# fix-npm-gemini.sh — npm суулгаад gemini CLI суулгах

set -e

echo "🔧 npm + Gemini CLI суулгах"
echo "================================"

# ── npm суулгах ──────────────────────────────────────────────────────────────
echo ""
echo "── npm суулгах ─────────────────────────────────────────"

if command -v npm &>/dev/null; then
    echo "  ✅ npm байна: $(npm --version)"
else
    echo "  ℹ️  npm суулгаж байна..."
    sudo apt-get install -y npm
    echo "  ✅ npm: $(npm --version)"
fi

# ── PATH шалгах ───────────────────────────────────────────────────────────────
echo ""
echo "── PATH тохиргоо ───────────────────────────────────────"

# npm global bin path тодорхойлох
NPM_PREFIX="$(npm config get prefix 2>/dev/null || echo "$HOME/.npm-global")"
NPM_BIN="$NPM_PREFIX/bin"
echo "  npm prefix: $NPM_PREFIX"
echo "  npm bin   : $NPM_BIN"

# PATH-д нэмэх
export PATH="$NPM_BIN:$PATH"

# ~/.bashrc-д нэмэх (байхгүй бол)
BASHRC="$HOME/.bashrc"
if ! grep -q "$NPM_BIN" "$BASHRC" 2>/dev/null; then
    echo "" >> "$BASHRC"
    echo "# npm global binaries" >> "$BASHRC"
    echo "export PATH=\"$NPM_BIN:\$PATH\"" >> "$BASHRC"
    echo "  ✅ PATH нэмэгдлээ ~/.bashrc"
fi

# ── Gemini CLI суулгах ───────────────────────────────────────────────────────
echo ""
echo "── Gemini CLI суулгах ──────────────────────────────────"

if command -v gemini &>/dev/null; then
    echo "  ✅ Gemini CLI байна: $(gemini --version 2>/dev/null || echo 'ok')"
else
    echo "  ℹ️  npm install -g @google/gemini-cli ..."
    npm install -g @google/gemini-cli
    echo "  ✅ Gemini CLI суулгагдлаа"
fi

# ── Шалгах ───────────────────────────────────────────────────────────────────
echo ""
echo "── Шалгах ──────────────────────────────────────────────"
echo "  node  : $(node --version)"
echo "  npm   : $(npm --version)"
echo "  gemini: $(command -v gemini || echo '❌ PATH-д олдсонгүй')"

# ── Дараагийн алхам ──────────────────────────────────────────────────────────
echo ""
echo "================================"

if command -v gemini &>/dev/null; then
    echo "✅ Бэлэн! Дараагийн алхамууд:"
    echo ""
    echo "  # PATH идэвхжүүлэх (одоогийн session)"
    echo "  export PATH=\"$NPM_BIN:\$PATH\""
    echo ""
    echo "  # Gemini-д нэвтрэх (нэг удаа)"
    echo "  gemini"
    echo ""
    echo "  # Эсвэл API key ашиглах"
    echo "  export GEMINI_API_KEY=your_key"
    echo "  # Key авах: https://aistudio.google.com/apikey"
    echo ""
    echo "  # Scan ажиллуулах"
    echo "  python3 msa.py ai-info"
    echo "  python3 msa.py scan 'https://play.google.com/...'"
else
    echo "⚠️  gemini command PATH-д байхгүй."
    echo "   Доорх командыг ажиллуулаад дахин оролдно уу:"
    echo ""
    echo "   export PATH=\"$NPM_BIN:\$PATH\""
    echo "   gemini --version"
fi

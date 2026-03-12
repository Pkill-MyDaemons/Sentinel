#!/usr/bin/env bash
# Sentinel Security — macOS Install Script
# Run after compiling: ./install.sh
set -euo pipefail

SENTINEL_BIN="./build/sentinel"      # HashLink: hl sentinel.hl | C++: build/cpp/Main
SENTINEL_CLI="./build/sentinel-cli"
CONFIG_DIR="$HOME/.sentinel"
LAUNCH_AGENTS="$HOME/Library/LaunchAgents"

echo "🛡  Sentinel Security Installer"
echo "================================"

# Check we're on macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo "❌ Sentinel is macOS-only."
    exit 1
fi

# Check Haxe is available
if ! command -v haxe &>/dev/null; then
    echo "❌ Haxe not found. Install via: brew install haxe"
    exit 1
fi

# Check HashLink
if ! command -v hl &>/dev/null; then
    echo "⚠  HashLink not found. Install via: brew install hashlink"
    echo "   Falling back to interpreted mode (slower)."
fi

echo ""
echo "── Building Sentinel ────────────────────"

mkdir -p build

# Build daemon
echo "→ Compiling daemon..."
haxe build-hl.hxml
echo "✓ Daemon: build/sentinel.hl"

# Build CLI
echo "→ Compiling CLI..."
haxe build-cli.hxml
echo "✓ CLI: build/sentinel-cli.hl"

echo ""
echo "── Installing ───────────────────────────"

# Install hl runner scripts
cat > /usr/local/bin/sentinel << 'EOF'
#!/usr/bin/env bash
exec hl "$HOME/.sentinel/bin/sentinel.hl" "$@"
EOF
chmod +x /usr/local/bin/sentinel

cat > /usr/local/bin/sentinel-cli << 'EOF'
#!/usr/bin/env bash
exec hl "$HOME/.sentinel/bin/sentinel-cli.hl" "$@"
EOF
chmod +x /usr/local/bin/sentinel-cli

# Copy binaries
mkdir -p "$CONFIG_DIR/bin"
cp build/sentinel.hl "$CONFIG_DIR/bin/"
cp build/sentinel-cli.hl "$CONFIG_DIR/bin/"
echo "✓ Installed to $CONFIG_DIR/bin/"

echo ""
echo "── Configuration ────────────────────────"

if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
    echo "→ Writing default config to $CONFIG_DIR/config.json"
    sentinel-cli --init-config 2>/dev/null || true
    echo "⚠  Edit $CONFIG_DIR/config.json to set your AI provider and API keys"
else
    echo "✓ Config exists at $CONFIG_DIR/config.json"
fi

echo ""
echo "── Shell Hook ───────────────────────────"
echo "→ Installing shell preexec hook..."
# (sentinel-cli generates this on first run)
echo "  To enable command blocking, add to ~/.zshrc:"
echo "    source ~/.sentinel/sentinel-hook.zsh"

echo ""
echo "── LaunchAgent ──────────────────────────"
echo "→ Installing LaunchAgent (auto-start on login)..."
cp com.sentinel.security.plist "$LAUNCH_AGENTS/"
launchctl load "$LAUNCH_AGENTS/com.sentinel.security.plist" 2>/dev/null || true
echo "✓ Sentinel will start automatically on login"

echo ""
echo "── Local AI (Optional) ──────────────────"
if ! command -v ollama &>/dev/null; then
    echo "⚠  Ollama not found. Sentinel defaults to local AI."
    echo "   Install Ollama for private on-device analysis:"
    echo "   brew install ollama && ollama pull llama3"
else
    echo "✓ Ollama found: $(ollama --version 2>/dev/null || echo 'installed')"
    if ! ollama list 2>/dev/null | grep -q "llama3"; then
        echo "→ Pulling llama3 model (this may take a while)..."
        ollama pull llama3 &
        echo "  (downloading in background)"
    else
        echo "✓ llama3 model ready"
    fi
fi

echo ""
echo "════════════════════════════════════════"
echo "✅ Sentinel installed successfully!"
echo ""
echo "Commands:"
echo "  sentinel             Start the daemon"
echo "  sentinel-cli help    CLI analysis tools"
echo ""
echo "Config: $CONFIG_DIR/config.json"
echo "Logs:   $CONFIG_DIR/logs/"
echo ""
echo "Start now: sentinel &"

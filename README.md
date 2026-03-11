# 🛡 Sentinel Security

**AI-powered macOS security monitor** — written in Haxe, compiles to native via HashLink or C++.

Sentinel runs as a background daemon and actively intercepts shell commands, validates app update prompts, audits Chrome extension permissions, and tracks per-app network connections — all with an AI analysis backend that defaults to a fully local, private model via Ollama.

A **native macOS GUI app** built with [HaxeUI](https://haxeui.org) + [hxWidgets](https://github.com/haxeui/hxWidgets) (wxWidgets backend) lets you review security alerts and edit configuration without touching JSON files.

---

## What It Does

| Module | What It Monitors | How It Decides |
|--------|-----------------|----------------|
| **TerminalWatcher** | Shell commands (zsh/bash history + preexec hook) | Heuristic rules → GitHub repo fetch → AI analysis + macOS codesign |
| **UpdateMonitor** | App update prompts (Info.plist + Sparkle feeds) | Version lookup → domain check → AI validation |
| **ExtensionMonitor** | Chrome extensions (manifest.json permissions) | Dangerous permission check → AI analysis → Chrome policy block |
| **NetworkMonitor** | Per-app TCP/UDP connections (via lsof) | Suspicious port detection → rapid connection alerting |

---

## File Structure

```
sentinel/
│
├── src/sentinel/                      # All Haxe source code
│   │
│   ├── Main.hx                        # Daemon entry point — boots all modules
│   ├── CLI.hx                         # CLI tool (analyze-cmd, codesign, etc.)
│   │
│   ├── app/                           # ── Native GUI app (HaxeUI + hxWidgets) ──
│   │   ├── SentinelApp.hx             # App entry point — Frame, Notebook, Timer
│   │   ├── AlertsView.hx              # Alerts tab: ListView, detail panel, review/dismiss
│   │   └── ConfigView.hx             # Config tab: five-section tabbed editor
│   │
│   ├── config/
│   │   └── Config.hx                  # Config loader/writer (~/.sentinel/config.json)
│   │
│   ├── core/
│   │   ├── EventBus.hx                # Typed publish/subscribe event bus
│   │   ├── IModule.hx                 # Module interface (start/stop/name)
│   │   ├── RiskLevel.hx               # RiskLevel enum (Safe/Low/Medium/High/Critical)
│   │   └── Logger.hx                  # Console + rotating file logger
│   │
│   ├── ai/
│   │   ├── AIEngine.hx                # AI provider router (Ollama / Anthropic / OpenAI)
│   │   ├── AIResult.hx                # Typed AI analysis result
│   │   ├── RepoData.hx                # GitHub repo data shape
│   │   └── GitHubFetcher.hx           # GitHub REST API + raw file fetcher
│   │
│   ├── modules/
│   │   ├── TerminalWatcher.hx         # MODULE 1 — shell command interception
│   │   ├── UpdateMonitor.hx           # MODULE 2 — app update validation
│   │   ├── ExtensionMonitor.hx        # MODULE 3 — Chrome extension auditor
│   │   └── NetworkMonitor.hx          # MODULE 4 — per-app connection tracker
│   │
│   ├── gui/
│   │   └── AlertStore.hx              # Event→Alert converter; persists ~/.sentinel/alerts.json
│   │
│   └── platform/
│       ├── UnixSocket.hx              # Haxe extern — HL + hxcpp native socket bridge
│       ├── UnixSocketServer.hx        # Multi-client accept-loop server
│       ├── HttpsClient.hx             # HTTPS via sys.ssl.Socket (no hxssl needed)
│       ├── MacSecurity.hx             # codesign / spctl / xattr wrappers
│       ├── Signal.hx                  # SIGINT/SIGTERM handlers
│       └── Verdict.hx                 # Verdict enum + AnalysisResult typedef
│
├── assets/                            # HaxeUI XML layouts + stylesheet
│   ├── alerts-view.xml                # Alerts tab layout (ListView + detail panel)
│   ├── config-view.xml                # Config tab layout (five TabView sections)
│   └── sentinel-theme.css             # HaxeUI component styles
│
├── native/                            # C/C++ native extension layer
│   ├── sentinel_socket.c              # POSIX Unix socket server for HashLink (.hdll)
│   ├── sentinel_socket_cpp.cpp        # Same as extern "C" for hxcpp target
│   └── Makefile                       # Builds sentinel_socket.hdll
│
├── tests/
│   └── SocketTest.hx                  # Integration tests for the socket server
│
├── build.hxml                         # Default build (HashLink bytecode daemon)
├── build-hl.hxml                      # HashLink bytecode daemon
├── build-cpp.hxml                     # C++ daemon via hxcpp
├── build-hlc.hxml                     # HashLink/C export for CMake
├── build-app.hxml                     # ★ Native GUI app (hxcpp + hxWidgets + HaxeUI)
├── build-cli.hxml                     # CLI tool
├── build-test.hxml                    # Socket integration tests
├── Build.xml                          # hxcpp extra files + macOS framework linker flags
├── CMakeLists.txt                     # CMake config for HashLink/C native binary
├── sentinel.entitlements              # macOS entitlements (network client, file read)
├── com.sentinel.security.plist        # LaunchAgent — auto-start on login
├── install.sh                         # Installer script
└── README.md                          # This file
```

### Runtime files (created on first run)

```
~/.sentinel/
├── config.json          # User configuration (auto-created with defaults)
├── alerts.json          # Alert history — written by daemon, read by GUI app
├── sentinel.sock        # Unix domain socket (daemon creates this)
├── sentinel-hook.zsh    # zsh preexec hook  → source from ~/.zshrc
├── sentinel-hook.bash   # bash DEBUG trap hook → source from ~/.bashrc
├── bin/
│   ├── sentinel.hl      # Installed daemon bytecode
│   └── sentinel-cli.hl  # Installed CLI bytecode
└── logs/
    └── sentinel-YYYYMMDD.log
```

---

## Quick Start

```bash
# 1. Install daemon dependencies
brew install haxe hashlink ollama

# 2. Install GUI dependencies (wxWidgets + HaxeUI haxelibs)
brew install wxwidgets
haxelib install hxWidgets
haxelib install haxeui-core
haxelib install haxeui-hxwidgets

# 3. Start local AI (private, on-device)
ollama serve &
ollama pull llama3

# 4. Build native socket extension
cd native && make && make install && cd ..

# 5. Build and run the daemon
haxe build-hl.hxml
hl build/sentinel.hl &

# 6. Build and launch the GUI app
haxe build-app.hxml
./build/app/SentinelApp

# 7. Enable shell interception
echo "source ~/.sentinel/sentinel-hook.zsh" >> ~/.zshrc
source ~/.sentinel/sentinel-hook.zsh
```

---

## Native GUI App

The GUI is a **separate native binary** from the daemon — it can be opened and closed independently. It does not embed a browser or any web runtime. All widgets are rendered by wxWidgets using native macOS Cocoa controls.

```
┌─────────────────────────────────────────────────────────────┐
│ Sentinel Security                                           │
├────────────┬────────────────────────────────────────────────┤
│  Alerts  │  Config                                         │  ← native tab bar
├────────────┴────────────────────────────────────────────────┤
│ [All][New][Terminal][Updates][Extensions][Network] [Refresh] │  filter toolbar
├──────────────────────────┬──────────────────────────────────┤
│ ● [HIGH]  Command inter… │  Command intercepted             │
│   Terminal · 14:22:01    │  HIGH  ·  Terminal               │
│                          │  2025-03-11 14:22:01             │
│   [LOW]   Update detect… │                                  │
│   Updates · 14:18:44     │  Details                         │
│                          │  cmd: curl … | bash              │
│   [SAFE]  Repo scanned   │  AI: looks like a crypto miner   │
│   Terminal · 14:10:02    │                                  │
│                          │  Status: new                     │
│                          │  ┌──────────────┐ ┌──────────┐  │
│                          │  │ ✓ Reviewed   │ │ Dismiss  │  │
│                          │  └──────────────┘ └──────────┘  │
├──────────────────────────┴──────────────────────────────────┤
│ ● Daemon: running    │    3 new alerts                      │  status bar
└─────────────────────────────────────────────────────────────┘
```

### How the GUI and daemon communicate

The GUI and daemon share two files in `~/.sentinel/`:

| File | Written by | Read by | Purpose |
|------|-----------|---------|---------|
| `alerts.json` | Daemon (`AlertStore`) | GUI (`AlertsView`) | Alert history + status |
| `config.json` | GUI (`ConfigView`) | Daemon (`Config`) | All settings |

The GUI **polls `alerts.json` every 5 seconds** — no IPC socket needed for display. When you mark an alert reviewed or dismissed, the GUI writes the status back to `alerts.json` directly. The daemon re-reads `alerts.json` on startup (or SIGHUP) so statuses survive restarts.

Config changes saved in the GUI take effect when the daemon next calls `Config.load()` — send it `SIGHUP` or restart via the LaunchAgent to apply immediately.

### Building the GUI app

```bash
# Prerequisites (one-time)
brew install wxwidgets
haxelib install hxWidgets
haxelib install haxeui-core
haxelib install haxeui-hxwidgets

# Compile
haxe build-app.hxml

# Run
./build/app/SentinelApp
```

The `assets/` folder (XML layouts + CSS) must be present in the working directory at runtime, or embedded via `-resource` in `build-app.hxml` (already configured).

---

## Compile Targets

> **Note:** After `brew install hashlink`, the `hl` binary is at
> `/opt/homebrew/bin/hl` (Apple Silicon) or `/usr/local/bin/hl` (Intel).

### Daemon — HashLink bytecode (fastest build, great for development)
```bash
cd native && make && make install && cd ..
haxe build-hl.hxml
hl build/sentinel.hl
```

### Daemon — C++ native binary (production)
```bash
haxelib install hxcpp
cd native && make && cd ..
haxe build-cpp.hxml
./build/cpp/Main
```

### GUI App — native (hxWidgets + HaxeUI)
```bash
haxe build-app.hxml
./build/app/SentinelApp
```

### CLI tool
```bash
haxe build-cli.hxml
hl build/sentinel-cli.hl analyze-cmd "brew tap suspicious/tap"
```

---

## AI Configuration

Sentinel defaults to **local Ollama** — commands and repo contents never leave your machine. Change the provider in the GUI Config tab, or edit `~/.sentinel/config.json` directly.

```jsonc
// ~/.sentinel/config.json
{
  "ai": {
    "provider": "local",              // "local" | "anthropic" | "openai"
    "localModel": "llama3",
    "localEndpoint": "http://localhost:11434",
    "anthropicKey": "",               // optional cloud fallback
    "anthropicModel": "claude-sonnet-4-20250514",
    "openaiKey": "",
    "blockThreshold": 0.85,           // auto-block above this risk score
    "warnThreshold": 0.50
  }
}
```

### Model recommendations

| Model | Size | Best for |
|-------|------|----------|
| `llama3` | 4.7 GB | General analysis, reliable JSON output |
| `codellama` | 3.8 GB | Code-heavy repo analysis |
| `mistral` | 4.1 GB | Fast responses, lower memory |
| `phi3` | 2.3 GB | Minimal RAM, lighter reasoning |

---

## Terminal Command Blocking

```
Shell              Sentinel daemon
  │                      │
  │─── cmd\n ───────────►│  1. heuristic check    (< 1ms)
  │                      │  2. GitHub repo fetch  (1–5s, if applicable)
  │                      │  3. AI analysis        (0.5–10s)
  │◄─── ALLOW ───────────│     └─ timeout: WARN immediately, finish in background
  │     WARN:<reason>    │
  │     BLOCK            │
```

### What triggers analysis

| Pattern | Example | Reason |
|---------|---------|--------|
| curl-pipe-bash | `curl url \| bash` | Classic malware delivery |
| bash process substitution | `bash <(curl url)` | Same, more obfuscated |
| Third-party brew tap | `brew tap user/repo` | Arbitrary code at install time |
| Base64 decode+exec | `base64 -d payload \| sh` | Obfuscated payload |
| sudo + download | `sudo curl ... -o /usr/local/bin/x` | Privileged install |
| Security disable | `csrutil disable` | Disabling macOS protections |
| LaunchAgent load | `launchctl load evil.plist` | Persistence mechanism |
| DYLD injection | `DYLD_INSERT_LIBRARIES=...` | Dynamic library hijack |

---

## CLI Reference

```bash
sentinel-cli analyze-cmd  "brew tap suspicious/tap && bash install.sh"
sentinel-cli analyze-repo https://github.com/owner/repo
sentinel-cli codesign     /Applications/DownloadedApp.app
sentinel-cli check-extension ~/Downloads/extension/manifest.json
sentinel-cli check-update /Applications/SomeApp.app/Contents/Info.plist
```

---

## macOS Tools Used (Built-in)

| Tool | Used By | Purpose |
|------|---------|---------| 
| `codesign` | MacSecurity | Verify binary signatures |
| `spctl` | MacSecurity | Gatekeeper acceptance check |
| `xattr` | MacSecurity | Read quarantine attribute |
| `plutil` | UpdateMonitor | Convert binary/XML plists |
| `lsof -i` | NetworkMonitor | Per-process network connections |
| `osascript` | All modules | macOS notifications + dialogs |
| `nc -U` | Shell hook | Unix socket client in preexec hook |
| `launchctl` | install.sh | Register LaunchAgent |

---

## Security Philosophy

- ✅ **SIP stays ON** — never asks you to disable System Integrity Protection
- ✅ **No kernel extension** — entirely user-space, no elevated privileges
- ✅ **Local AI by default** — commands never leave your machine
- ✅ **Fail open** — if daemon is down, commands proceed normally
- ✅ **Auditable** — every decision logged to `~/.sentinel/logs/` with full AI reasoning
- ✅ **No auto-block by default** — `autoBlock: false`; you confirm WARNs
- ✅ **Native GUI, no browser** — HaxeUI + wxWidgets renders real Cocoa controls

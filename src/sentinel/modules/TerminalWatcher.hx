package sentinel.modules;

import sentinel.core.IModule;
import sentinel.core.EventBus;
import sentinel.core.Logger;
import sentinel.ai.AIEngine;
import sentinel.ai.AIResult;
import sentinel.ai.GitHubFetcher;
import sentinel.ai.RepoData;
import sentinel.platform.MacSecurity;
import sentinel.platform.UnixSocketServer;
import sentinel.platform.Verdict;
import sentinel.config.Config;
import sys.io.File;
import sys.io.FileSeek;
import sys.FileSystem;

using StringTools;

/**
 * TerminalWatcher — Module 1
 *
 * Two layers:
 *   A) Passive: history file tailing (no blocking, just alerting)
 *   B) Active:  preexec hook via shell socket (blocking capable)
 */
class TerminalWatcher implements IModule {

    var bus:EventBus;
    var ai:AIEngine;
    var fetcher:GitHubFetcher;
    var cfg:sentinel.config.TerminalConfig;
    var watchedFiles:Map<String, Int> = new Map();
    var running:Bool = false;
    var workerThread:sys.thread.Thread;
    var socketServer:Null<UnixSocketServer> = null;
    var socketPath:String = "";

    public function new(bus:EventBus, ai:AIEngine) {
        this.bus = bus;
        this.ai = ai;
        this.cfg = Config.get().terminal;
        this.fetcher = new GitHubFetcher(cfg.githubToken);
    }

    public function name():String return "TerminalWatcher";

    public function start() {
        var home = Sys.getEnv("HOME") ?? "/tmp";
        for (path in cfg.watchPaths) {
            // StringTools.replace used via 'using StringTools'
            var resolved = path.replace("~", home);
            if (FileSystem.exists(resolved)) {
                watchedFiles.set(resolved, FileSystem.stat(resolved).size);
                Logger.info('[Terminal] Watching: $resolved');
            }
        }
        startSocketListener();
        running = true;
        workerThread = sys.thread.Thread.create(watchLoop);
    }

    public function stop() {
        running = false;
        if (socketServer != null) {
            socketServer.stop();
            socketServer = null;
        }
    }

    // ----------------------------------------------------------------
    // Passive: history file tailing
    // ----------------------------------------------------------------

    function watchLoop() {
        while (running) {
            for (path in watchedFiles.keys()) {
                try {
                    var currentSize = FileSystem.stat(path).size;
                    var lastSize = watchedFiles.get(path);
                    if (currentSize > lastSize) {
                        var f = File.read(path, false);
                        f.seek(lastSize, FileSeek.SeekBegin);
                        var newContent = f.readAll().toString();
                        f.close();
                        watchedFiles.set(path, currentSize);
                        processNewCommands(newContent);
                    }
                } catch (e:Dynamic) {}
            }
            Sys.sleep(0.5);
        }
    }

    function processNewCommands(content:String) {
        for (line in content.split("\n")) {
            var cmd = cleanHistoryLine(line);
            if (cmd.length < 3) continue;
            Logger.debug('[Terminal] New command: $cmd');
            analyzeCommand(cmd);
        }
    }

    /** Strip zsh timestamp prefix: `: 1234567890:0;actual command` */
    static function cleanHistoryLine(line:String):String {
        var re = ~/^: \d+:\d+;/;
        return re.replace(line, "").trim();
    }

    // ----------------------------------------------------------------
    // Active: Unix socket server for shell preexec hook
    // ----------------------------------------------------------------

    function startSocketListener() {
        var home = Sys.getEnv("HOME") ?? "/tmp";
        socketPath = '$home/.sentinel/sentinel.sock';
        writeShellHook(home, socketPath);

        #if (hl || hlc || cpp)
        socketServer = new UnixSocketServer(socketPath, handleSocketCommand);
        socketServer.maxAnalysisMs = 8000;
        try {
            socketServer.start();
            Logger.info('[Terminal] Socket server active at $socketPath');
            Logger.info('[Terminal] Add to ~/.zshrc: source ~/.sentinel/sentinel-hook.zsh');
        } catch (e:Dynamic) {
            Logger.error('[Terminal] Could not start socket server: $e');
            Logger.warn('[Terminal] Falling back to passive history monitoring only');
        }
        #else
        Logger.info('[Terminal] Shell hook written (socket server requires native build).');
        #end
    }

    function handleSocketCommand(cmd:String):AnalysisResult {
        Logger.debug('[Socket→] $cmd');

        var h = heuristicCheck(cmd);
        if (h.safe) {
            return { verdict: Allow, reason: "" };
        }

        Logger.warn('[Socket] Heuristic flag: ${h.reason}');

        var repoUrl = GitHubFetcher.parseRepoFromCommand(cmd);
        var repoData:Null<RepoData> = null;

        if (repoUrl != null) {
            Logger.info('[Socket] Fetching repo: $repoUrl');
            try {
                repoData = fetcher.fetch(repoUrl);
                Logger.info('[Socket] Repo: ${repoData.stars}★ created ${repoData.createdAt}');
            } catch (e:Dynamic) {
                Logger.warn('[Socket] Repo fetch failed: $e');
            }
        }

        // repoUrl is Null<String> — use repoData branch only when both are non-null
        var aiResult:AIResult = (repoData != null && repoUrl != null)
            ? ai.analyzeRepo(repoUrl, repoData)
            : ai.analyzeCommand(cmd);

        if (repoData != null) {
            var codesignNote = runCodesignOnRepo(repoData, cmd);
            if (codesignNote != null) aiResult.warnings.push("codesign: " + codesignNote);
        }

        bus.emitNow(TerminalCommand(cmd, aiResult.riskLevel,
            aiResult.summary + " | " + aiResult.warnings.join("; ")));

        var cfg = Config.get();
        var score = aiResult.riskScore;

        if (score >= cfg.ai.blockThreshold || aiResult.recommendation == "BLOCK") {
            Logger.critical('[Socket] BLOCKING: $cmd (score=$score)');
            showAlert("BLOCKED", cmd, aiResult.summary);
            return { verdict: Block, reason: aiResult.summary };
        }

        if (score >= cfg.ai.warnThreshold || aiResult.recommendation == "WARN") {
            var warningText = aiResult.summary;
            if (aiResult.warnings.length > 0)
                warningText += ' [' + aiResult.warnings.join('; ') + ']';
            Logger.warn('[Socket] WARN: $warningText');
            return { verdict: Warn(warningText), reason: warningText };
        }

        return { verdict: Allow, reason: "" };
    }

    // ----------------------------------------------------------------
    // Shell hook generation
    // ----------------------------------------------------------------

    function writeShellHook(home:String, socketPath:String) {
        var dir = '$home/.sentinel';
        if (!FileSystem.exists(dir)) FileSystem.createDirectory(dir);
        File.saveContent('$dir/sentinel-hook.zsh',  buildZshHook(socketPath));
        File.saveContent('$dir/sentinel-hook.bash', buildBashHook(socketPath));
        Logger.debug('[Terminal] Shell hooks written to $dir');
    }

    /**
     * Build the zsh hook using double-quoted multiline strings.
     *
     * Haxe double-quoted strings ("...") do NOT interpolate $VAR or ${VAR},
     * so shell variables pass through verbatim. Only the socketPath value
     * itself is spliced in via string concatenation.
     *
     * This is Haxe's equivalent of a heredoc for shell-script generation.
     */
    static function buildZshHook(socketPath:String):String {
        return
"#!/usr/bin/env zsh
# Sentinel Security — zsh preexec hook
# Source this from ~/.zshrc:
#   echo \"source ~/.sentinel/sentinel-hook.zsh\" >> ~/.zshrc

SENTINEL_SOCKET=\"" + socketPath + "\"
SENTINEL_TIMEOUT=10
SENTINEL_ENABLED=1
_SENTINEL_SAFE_CMDS=\"ls|ll|la|cd|pwd|echo|cat|man|help|clear|history|exit|which|type|alias|export|unset|set|env|git|vim|nano|code\"

function sentinel_check() {
    [[ \"$SENTINEL_ENABLED\" != \"1\" ]] && return 0
    [[ ! -S \"$SENTINEL_SOCKET\" ]]    && return 0

    local cmd=\"$1\"
    local trimmed=\"${cmd## }\"
    [[ ${#trimmed} -lt 4 ]] && return 0

    local first_word=\"${trimmed%% *}\"
    if [[ \"$first_word\" =~ ^($_SENTINEL_SAFE_CMDS)$ ]]; then
        return 0
    fi

    printf \"\\r\\033[90m🛡 sentinel...\\033[0m\" >&2

    local response
    response=$(printf \"%s\\n\" \"$trimmed\" | nc -U -w$SENTINEL_TIMEOUT \"$SENTINEL_SOCKET\" 2>/dev/null)
    local nc_exit=$?
    printf \"\\r\\033[K\" >&2

    [[ $nc_exit -ne 0 || -z \"$response\" ]] && return 0

    if [[ \"$response\" == \"BLOCK\" ]]; then
        echo \"\" >&2
        echo \"╔══════════════════════════════════════════════╗\" >&2
        echo \"║  🚨  SENTINEL BLOCKED THIS COMMAND           ║\" >&2
        echo \"╚══════════════════════════════════════════════╝\" >&2
        echo \"   ${trimmed:0:80}\" >&2
        echo \"   See ~/.sentinel/logs/ for details.\" >&2
        return 1

    elif [[ \"$response\" == \"WARN:\"* ]]; then
        local reason=\"${response#WARN:}\"
        echo \"\" >&2
        echo \"┌─────────────────────────────────────────────┐\" >&2
        echo \"│  ⚠️   SENTINEL WARNING                      │\" >&2
        echo \"└─────────────────────────────────────────────┘\" >&2
        echo \"  $reason\" >&2
        echo -n \"  Run anyway? [y/N] \" >&2
        local answer
        read -r answer </dev/tty
        echo \"\" >&2
        [[ \"$answer\" == \"y\" || \"$answer\" == \"Y\" ]] && return 0 || return 1
    fi
    return 0
}

autoload -Uz add-zsh-hook
function _sentinel_preexec() {
    sentinel_check \"$1\" || {
        zle .kill-whole-line 2>/dev/null
        zle .accept-line     2>/dev/null
        return 1
    }
}
add-zsh-hook preexec _sentinel_preexec

function sentinel-off()    { SENTINEL_ENABLED=0; echo \"🛡 Sentinel paused\"; }
function sentinel-on()     { SENTINEL_ENABLED=1; echo \"🛡 Sentinel active\"; }
function sentinel-status() {
    if [[ -S \"$SENTINEL_SOCKET\" ]]; then
        echo \"🛡 Sentinel: RUNNING ($SENTINEL_SOCKET)\"
    else
        echo \"🛡 Sentinel: NOT RUNNING\"
    fi
}

echo \"🛡  Sentinel active — sentinel-off to pause, sentinel-status to check\"
";
    }

    static function buildBashHook(socketPath:String):String {
        return
"#!/usr/bin/env bash
# Sentinel Security — bash DEBUG trap hook
# Source from ~/.bashrc:
#   echo \"source ~/.sentinel/sentinel-hook.bash\" >> ~/.bashrc

SENTINEL_SOCKET=\"" + socketPath + "\"
SENTINEL_TIMEOUT=10
SENTINEL_ENABLED=1
_SENTINEL_PREV_CMD=\"\"
_SENTINEL_SAFE_CMDS=\"ls|ll|la|cd|pwd|echo|cat|man|help|clear|history|exit|which|type|alias|export|unset|set|env|git|vim|nano|code\"

_sentinel_preexec() {
    [[ \"$SENTINEL_ENABLED\" != \"1\" ]] && return
    [[ ! -S \"$SENTINEL_SOCKET\" ]]    && return

    local cmd=\"$BASH_COMMAND\"
    [[ \"$cmd\" == \"$_SENTINEL_PREV_CMD\" ]] && return
    _SENTINEL_PREV_CMD=\"$cmd\"

    local trimmed=\"${cmd## }\"
    [[ ${#trimmed} -lt 4 ]] && return

    local first_word=\"${trimmed%% *}\"
    if [[ \"$first_word\" =~ ^($_SENTINEL_SAFE_CMDS)$ ]]; then return; fi

    printf \"\\r\\033[90m🛡 sentinel...\\033[0m\" >&2

    local response
    response=$(printf \"%s\\n\" \"$trimmed\" | nc -U -w$SENTINEL_TIMEOUT \"$SENTINEL_SOCKET\" 2>/dev/null)
    local nc_exit=$?
    printf \"\\r\\033[K\" >&2

    [[ $nc_exit -ne 0 || -z \"$response\" ]] && return

    if [[ \"$response\" == \"BLOCK\" ]]; then
        echo \"🚨 SENTINEL BLOCKED: ${trimmed:0:80}\" >&2
        echo \"   See ~/.sentinel/logs/ for details.\" >&2
        kill -INT $$
        return
    elif [[ \"$response\" == \"WARN:\"* ]]; then
        local reason=\"${response#WARN:}\"
        echo \"⚠️  SENTINEL WARNING: $reason\" >&2
        echo -n \"  Run anyway? [y/N] \" >&2
        local answer
        read -r answer </dev/tty
        if [[ \"$answer\" != \"y\" && \"$answer\" != \"Y\" ]]; then kill -INT $$; fi
    fi
}

trap _sentinel_preexec DEBUG
function sentinel-off() { SENTINEL_ENABLED=0; echo \"🛡 Sentinel paused\"; }
function sentinel-on()  { SENTINEL_ENABLED=1; echo \"🛡 Sentinel active\"; }
echo \"🛡  Sentinel active (bash)\"
";
    }

    // ----------------------------------------------------------------
    // Command analysis pipeline (passive history tailing)
    // ----------------------------------------------------------------

    public function analyzeCommand(cmd:String) {
        var result = handleSocketCommand(cmd);
        switch result.verdict {
            case Block:
                Logger.critical('[Terminal] HIGH RISK (passive): $cmd');
                showAlert("BLOCKED", cmd, result.reason);
            case Warn(reason):
                Logger.warn('[Terminal] WARNING (passive): $reason');
                showAlert("WARNING", cmd, reason);
            case Allow:
                Logger.debug('[Terminal] OK: $cmd');
        }
    }

    // ----------------------------------------------------------------
    // Heuristic pre-screen (no AI — fast)
    // ----------------------------------------------------------------

    static function heuristicCheck(cmd:String):{ safe:Bool, reason:String } {
        var lower = cmd.toLowerCase();

        if (~/(curl|wget).*(sh|bash|zsh|python|ruby|perl|node)\s*$/.match(cmd) ||
            ~/\|\s*(ba)?sh/.match(cmd) ||
            ~/bash\s+<\(curl/.match(cmd)) {
            return { safe: false, reason: "curl-pipe-bash execution pattern" };
        }

        if (~/(base64|b64).*(decode|d\s)/.match(lower) && ~/exec|eval|bash|sh/.match(lower)) {
            return { safe: false, reason: "base64 decode + execute pattern" };
        }

        if (~/brew\s+tap/.match(lower) && !isOfficialTap(cmd)) {
            return { safe: false, reason: "brew tap from non-official source" };
        }

        if (~/brew\s+install\s+\w+\/\w+\//.match(cmd)) {
            return { safe: false, reason: "brew install from third-party tap" };
        }

        if (~/sudo/.match(lower) && ~/(curl|wget)/.match(lower)) {
            return { safe: false, reason: "sudo + network download" };
        }

        if (~/csrutil\s+disable/.match(lower) ||
            ~/spctl\s+--master-disable/.match(lower) ||
            ~/defaults write.*gatekeeper/.match(lower)) {
            return { safe: false, reason: "disabling macOS security features" };
        }

        if (~/launchctl\s+(load|bootstrap)/.match(lower) && ~/plist/.match(lower)) {
            return { safe: false, reason: "loading LaunchAgent/LaunchDaemon" };
        }

        if (~/(python|ruby|perl|node)\s+-c\s+/.match(lower) &&
            ~/import|require|exec|eval/.match(lower)) {
            return { safe: false, reason: "inline script execution with interpreter" };
        }

        if (~/LD_PRELOAD|DYLD_INSERT_LIBRARIES/.match(cmd)) {
            return { safe: false, reason: "dynamic library injection via environment" };
        }

        if (~/chmod.*(+x|\d+[57])/.match(lower) && ~/curl|wget|tmp|download/.match(lower)) {
            return { safe: false, reason: "chmod +x on potentially downloaded file" };
        }

        return { safe: true, reason: "" };
    }

    static function isOfficialTap(cmd:String):Bool {
        var officialPrefixes = ["homebrew/", "caskroom/", "homebrew-cask"];
        for (prefix in officialPrefixes) {
            if (cmd.contains(prefix)) return true;
        }
        var trusted = Config.get().terminal.trustedTaps;
        for (tap in trusted) {
            if (cmd.contains(tap)) return true;
        }
        return false;
    }

    function runCodesignOnRepo(data:RepoData, cmd:String):Null<String> {
        var binaryExts = [".app", ".pkg", ".dmg", ".dylib", ".so", ".a"];
        var suspiciousBins:Array<String> = [];

        if (data.fileList != null) {
            for (f in data.fileList) {
                for (ext in binaryExts) {
                    if (f.endsWith(ext)) {
                        suspiciousBins.push(f);
                        break;
                    }
                }
            }
        }

        if (suspiciousBins.length > 0) {
            return 'Repo contains pre-built binaries: ${suspiciousBins.join(", ")}';
        }
        return null;
    }

    function showAlert(type:String, cmd:String, reason:String) {
        var title = type == "BLOCKED" ? "🚨 Sentinel BLOCKED" : "⚠️ Sentinel Warning";
        var msg = 'Command: ${cmd.substr(0, 80)}\n$reason';
        try {
            var p = new sys.io.Process("osascript", [
                "-e",
                'display notification "${escapeAppleScript(msg)}" with title "${escapeAppleScript(title)}" sound name "Basso"'
            ]);
            p.exitCode();
            p.close();
        } catch (e:Dynamic) {
            Logger.warn('[Terminal] Could not show notification: $e');
        }
    }

    static function escapeAppleScript(s:String):String {
        return s.split('"').join('\\"').split("\n").join(" ");
    }
}

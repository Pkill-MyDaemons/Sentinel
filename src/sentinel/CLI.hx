package sentinel;
using StringTools;
import sentinel.config.Config;
import sentinel.ai.AIEngine;
import sentinel.ai.GitHubFetcher;
import sentinel.platform.MacSecurity;
import sentinel.core.Logger;

/**
 * Sentinel CLI — for testing individual modules without running the full daemon.
 *
 * Usage:
 *   sentinel-cli analyze-cmd "brew tap evil/tap && bash install.sh"
 *   sentinel-cli analyze-repo https://github.com/owner/repo
 *   sentinel-cli codesign /Applications/SomeApp.app
 *   sentinel-cli check-extension /path/to/manifest.json
 *   sentinel-cli check-update /Applications/SomeApp.app/Contents/Info.plist
 */
class CLI {

    static function main() {
        Logger.init(sentinel.core.LogLevel.DEBUG);
        Config.load();

        var args = Sys.args();
        if (args.length == 0) {
            printUsage();
            Sys.exit(1);
        }

        var cmd = args[0];
        var rest = args.slice(1);

        switch cmd {
            case "analyze-cmd":
                cmdAnalyzeCommand(rest.join(" "));

            case "analyze-repo":
                cmdAnalyzeRepo(rest[0]);

            case "codesign":
                cmdCodesign(rest[0]);

            case "check-extension":
                cmdCheckExtension(rest[0]);

            case "check-update":
                cmdCheckUpdate(rest[0]);

            case "help", "--help", "-h":
                printUsage();

            default:
                Sys.println('Unknown command: $cmd');
                printUsage();
                Sys.exit(1);
        }
    }

    // ----------------------------------------------------------------
    // Subcommands
    // ----------------------------------------------------------------

    static function cmdAnalyzeCommand(cmd:String) {
        if (cmd.trim().length == 0) {
            Sys.println("Usage: sentinel-cli analyze-cmd <command>");
            return;
        }

        Sys.println('\n🔍 Analyzing command: $cmd\n');

        var ai = new AIEngine(Config.get());
        var fetcher = new GitHubFetcher(Config.get().terminal.githubToken);

        // Heuristic check (fast)
        Sys.println("── Heuristic check ──────────────────────");
        var repoUrl = GitHubFetcher.parseRepoFromCommand(cmd);

        if (repoUrl != null) {
            Sys.println('GitHub repo detected: $repoUrl');
            Sys.println("\n── Fetching repository ──────────────────");
            try {
                var repoData = fetcher.fetch(repoUrl);
                Sys.println('Stars: ${repoData.stars} | Forks: ${repoData.forks}');
                Sys.println('Created: ${repoData.createdAt} | Last push: ${repoData.pushedAt}');
                Sys.println('Files: ${repoData.fileList?.length ?? 0} listed');

                Sys.println("\n── AI repo analysis ─────────────────────");
                var result = ai.analyzeRepo(repoUrl, repoData);
                printAIResult(result);
            } catch (e:Dynamic) {
                Sys.println('Repo fetch failed: $e');
                Sys.println("\n── AI command analysis ──────────────────");
                var result = ai.analyzeCommand(cmd);
                printAIResult(result);
            }
        } else {
            Sys.println("No GitHub repo detected — analyzing command directly");
            Sys.println("\n── AI command analysis ──────────────────");
            var result = ai.analyzeCommand(cmd);
            printAIResult(result);
        }
    }

    static function cmdAnalyzeRepo(url:String) {
        if (url == null || url.trim().length == 0) {
            Sys.println("Usage: sentinel-cli analyze-repo <github-url>");
            return;
        }

        Sys.println('\n🔍 Analyzing repo: $url\n');
        var ai = new AIEngine(Config.get());
        var fetcher = new GitHubFetcher(Config.get().terminal.githubToken);

        try {
            var repoData = fetcher.fetch(url);
            Sys.println('Stars: ${repoData.stars} | Forks: ${repoData.forks}');
            Sys.println('Created: ${repoData.createdAt} | Owner joined: ${repoData.ownerAge}');

            var result = ai.analyzeRepo(url, repoData);
            printAIResult(result);
        } catch (e:Dynamic) {
            Sys.println('Error: $e');
        }
    }

    static function cmdCodesign(path:String) {
        if (path == null) {
            Sys.println("Usage: sentinel-cli codesign <path>");
            return;
        }

        Sys.println('\n🔏 Code signature analysis: $path\n');
        var result = MacSecurity.fullScan(path);

        Sys.println('Signed: ${result.codeSign.signed}');
        Sys.println('Team ID: ${result.codeSign.teamId ?? "none"}');
        Sys.println('Identifier: ${result.codeSign.identifier ?? "none"}');
        Sys.println('Authority chain: ${result.codeSign.authority.join(" → ")}');
        Sys.println('Gatekeeper: ${result.gatekeeper.accepted ? "ACCEPTED" : "REJECTED"} (${result.gatekeeper.source ?? "unknown"})');
        Sys.println('Quarantine: ${result.quarantine}');

        if (result.warnings.length > 0) {
            Sys.println('\nWarnings:');
            for (w in result.warnings) Sys.println('  ⚠ $w');
        } else {
            Sys.println('\n✅ No security warnings');
        }
    }

    static function cmdCheckExtension(manifestPath:String) {
        if (manifestPath == null) {
            Sys.println("Usage: sentinel-cli check-extension <manifest.json>");
            return;
        }

        var content = sys.io.File.getContent(manifestPath);
        var manifest:Dynamic = haxe.Json.parse(content);

        var name:String = manifest.name ?? "unknown";
        var permissions:Array<String> = [];
        if (manifest.permissions != null)
            for (p in (manifest.permissions:Array<Dynamic>)) permissions.push(Std.string(p));
        if (manifest.host_permissions != null)
            for (p in (manifest.host_permissions:Array<Dynamic>)) permissions.push(Std.string(p));

        Sys.println('\n🔌 Extension: $name');
        Sys.println('Permissions (${permissions.length}): ${permissions.join(", ")}');

        var ai = new AIEngine(Config.get());
        var result = ai.analyzeExtension(name, permissions, content.substr(0, 3000));
        printAIResult(result);
    }

    static function cmdCheckUpdate(plistPath:String) {
        if (plistPath == null) {
            Sys.println("Usage: sentinel-cli check-update <Info.plist>");
            return;
        }

        var mon = new sentinel.modules.UpdateMonitor(
            new sentinel.core.EventBus(),
            new AIEngine(Config.get())
        );
        mon.validateUpdate("App", plistPath, "unknown");
    }

    // ----------------------------------------------------------------
    // Output formatting
    // ----------------------------------------------------------------

    static function printAIResult(result:sentinel.ai.AIResult) {
        var riskLabel = Type.enumConstructor(result.riskLevel);
        var icon = switch result.riskLevel {
            case Safe:     "✅";
            case Low:      "🟡";
            case Medium:   "🟠";
            case High:     "🔴";
            case Critical: "💀";
        };

        Sys.println('');
        Sys.println('$icon Risk Level: $riskLabel (score: ${result.riskScore})');
        Sys.println('Summary: ${result.summary}');
        Sys.println('Recommendation: ${result.recommendation}');

        if (result.warnings.length > 0) {
            Sys.println('\nWarnings:');
            for (w in result.warnings) Sys.println('  ⚠ $w');
        }
    }

    static function printUsage() {
        Sys.println('
Sentinel Security CLI — AI-powered macOS security analysis

Usage: sentinel-cli <command> [args]

Commands:
  analyze-cmd  <command>       Analyze a terminal command for malicious behavior
  analyze-repo <github-url>    Fetch and analyze a GitHub repository
  codesign     <path>          Run macOS codesign + Gatekeeper check on a binary
  check-extension <manifest>   Analyze a Chrome extension manifest.json
  check-update  <Info.plist>   Validate an app update from its Info.plist

Examples:
  sentinel-cli analyze-cmd "brew tap suspicious/tap && bash install.sh"
  sentinel-cli analyze-repo https://github.com/someuser/somerepo
  sentinel-cli codesign /Applications/SomeApp.app
  sentinel-cli check-extension ~/Downloads/ext/manifest.json

Config: ~/.sentinel/config.json
Logs:   ~/.sentinel/logs/
');
    }
}

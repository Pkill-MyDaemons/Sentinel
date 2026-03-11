package sentinel.ai;

import sentinel.config.Config;
import sentinel.core.Logger;
import sentinel.core.EventBus;
import haxe.Json;
import haxe.Http;
import sentinel.core.RiskLevel;

using StringTools;

/**
 * AIEngine — unified interface for all AI analysis in Sentinel.
 *
 * Priority:
 *   1. Local Ollama (default, private, no cost)
 *   2. Anthropic API (if anthropicKey configured)
 *   3. OpenAI API (if openaiKey configured)
 *
 * All analysis methods return an AIResult with a risk score (0.0–1.0),
 * a human-readable explanation, and a list of specific warnings.
 */

class AIEngine {

    var cfg:sentinel.config.ConfigData;

    public function new(cfg:sentinel.config.ConfigData) {
        this.cfg = cfg;
        Logger.info('[AI] Provider: ${cfg.ai.provider} | Model: ${resolveModel()}');
    }

    // ----------------------------------------------------------------
    // Public analysis methods
    // ----------------------------------------------------------------

    /**
     * Analyze a terminal command for malicious intent.
     * Includes brew tap analysis, curl-pipe-bash patterns, obfuscation, etc.
     */
    public function analyzeCommand(cmd:String):AIResult {
        var prompt = buildCommandPrompt(cmd);
        return query(prompt);
    }

    /**
     * Analyze a GitHub repository's contents for malicious code.
     * Pass in the repo metadata + key file contents.
     */
    public function analyzeRepo(repoUrl:String, repoData:RepoData):AIResult {
        var prompt = buildRepoPrompt(repoUrl, repoData);
        return query(prompt);
    }

    /**
     * Validate an app update — checks publisher, download URL, version bump rationale.
     */
    public function analyzeUpdate(appName:String, currentVersion:String,
                                   newVersion:String, downloadUrl:String,
                                   plistInfo:String):AIResult {
        var prompt = buildUpdatePrompt(appName, currentVersion, newVersion, downloadUrl, plistInfo);
        return query(prompt);
    }

    /**
     * Analyze a Chrome extension's permissions for over-reach.
     */
    public function analyzeExtension(name:String, permissions:Array<String>,
                                      manifestJson:String):AIResult {
        var prompt = buildExtensionPrompt(name, permissions, manifestJson);
        return query(prompt);
    }

    // ----------------------------------------------------------------
    // Prompt builders
    // ----------------------------------------------------------------

    function buildCommandPrompt(cmd:String):String {
        return '
You are a macOS security expert analyzing terminal commands for malicious behavior.

COMMAND TO ANALYZE:
```
$cmd
```

Analyze this command for:
1. Curl-pipe-bash patterns (downloading and executing unknown scripts)
2. Suspicious brew tap sources (non-official Homebrew taps installing malware)
3. Base64 encoded payloads being decoded and executed
4. Privilege escalation (sudo with unusual commands)
5. Network exfiltration patterns
6. Obfuscated shell commands
7. Persistence mechanisms (LaunchAgents, cron, login items)
8. Known malicious command patterns

Respond ONLY with a JSON object (no markdown, no explanation outside JSON):
{
  "riskScore": 0.0,
  "summary": "one sentence description",
  "warnings": ["warning1", "warning2"],
  "recommendation": "ALLOW | WARN | BLOCK",
  "details": "detailed technical explanation"
}

Risk score guide: 0.0=safe, 0.3=low, 0.5=medium, 0.75=high, 0.9+=critical/block
';
    }

    function buildRepoPrompt(repoUrl:String, data:RepoData):String {
        var installScript = data.installScript != null ? data.installScript : "(not found)";
        var readme = data.readme != null ? data.readme.substr(0, 2000) : "(not found)";
        var packageJson = data.packageJson != null ? data.packageJson : "(not found)";
        var files = data.fileList != null ? data.fileList.join(", ") : "(unknown)";

        return '
You are a security researcher auditing a GitHub repository for malicious code.

REPOSITORY: $repoUrl
Stars: ${data.stars} | Forks: ${data.forks} | Created: ${data.createdAt} | Last push: ${data.pushedAt}
Owner account age: ${data.ownerAge}

FILE LIST (top-level):
$files

INSTALL SCRIPT (install.sh / Makefile / Formula):
```
$installScript
```

README (first 2000 chars):
$readme

PACKAGE MANIFEST:
$packageJson

Analyze for:
1. Obfuscated code in install scripts
2. Downloading additional payloads during install
3. Requesting unnecessary permissions or sudo
4. Typosquatting (name similar to popular packages)
5. Very new repo with high-risk install script
6. Hardcoded IPs or suspicious domains
7. Disabling security tools (XProtect, Gatekeeper, SIP)
8. Persistence mechanisms
9. Data exfiltration in scripts
10. Discrepancy between README claims and actual script behavior

Respond ONLY with JSON:
{
  "riskScore": 0.0,
  "summary": "one sentence",
  "warnings": ["warning1"],
  "recommendation": "ALLOW | WARN | BLOCK",
  "details": "technical breakdown"
}
';
    }

    function buildUpdatePrompt(app:String, current:String, next:String,
                                url:String, plist:String):String {
        return '
You are a macOS security expert validating an app update prompt.

APP: $app
CURRENT VERSION: $current
OFFERED VERSION: $next
DOWNLOAD URL: $url

INFO.PLIST EXCERPT:
$plist

Tasks:
1. Is the download URL hosted on the official publisher domain for "$app"?
2. Does the domain match what is in Info.plist (CFBundleURLTypes, SUFeedURL, etc.)?
3. Is the version jump suspicious (e.g. jumping from 1.x to 9.x overnight)?
4. Is the domain newly registered or suspicious?
5. Could this be a fake update popup (commonly used in drive-by malware)?
6. Does the URL use an unusual CDN or file host?

Respond ONLY with JSON:
{
  "riskScore": 0.0,
  "summary": "one sentence",
  "warnings": ["warning1"],
  "recommendation": "ALLOW | WARN | BLOCK",
  "domainTrusted": true,
  "details": "technical breakdown"
}
';
    }

    function buildExtensionPrompt(name:String, perms:Array<String>, manifest:String):String {
        var permList = perms.join(", ");
        return '
You are a browser security expert auditing a Chrome extension.

EXTENSION NAME: $name
DECLARED PERMISSIONS: $permList

MANIFEST.JSON:
$manifest

Analyze for:
1. Over-broad host permissions (<all_urls>, *://*/*)
2. webRequest/webRequestBlocking — can intercept all network traffic
3. nativeMessaging — can talk to native apps (high risk)
4. tabs + history — full browsing history access
5. clipboardRead/Write — clipboard snooping
6. debugger — can attach to pages (very dangerous)
7. Mismatch between extension purpose and permissions
8. permissions that enable ad injection, credential theft, or tracking

Respond ONLY with JSON:
{
  "riskScore": 0.0,
  "summary": "one sentence",
  "warnings": ["warning1"],
  "recommendation": "ALLOW | WARN | DISABLE",
  "shouldBlockNetwork": false,
  "details": "technical breakdown"
}
';
    }

    // ----------------------------------------------------------------
    // Query routing
    // ----------------------------------------------------------------

    function query(prompt:String):AIResult {
        try {
            var raw = switch cfg.ai.provider {
                case "anthropic": queryAnthropic(prompt);
                case "openai":    queryOpenAI(prompt);
                default:          queryOllama(prompt);
            };
            return parseResult(raw);
        } catch (e:Dynamic) {
            Logger.error('[AI] Query failed: $e');
            return fallbackResult('AI query failed: $e');
        }
    }

    // ----------------------------------------------------------------
    // Provider implementations
    // ----------------------------------------------------------------

    function queryOllama(prompt:String):String {
        var endpoint = cfg.ai.localEndpoint + "/api/generate";
        var payload = Json.stringify({
            model: cfg.ai.localModel,
            prompt: prompt,
            stream: false,
            format: "json",
            options: { temperature: 0.1 }  // low temp for consistent JSON
        });

        var http = new Http(endpoint);
        http.setHeader("Content-Type", "application/json");

        var response = "";
        var error = "";

        http.onData = (data) -> response = data;
        http.onError = (err) -> error = err;

        http.setPostData(payload);
        http.request(true);

        if (error != "") throw 'Ollama error: $error';

        var parsed = Json.parse(response);
        return parsed.response;
    }

    function queryAnthropic(prompt:String):String {
        #if no_ssl
        throw "Anthropic API requires SSL. Build without -D no_ssl, or switch provider to 'ollama' in config.";
        return "";
        #else
        var http = new Http("https://api.anthropic.com/v1/messages");
        http.setHeader("Content-Type", "application/json");
        http.setHeader("x-api-key", cfg.ai.anthropicKey);
        http.setHeader("anthropic-version", "2023-06-01");

        var model = cfg.ai.anthropicModel != null ? cfg.ai.anthropicModel : "claude-sonnet-4-20250514";
        var payload = Json.stringify({
            model: model,
            max_tokens: 1024,
            messages: [{ role: "user", content: prompt }]
        });

        var response = "";
        var error = "";
        http.onData = (data) -> response = data;
        http.onError = (err) -> error = err;
        http.setPostData(payload);
        http.request(true);

        if (error != "") throw 'Anthropic error: $error';

        var parsed = Json.parse(response);
        return parsed.content[0].text;
        #end
    }

    function queryOpenAI(prompt:String):String {
        #if no_ssl
        throw "OpenAI API requires SSL. Build without -D no_ssl, or switch provider to 'ollama' in config.";
        return "";
        #else
        var http = new Http("https://api.openai.com/v1/chat/completions");
        http.setHeader("Content-Type", "application/json");
        http.setHeader("Authorization", "Bearer " + cfg.ai.openaiKey);

        var model = cfg.ai.openaiModel != null ? cfg.ai.openaiModel : "gpt-4o";
        var payload = Json.stringify({
            model: model,
            temperature: 0.1,
            messages: [
                { role: "system", content: "You are a macOS security expert. Always respond with valid JSON only." },
                { role: "user", content: prompt }
            ]
        });

        var response = "";
        var error = "";
        http.onData = (data) -> response = data;
        http.onError = (err) -> error = err;
        http.setPostData(payload);
        http.request(true);

        if (error != "") throw 'OpenAI error: $error';

        var parsed = Json.parse(response);
        return parsed.choices[0].message.content;
        #end
    }

    // ----------------------------------------------------------------
    // Result parsing
    // ----------------------------------------------------------------

    function parseResult(raw:String):AIResult {
        // Strip markdown fences if any
        var clean = ~/```json\n?|```/g.replace(raw, "").trim();
        try {
            var j = Json.parse(clean);
            var score:Float = j.riskScore != null ? j.riskScore : 0.5;
            return {
                riskScore: score,
                riskLevel: scoreToLevel(score),
                summary: j.summary ?? "No summary",
                warnings: j.warnings ?? [],
                recommendation: j.recommendation ?? "WARN",
                rawResponse: raw,
            };
        } catch (e:Dynamic) {
            Logger.warn('[AI] Failed to parse JSON response: $e\nRaw: $raw');
            return fallbackResult(raw);
        }
    }

    function scoreToLevel(score:Float):sentinel.core.RiskLevel {
        if (score < 0.2) return Safe;
        if (score < 0.4) return Low;
        if (score < 0.6) return Medium;
        if (score < 0.8) return High;
        return Critical;
    }

    function fallbackResult(msg:String):AIResult {
        return {
            riskScore: 0.5,
            riskLevel: Medium,
            summary: "AI analysis unavailable — manual review required",
            warnings: [msg],
            recommendation: "WARN",
            rawResponse: msg,
        };
    }

    function resolveModel():String {
        return switch cfg.ai.provider {
            case "anthropic": cfg.ai.anthropicModel ?? "claude-sonnet-4-20250514";
            case "openai":    cfg.ai.openaiModel ?? "gpt-4o";
            default:          cfg.ai.localModel ?? "llama3";
        };
    }
}

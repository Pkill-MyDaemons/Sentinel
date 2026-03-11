package sentinel.config;

using StringTools;

import haxe.Json;
import sys.io.File;
import sys.FileSystem;
import sentinel.core.Logger;

/**
 * Sentinel configuration — loaded from ~/.sentinel/config.json
 *
 * Supports:
 *   - Local AI model via Ollama (default, no API key needed)
 *   - Anthropic Claude API
 *   - OpenAI API
 *   - Risk thresholds, trusted domains, extension allowlists
 */
typedef ConfigData = {
    var version:String;
    var ai:AIConfig;
    var terminal:TerminalConfig;
    var updates:UpdateConfig;
    var extensions:ExtensionConfig;
    var network:NetworkConfig;
}

typedef AIConfig = {
    /** "local" | "anthropic" | "openai" */
    var provider:String;
    /** Ollama model name, e.g. "llama3", "mistral", "codellama" */
    var localModel:String;
    /** Ollama base URL */
    var localEndpoint:String;
    @:optional var anthropicKey:String;
    @:optional var anthropicModel:String;
    @:optional var openaiKey:String;
    @:optional var openaiModel:String;
    /** 0.0–1.0 confidence threshold to auto-block */
    var blockThreshold:Float;
    /** 0.0–1.0 confidence threshold to warn (but allow) */
    var warnThreshold:Float;
}

typedef TerminalConfig = {
    /** Shell history files to watch */
    var watchPaths:Array<String>;
    /** Auto-block high-risk commands without prompting */
    var autoBlock:Bool;
    /** GitHub token for higher rate limits when fetching repos */
    @:optional var githubToken:String;
    /** Trusted Homebrew tap owners (never flagged) */
    var trustedTaps:Array<String>;
}

typedef UpdateConfig = {
    /** Trusted publisher domains — skip deep analysis */
    var trustedDomains:Array<String>;
    /** Auto-block updates from unknown domains */
    var blockUnknownDomains:Bool;
}

typedef ExtensionConfig = {
    /** Max number of permissions before flagging */
    var maxPermissions:Int;
    /** Permissions considered always-dangerous */
    var dangerousPermissions:Array<String>;
    /** Automatically disable extensions that exceed limits */
    var autoDisable:Bool;
}

typedef NetworkConfig = {
    /** Apps to ignore in connection tracking */
    var ignoredApps:Array<String>;
    var logConnections:Bool;
}

class Config {

    public static final VERSION = "0.1.0";

    static var configPath:String;
    static var data:ConfigData;

    public static function load() {
        configPath = getConfigPath();
        if (FileSystem.exists(configPath)) {
            var raw = File.getContent(configPath);
            data = Json.parse(raw);
            Logger.info('Config loaded from $configPath');
        } else {
            data = defaults();
            save(); // write defaults so user can edit
            Logger.info('No config found — wrote defaults to $configPath');
        }
    }

    public static function get():ConfigData {
        if (data == null) load();
        return data;
    }

    public static function save() {
        var dir = haxe.io.Path.directory(configPath);
        if (!FileSystem.exists(dir)) FileSystem.createDirectory(dir);
        File.saveContent(configPath, Json.stringify(data, null, "  "));
    }

    static function getConfigPath():String {
        var home = Sys.getEnv("HOME");
        if (home == null) home = "/tmp";
        return '$home/.sentinel/config.json';
    }

    static function defaults():ConfigData {
        return {
            version: VERSION,
            ai: {
                provider: "local",
                localModel: "llama3",
                localEndpoint: "http://localhost:11434",
                anthropicKey: "",
                anthropicModel: "claude-sonnet-4-20250514",
                openaiKey: "",
                openaiModel: "gpt-4o",
                blockThreshold: 0.85,
                warnThreshold: 0.50,
            },
            terminal: {
                watchPaths: [
                    "~/.bash_history",
                    "~/.zsh_history",
                    "~/.zhistory",
                ],
                autoBlock: false,
                githubToken: "",
                trustedTaps: ["homebrew/homebrew-core", "homebrew/homebrew-cask"],
            },
            updates: {
                trustedDomains: [
                    "apple.com", "microsoft.com", "google.com",
                    "mozilla.org", "github.com", "adobe.com",
                ],
                blockUnknownDomains: false,
            },
            extensions: {
                maxPermissions: 5,
                dangerousPermissions: [
                    "<all_urls>",
                    "tabs",
                    "webRequest",
                    "webRequestBlocking",
                    "nativeMessaging",
                    "debugger",
                    "cookies",
                    "history",
                    "clipboardRead",
                    "clipboardWrite",
                ],
                autoDisable: false,
            },
            network: {
                ignoredApps: ["kernel_task", "launchd"],
                logConnections: true,
            },
        };
    }
}

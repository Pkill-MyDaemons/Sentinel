package sentinel.modules;

using StringTools;

import sentinel.core.IModule;
import sentinel.core.EventBus;
import sentinel.core.Logger;
import sentinel.ai.AIEngine;
import sentinel.config.Config;
import sys.io.File;
import sys.FileSystem;
import haxe.Json;

typedef PlistInfo = {
    @:optional var bundleId:String;
    @:optional var version:String;
    @:optional var shortVersion:String;
    @:optional var feedUrl:String;
    @:optional var updateUrl:String;
    @:optional var minOS:String;
    @:optional var raw:String;
}

typedef VersionInfo = {
    @:optional var version:String;
    @:optional var releaseDate:String;
    @:optional var notes:String;
}

/**
 * UpdateMonitor — Module 2
 *
 * Monitors for app update prompts by:
 *   1. Watching /Applications and ~/Applications for Info.plist changes
 *   2. Reading Info.plist (CFBundleVersion, SUFeedURL, LSMinimumSystemVersion)
 *   3. Checking macOS software update daemon logs for pending updates
 *   4. When an update URL is seen in network traffic, validates via AI
 *
 * For each detected update:
 *   - Extracts current version from Info.plist
 *   - Looks up latest known version (GitHub releases / official site)
 *   - Checks download URL domain against trusted list
 *   - Runs AI analysis on the update legitimacy
 */
class UpdateMonitor implements IModule {

    var bus:EventBus;
    var ai:AIEngine;
    var cfg:sentinel.config.UpdateConfig;
    var running:Bool = false;
    var knownVersions:Map<String, String> = new Map(); // bundleId -> version
    var checkedApps:Map<String, Float> = new Map(); // bundleId -> last check timestamp

    static final APP_DIRS = ["/Applications", "~/Applications"];
    static final RECHECK_INTERVAL = 3600.0; // 1 hour between re-checks

    public function new(bus:EventBus, ai:AIEngine) {
        this.bus = bus;
        this.ai = ai;
        this.cfg = Config.get().updates;
        bus.subscribe(onEvent);
    }

    public function name():String return "UpdateMonitor";

    public function start() {
        running = true;
        // Initial scan
        sys.thread.Thread.create(() -> {
            scanApplications();
            while (running) {
                Sys.sleep(60.0); // check every minute for new/updated apps
                scanApplications();
            }
        });
    }

    public function stop() {
        running = false;
    }

    function onEvent(event:sentinel.core.SecurityEvent) {
        switch event {
            case UpdateDetected(appName, plistPath, downloadUrl):
                validateUpdate(appName, plistPath, downloadUrl);
            default:
        }
    }

    // ----------------------------------------------------------------
    // App scanning
    // ----------------------------------------------------------------

    function scanApplications() {
        var home = Sys.getEnv("HOME") ?? "/tmp";
        var dirs = ["/Applications", '$home/Applications'];

        for (dir in dirs) {
            if (!FileSystem.exists(dir)) continue;
            try {
                for (entry in FileSystem.readDirectory(dir)) {
                    if (!entry.endsWith(".app")) continue;
                    var appPath = '$dir/$entry';
                    var plistPath = '$appPath/Contents/Info.plist';
                    if (!FileSystem.exists(plistPath)) continue;

                    var info = parsePlist(plistPath);
                    if (info == null) continue;

                    var bundleId = info.bundleId ?? entry;
                    var version  = info.version ?? "unknown";

                    // Check if version changed (update pending?)
                    var lastVersion = knownVersions.get(bundleId);
                    if (lastVersion != null && lastVersion != version) {
                        Logger.info('[Update] Version change detected: $entry $lastVersion → $version');
                        // Check if enough time has passed since last analysis
                        var lastCheck = checkedApps.get(bundleId) ?? 0.0;
                        if (Date.now().getTime() / 1000 - lastCheck > RECHECK_INTERVAL) {
                            analyzeUpdateFromPlist(entry, plistPath, info, lastVersion, version);
                            checkedApps.set(bundleId, Date.now().getTime() / 1000);
                        }
                    }
                    knownVersions.set(bundleId, version);
                }
            } catch (e:Dynamic) {
                Logger.warn('[Update] Scan error in $dir: $e');
            }
        }
    }

    // ----------------------------------------------------------------
    // Plist parsing (binary plist via plutil, text plist via regex)
    // ----------------------------------------------------------------

    static function parsePlist(path:String):Null<PlistInfo> {
        // Convert to XML via plutil (always available on macOS)
        try {
            var p = new sys.io.Process("plutil", ["-convert", "xml1", "-o", "-", path]);
            var xml = p.stdout.readAll().toString();
            p.exitCode();
            p.close();

            if (xml.length < 10) return null;

            var info:PlistInfo = { raw: xml.substr(0, 5000) };

            // Simple key-value extraction from plist XML
            info.bundleId    = extractPlistValue(xml, "CFBundleIdentifier");
            info.version     = extractPlistValue(xml, "CFBundleVersion");
            info.shortVersion = extractPlistValue(xml, "CFBundleShortVersionString");
            info.feedUrl     = extractPlistValue(xml, "SUFeedURL")
                            ?? extractPlistValue(xml, "SUScheduledCheckIntervalKey");
            info.updateUrl   = extractPlistValue(xml, "CFBundleURLTypes")
                            ?? info.feedUrl;
            info.minOS       = extractPlistValue(xml, "LSMinimumSystemVersion");

            return info;
        } catch (e:Dynamic) {
            // Try reading as plain text plist
            try {
                var raw = File.getContent(path);
                return {
                    bundleId: extractPlistValue(raw, "CFBundleIdentifier"),
                    version:  extractPlistValue(raw, "CFBundleVersion"),
                    raw: raw.substr(0, 5000),
                };
            } catch (e2:Dynamic) {
                return null;
            }
        }
    }

    static function extractPlistValue(xml:String, key:String):Null<String> {
        // Match <key>CFBundleIdentifier</key>\n\t<string>VALUE</string>
        var re = new EReg('<key>' + key + '</key>\\s*<(string|integer|real)>([^<]+)</', "i");
        if (re.match(xml)) return re.matched(2).trim();
        return null;
    }

    // ----------------------------------------------------------------
    // Update analysis
    // ----------------------------------------------------------------

    function analyzeUpdateFromPlist(appName:String, plistPath:String,
                                     info:PlistInfo, oldVer:String, newVer:String) {
        var downloadUrl = info.feedUrl ?? info.updateUrl ?? "unknown";
        bus.emitNow(UpdateDetected(appName, plistPath, downloadUrl));
    }

    public function validateUpdate(appName:String, plistPath:String, downloadUrl:String) {
        Logger.info('[Update] Validating update for $appName — $downloadUrl');

        var info = parsePlist(plistPath);
        var currentVersion = info?.version ?? "unknown";
        var shortVersion   = info?.shortVersion ?? "unknown";
        var plistSnippet   = info?.raw ?? "(could not read)";

        // Quick domain check against trusted list
        var domain = extractDomain(downloadUrl);
        var trusted = isTrustedDomain(domain);

        if (trusted) {
            Logger.info('[Update] $appName — trusted domain ($domain) — skipping deep analysis');
            bus.emitNow(UpdateValidated(appName, true, 'Trusted domain: $domain'));
            return;
        }

        // Look up latest version from GitHub releases or Sparkle feed
        var latestInfo = lookupLatestVersion(appName, downloadUrl);
        var newVersion = latestInfo?.version ?? "unknown";

        // AI analysis
        var result = ai.analyzeUpdate(
            appName, currentVersion, newVersion,
            downloadUrl, plistSnippet.substr(0, 2000)
        );

        Logger.warn('[Update] AI risk=${Type.enumConstructor(result.riskLevel)} for $appName');
        for (w in result.warnings) Logger.warn('[Update]   ⚠ $w');

        bus.emitNow(UpdateValidated(appName, result.riskLevel == Safe || result.riskLevel == Low,
            result.summary));

        bus.emitNow(Alert(result.riskLevel, "UpdateMonitor",
            '$appName update from $domain — ${result.recommendation}: ${result.summary}'));

        if (result.riskLevel == High || result.riskLevel == Critical) {
            showUpdateAlert(appName, downloadUrl, result.summary, result.warnings);
        }
    }

    // ----------------------------------------------------------------
    // Version lookup (Sparkle feed + GitHub releases)
    // ----------------------------------------------------------------

    static function lookupLatestVersion(appName:String, updateUrl:String):Null<VersionInfo> {
        // Try Sparkle appcast XML
        if (updateUrl.contains("appcast") || updateUrl.endsWith(".xml") || updateUrl.endsWith(".rss")) {
            return fetchSparkleVersion(updateUrl);
        }

        // Try GitHub releases API
        var ghRe = ~/github\.com\/([\w.-]+)\/([\w.-]+)/;
        if (ghRe.match(updateUrl)) {
            return fetchGithubLatestRelease(ghRe.matched(1), ghRe.matched(2));
        }

        return null;
    }

    static function fetchSparkleVersion(feedUrl:String):Null<VersionInfo> {
        try {
            var http = new haxe.Http(feedUrl);
            var xml = "";
            http.onData = (d) -> xml = d;
            http.onError = (e) -> {};
            http.request(false);

            if (xml.length == 0) return null;

            // Parse Sparkle appcast
            var verRe = ~/sparkle:version="([^"]+)"/;
            var version = verRe.match(xml) ? verRe.matched(1) : null;

            var dateRe = ~/<pubDate>([^<]+)<\/pubDate>/;
            var date = dateRe.match(xml) ? dateRe.matched(1) : null;

            return { version: version, releaseDate: date };
        } catch (e:Dynamic) {
            return null;
        }
    }

    static function fetchGithubLatestRelease(owner:String, repo:String):Null<VersionInfo> {
        try {
            var http = new haxe.Http('https://api.github.com/repos/$owner/$repo/releases/latest');
            http.setHeader("User-Agent", "Sentinel-Security/0.1");
            http.setHeader("Accept", "application/vnd.github+json");
            var response = "";
            http.onData = (d) -> response = d;
            http.onError = (e) -> {};
            http.request(false);

            if (response.length == 0) return null;
            var j = Json.parse(response);
            return {
                version: j.tag_name,
                releaseDate: j.published_at,
                notes: j.body != null ? Std.string(j.body).substr(0, 500) : null,
            };
        } catch (e:Dynamic) {
            return null;
        }
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    static function extractDomain(url:String):String {
        var re = ~/https?:\/\/([^\/]+)/;
        if (re.match(url)) return re.matched(1).toLowerCase();
        return url.toLowerCase();
    }

    function isTrustedDomain(domain:String):Bool {
        for (trusted in cfg.trustedDomains) {
            if (domain.endsWith(trusted) || domain == trusted) return true;
        }
        return false;
    }

    function showUpdateAlert(app:String, url:String, summary:String, warnings:Array<String>) {
        var msg = 'App: $app\nURL: $url\n$summary';
        if (warnings.length > 0) msg += '\nWarnings: ${warnings.join("; ")}';
        try {
            var p = new sys.io.Process("osascript", [
                "-e",
                'display alert "⚠️ Suspicious Update Detected" message "${escapeAS(msg)}" buttons {"Block", "Allow"} default button "Block" as warning'
            ]);
            p.exitCode();
            p.close();
        } catch (e:Dynamic) {}
    }

    static function escapeAS(s:String):String {
        return s.split('"').join('\\"').split("\n").join(" ");
    }
}

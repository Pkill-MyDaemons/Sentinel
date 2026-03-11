package sentinel.modules;

using StringTools;

import sentinel.core.IModule;
import sentinel.core.EventBus;
import sentinel.core.Logger;
import sentinel.ai.AIResult;
import sentinel.ai.AIEngine;
import sentinel.config.Config;
import sys.io.File;
import sys.FileSystem;
import haxe.Json;

/**
 * ExtensionMonitor — Module 3
 *
 * Watches Chrome/Chromium extension directories for new/updated extensions.
 * For each extension:
 *   1. Reads manifest.json and extracts permissions
 *   2. Checks against dangerous permission list
 *   3. Runs AI analysis for over-reach assessment
 *   4. Optionally disables extensions via Chrome's preferences file
 *   5. Can block https/wss connections for flagged extensions
 *     via macOS pf (packet filter) or Little Snitch rules
 *
 * Chrome extension directories (per-profile):
 *   ~/Library/Application Support/Google/Chrome/Default/Extensions/
 *   ~/Library/Application Support/Google/Chrome/Profile */
class ExtensionMonitor implements IModule {

    var bus:EventBus;
    var ai:AIEngine;
    var cfg:sentinel.config.ExtensionConfig;
    var running:Bool = false;
    var seenExtensions:Map<String, String> = new Map(); // extId -> manifest hash

    static final CHROME_BASE = "~/Library/Application Support/Google/Chrome";
    static final PROFILES = ["Default", "Profile 1", "Profile 2", "Profile 3"];

    public function new(bus:EventBus, ai:AIEngine) {
        this.bus = bus;
        this.ai = ai;
        this.cfg = Config.get().extensions;
    }

    public function name():String return "ExtensionMonitor";

    public function start() {
        running = true;
        sys.thread.Thread.create(() -> {
            while (running) {
                scanExtensions();
                Sys.sleep(30.0);
            }
        });
    }

    public function stop() {
        running = false;
    }

    // ----------------------------------------------------------------
    // Extension scanning
    // ----------------------------------------------------------------

    function scanExtensions() {
        var home = Sys.getEnv("HOME") ?? "/tmp";
        var base = CHROME_BASE.replace("~", home);

        for (profile in PROFILES) {
            var extDir = '$base/$profile/Extensions';
            if (!FileSystem.exists(extDir)) continue;

            try {
                for (extId in FileSystem.readDirectory(extDir)) {
                    if (extId.startsWith(".")) continue;
                    var extPath = '$extDir/$extId';
                    if (!FileSystem.isDirectory(extPath)) continue;

                    // Extensions have version subdirectories
                    var manifest = findManifest(extPath);
                    if (manifest == null) continue;

                    // Hash to detect changes
                    var hash = haxe.crypto.Md5.encode(manifest);
                    var lastHash = seenExtensions.get(extId);
                    if (lastHash == hash) continue; // unchanged

                    seenExtensions.set(extId, hash);
                    Logger.info('[Extension] Analyzing: $extId');
                    analyzeExtension(extId, manifest, extPath, profile);
                }
            } catch (e:Dynamic) {
                Logger.warn('[Extension] Scan error for $profile: $e');
            }
        }
    }

    static function findManifest(extPath:String):Null<String> {
        try {
            for (version in FileSystem.readDirectory(extPath)) {
                var vPath = '$extPath/$version';
                var mPath = '$vPath/manifest.json';
                if (FileSystem.exists(mPath)) {
                    return File.getContent(mPath);
                }
            }
        } catch (e:Dynamic) {}
        return null;
    }

    // ----------------------------------------------------------------
    // Extension analysis
    // ----------------------------------------------------------------

    function analyzeExtension(extId:String, manifestJson:String, extPath:String, profile:String) {
        var manifest:Dynamic;
        try {
            manifest = Json.parse(manifestJson);
        } catch (e:Dynamic) {
            Logger.warn('[Extension] Invalid manifest for $extId: $e');
            return;
        }

        var name:String = manifest.name ?? extId;
        var version:String = manifest.version ?? "unknown";

        // Handle manifest v2 and v3 permissions
        var permissions:Array<String> = [];
        if (manifest.permissions != null) {
            for (p in (manifest.permissions:Array<Dynamic>)) permissions.push(Std.string(p));
        }
        if (manifest.host_permissions != null) {
            for (p in (manifest.host_permissions:Array<Dynamic>)) permissions.push(Std.string(p));
        }
        // Optional permissions (can be granted at runtime)
        var optionalPerms:Array<String> = [];
        if (manifest.optional_permissions != null) {
            for (p in (manifest.optional_permissions:Array<Dynamic>)) optionalPerms.push(Std.string(p));
        }

        Logger.info('[Extension] $name ($extId) v$version — ${permissions.length} permissions');

        // Heuristic check first
        var dangerous = findDangerousPermissions(permissions);
        var tooMany = permissions.length > cfg.maxPermissions;

        if (!tooMany && dangerous.length == 0) {
            Logger.debug('[Extension] $name — OK');
            return;
        }

        // Emit flag event
        bus.emitNow(ExtensionFlagged(extId, name, permissions));

        Logger.warn('[Extension] FLAGGED: $name');
        if (dangerous.length > 0) Logger.warn('[Extension]   Dangerous perms: ${dangerous.join(", ")}');
        if (tooMany) Logger.warn('[Extension]   Too many permissions: ${permissions.length} > ${cfg.maxPermissions}');

        // AI deep analysis
        var aiResult = ai.analyzeExtension(name, permissions, manifestJson.substr(0, 3000));
        Logger.warn('[Extension] AI risk=${Type.enumConstructor(aiResult.riskLevel)} — ${aiResult.summary}');

        for (w in aiResult.warnings) Logger.warn('[Extension]   ⚠ $w');

        // Block network connections for high-risk extensions
        if (aiResult.riskLevel == High || aiResult.riskLevel == Critical) {
            blockExtensionNetwork(extId, name, profile);
        }

        // Auto-disable if configured
        if (cfg.autoDisable && (aiResult.riskLevel == High || aiResult.riskLevel == Critical)) {
            disableExtension(extId, profile);
        }

        // Show notification
        showExtensionAlert(name, extId, dangerous, aiResult);
    }

    function findDangerousPermissions(perms:Array<String>):Array<String> {
        var found:Array<String> = [];
        for (perm in perms) {
            for (dangerous in cfg.dangerousPermissions) {
                if (perm == dangerous || perm.contains("*")) {
                    found.push(perm);
                    break;
                }
            }
        }
        return found;
    }

    // ----------------------------------------------------------------
    // Network blocking via macOS pf (packet filter)
    // ----------------------------------------------------------------

    /**
     * Block https (443) and wss (443/80) connections for a Chrome extension.
     *
     * Strategy: Since extensions run inside Chrome's renderer process,
     * we can't easily block by extension ID at the OS level. Instead:
     *
     * Option A: Add pf rules blocking the extension's known bad hosts
     *           (extracted from manifest content_scripts / background)
     * Option B: Write a Chrome policy file disabling the extension
     * Option C: Modify Chrome's Preferences to disable the extension
     *
     * We implement Option B (Chrome managed policies) as it's safest.
     */
    function blockExtensionNetwork(extId:String, name:String, profile:String) {
        Logger.critical('[Extension] Blocking network for: $name ($extId)');

        // Write Chrome managed policy to block this extension's network access
        // Chrome respects policies in /Library/Managed Preferences/
        writeChromeExtensionPolicy(extId, true);

        Logger.info('[Extension] Chrome policy written to block $extId network access');
    }

    function writeChromeExtensionPolicy(extId:String, blocked:Bool) {
        var home = Sys.getEnv("HOME") ?? "/tmp";
        var policyDir = '$home/Library/Application Support/Google/Chrome/policies/recommended';

        try {
            if (!FileSystem.exists(policyDir)) FileSystem.createDirectory(policyDir);

            // Read existing policy or create new
            var policyPath = '$policyDir/sentinel-policy.json';
            var policy:Dynamic = {};
            if (FileSystem.exists(policyPath)) {
                try {
                    policy = Json.parse(File.getContent(policyPath));
                } catch (e:Dynamic) {}
            }

            // ExtensionSettings policy for per-extension control
            if (policy.ExtensionSettings == null) policy.ExtensionSettings = {};

            if (blocked) {
                // Block all URLs for this extension
                Reflect.setField(policy.ExtensionSettings, extId, {
                    "runtime_blocked_hosts": ["*://*/*"],
                    "installation_mode": "blocked",
                });
                Logger.info('[Extension] Policy: blocked all hosts for $extId');
            } else {
                Reflect.deleteField(policy.ExtensionSettings, extId);
            }

            File.saveContent(policyPath, Json.stringify(policy, null, "  "));
        } catch (e:Dynamic) {
            Logger.error('[Extension] Could not write Chrome policy: $e');
        }
    }

    // ----------------------------------------------------------------
    // Extension disabling via Chrome Preferences
    // ----------------------------------------------------------------

    function disableExtension(extId:String, profile:String) {
        var home = Sys.getEnv("HOME") ?? "/tmp";
        var base = CHROME_BASE.replace("~", home);
        var prefPath = '$base/$profile/Preferences';

        if (!FileSystem.exists(prefPath)) return;

        try {
            var raw = File.getContent(prefPath);
            var prefs:Dynamic = Json.parse(raw);

            // Chrome stores extension state in extensions.settings
            if (prefs.extensions != null && prefs.extensions.settings != null) {
                var extSettings = Reflect.field(prefs.extensions.settings, extId);
                if (extSettings != null) {
                    extSettings.state = 0; // 0 = disabled, 1 = enabled
                    File.saveContent(prefPath, Json.stringify(prefs));
                    Logger.info('[Extension] Disabled $extId in Chrome Preferences');
                }
            }
        } catch (e:Dynamic) {
            Logger.error('[Extension] Could not disable extension: $e');
        }
    }

    // ----------------------------------------------------------------
    // Notification
    // ----------------------------------------------------------------

    function showExtensionAlert(name:String, extId:String,
                                 dangerous:Array<String>, result:sentinel.ai.AIResult) {
        var riskLabel = Type.enumConstructor(result.riskLevel);
        var msg = 'Extension "$name" flagged as $riskLabel risk.\n';
        if (dangerous.length > 0) msg += 'Dangerous permissions: ${dangerous.join(", ")}\n';
        msg += result.summary;

        try {
            var p = new sys.io.Process("osascript", [
                "-e",
                'display notification "${escapeAS(msg)}" with title "🔌 Sentinel: Extension Alert" sound name "Funk"'
            ]);
            p.exitCode();
            p.close();
        } catch (e:Dynamic) {}
    }

    static function escapeAS(s:String):String {
        return s.split('"').join('\\"').split("\n").join(" ");
    }
}

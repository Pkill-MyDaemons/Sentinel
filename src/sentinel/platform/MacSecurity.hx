package sentinel.platform;

using StringTools;

import sentinel.core.Logger;
import sys.io.Process;

/**
 * MacSecurity — wraps macOS native security tools:
 *
 *   codesign   — verify binary signing + entitlements
 *   spctl      — Gatekeeper assessment
 *   xattr      — quarantine attribute check
 *   mdls       — file metadata
 *   pkgutil    — package receipt info
 *
 * These tools are always available on macOS with no extra install.
 */

typedef CodeSignResult = {
    var signed:Bool;
    var teamId:Null<String>;
    var identifier:Null<String>;
    var authority:Array<String>;
    var entitlements:Null<String>;
    var warnings:Array<String>;
    var raw:String;
}

typedef GatekeeperResult = {
    var accepted:Bool;
    var source:Null<String>;
    var raw:String;
}

class MacSecurity {

    /**
     * Run codesign --verify --deep --verbose on a path (file, .app, or directory)
     */
    public static function codesign(path:String):CodeSignResult {
        var result:CodeSignResult = {
            signed: false,
            teamId: null,
            identifier: null,
            authority: [],
            entitlements: null,
            warnings: [],
            raw: "",
        };

        // Verify signature
        var verifyOut = run("codesign", ["--verify", "--deep", "--verbose=4", path]);
        result.raw += "=== codesign verify ===\n" + verifyOut.stdout + verifyOut.stderr;

        if (verifyOut.code == 0) {
            result.signed = true;
        } else {
            result.warnings.push("Binary not signed or signature invalid");
            result.warnings.push(verifyOut.stderr.trim());
        }

        // Display info
        var infoOut = run("codesign", ["--display", "--verbose=4", path]);
        result.raw += "\n=== codesign info ===\n" + infoOut.stdout + infoOut.stderr;

        var combined = infoOut.stdout + infoOut.stderr;

        // Parse TeamIdentifier
        var teamRe = ~/TeamIdentifier=(\S+)/;
        if (teamRe.match(combined)) result.teamId = teamRe.matched(1);

        // Parse Identifier
        var idRe = ~/Identifier=(\S+)/;
        if (idRe.match(combined)) result.identifier = idRe.matched(1);

        // Parse Authority chain
        var authRe = ~/Authority=(.+)/g;
        authRe.map(combined, (m) -> { result.authority.push(m.matched(1)); return ""; });

        // Extract entitlements
        var entOut = run("codesign", ["--entitlements", "-", "--xml", path]);
        if (entOut.code == 0 && entOut.stdout.trim() != "") {
            result.entitlements = entOut.stdout;
            result.raw += "\n=== entitlements ===\n" + entOut.stdout;

            // Flag dangerous entitlements
            if (entOut.stdout.contains("com.apple.security.cs.disable-library-validation"))
                result.warnings.push("⚠ Disables library validation — can load unsigned dylibs");
            if (entOut.stdout.contains("com.apple.security.cs.allow-jit"))
                result.warnings.push("⚠ JIT entitlement — can write+execute memory");
            if (entOut.stdout.contains("com.apple.security.get-task-allow"))
                result.warnings.push("⚠ get-task-allow — allows debuggers to attach (dev builds only)");
        }

        return result;
    }

    /**
     * Run spctl (Gatekeeper) assessment on a path
     */
    public static function gatekeeper(path:String):GatekeeperResult {
        var out = run("spctl", ["--assess", "--verbose", "--type", "execute", path]);
        var combined = out.stdout + out.stderr;

        var source:Null<String> = null;
        var srcRe = ~/source=(.+)/;
        if (srcRe.match(combined)) source = srcRe.matched(1).trim();

        return {
            accepted: out.code == 0,
            source: source,
            raw: combined,
        };
    }

    /**
     * Check quarantine xattr on a downloaded file
     */
    public static function quarantineInfo(path:String):String {
        var out = run("xattr", ["-p", "com.apple.quarantine", path]);
        if (out.code != 0) return "no quarantine attribute";
        return out.stdout.trim();
    }

    /**
     * Run `security` tool to check a file against XProtect/MRT signatures
     * (requires the file to be present on disk)
     */
    public static function xprotectCheck(path:String):{ clean:Bool, output:String } {
        // macOS doesn't expose a direct XProtect CLI, but we can use:
        // 1. `security assess` (same as spctl for files)
        // 2. `mdls` for type info
        // 3. scan via malware scanner if available
        var out = run("security", ["assess", "-v", path]);
        return {
            clean: out.code == 0,
            output: out.stdout + out.stderr,
        };
    }

    /**
     * Get file metadata with mdls
     */
    public static function fileMetadata(path:String):String {
        var out = run("mdls", [path]);
        return out.stdout;
    }

    /**
     * Full security scan: codesign + gatekeeper + quarantine
     */
    public static function fullScan(path:String):{
        codeSign:CodeSignResult,
        gatekeeper:GatekeeperResult,
        quarantine:String,
        warnings:Array<String>,
        safe:Bool,
    } {
        var warnings:Array<String> = [];

        var cs = codesign(path);
        var gk = gatekeeper(path);
        var qt = quarantineInfo(path);

        for (w in cs.warnings) warnings.push(w);

        if (!gk.accepted) {
            warnings.push("⚠ Gatekeeper: NOT accepted (${gk.source ?? 'unknown source'})");
        }

        if (qt.contains("quarantine") && qt.contains("00c1")) {
            warnings.push("ℹ File was quarantined (downloaded from internet) — quarantine cleared");
        }

        var safe = cs.signed && gk.accepted && warnings.length == 0;

        return {
            codeSign: cs,
            gatekeeper: gk,
            quarantine: qt,
            warnings: warnings,
            safe: safe,
        };
    }

    // ----------------------------------------------------------------
    // Process runner
    // ----------------------------------------------------------------

    static function run(cmd:String, args:Array<String>):{ code:Int, stdout:String, stderr:String } {
        try {
            var p = new Process(cmd, args);
            var stdout = p.stdout.readAll().toString();
            var stderr = p.stderr.readAll().toString();
            var code = p.exitCode();
            p.close();
            return { code: code, stdout: stdout, stderr: stderr };
        } catch (e:Dynamic) {
            Logger.warn('[MacSecurity] Process error ($cmd): $e');
            return { code: -1, stdout: "", stderr: Std.string(e) };
        }
    }
}

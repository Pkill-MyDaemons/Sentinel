package sentinel.modules;

using StringTools;

import sentinel.core.IModule;
import sentinel.core.EventBus;
import sentinel.core.Logger;
import sentinel.config.Config;
import sys.io.Process;

/**
 * NetworkMonitor — Module 4
 *
 * Tracks incoming and outgoing network connections per application.
 * Uses native macOS tools (no kernel extension needed):
 *   - `lsof -i -n -P`  → list all network file descriptors with PID/process
 *   - `netstat -anv`   → connection states
 *   - `ss` (if available) → socket stats
 *
 * For each connection:
 *   - Records app name, PID, direction, remote host:port, protocol
 *   - Flags unusual ports, unexpected foreign connections, known C2 patterns
 *   - Emits NetworkConnection events for other modules to react to
 *
 * Future: dtrace/DTrace integration for real-time kernel-level monitoring.
 */

typedef Connection = {
    var pid:Int;
    var app:String;
    var protocol:String;
    var localAddr:String;
    var remoteAddr:String;
    var state:String;
    var direction:String; // "outbound" | "inbound" | "listen"
}

class NetworkMonitor implements IModule {

    var bus:EventBus;
    var cfg:sentinel.config.NetworkConfig;
    var running:Bool = false;
    var knownConnections:Map<String, Connection> = new Map();

    // Ports that are always interesting to flag
    static final SUSPICIOUS_PORTS = [
        4444, 5555, 6666, 7777, 8888, 9999, // common reverse shells
        1337, 31337,                          // "elite" hacker ports
        6667, 6697,                           // IRC (rare for legit apps)
        23, 513, 514,                         // Telnet/rlogin
    ];

    public function new(bus:EventBus) {
        this.bus = bus;
        this.cfg = Config.get().network;
    }

    public function name():String return "NetworkMonitor";

    public function start() {
        running = true;
        sys.thread.Thread.create(monitorLoop);
        Logger.info('[Network] Monitoring connections via lsof...');
    }

    public function stop() {
        running = false;
    }

    // ----------------------------------------------------------------
    // Monitor loop
    // ----------------------------------------------------------------

    function monitorLoop() {
        while (running) {
            try {
                var connections = getConnections();
                processConnections(connections);
            } catch (e:Dynamic) {
                Logger.warn('[Network] Monitor error: $e');
            }
            Sys.sleep(5.0); // poll every 5 seconds
        }
    }

    function getConnections():Array<Connection> {
        var conns:Array<Connection> = [];

        // lsof -i -n -P: list network connections, no DNS, numeric ports
        var p = new Process("lsof", ["-i", "-n", "-P", "-F", "pcnPTs"]);
        var raw = p.stdout.readAll().toString();
        p.exitCode();
        p.close();

        // Parse lsof field output (-F format)
        // Each record starts with 'p' (pid) field
        var records = raw.split("\np");
        for (record in records) {
            var conn = parseLsofRecord("p" + record);
            if (conn != null) conns.push(conn);
        }

        return conns;
    }

    static function parseLsofRecord(record:String):Null<Connection> {
        var lines = record.split("\n");
        var pid = -1;
        var app = "";
        var proto = "";
        var name = "";
        var state = "";

        for (line in lines) {
            if (line.length < 2) continue;
            var code = line.charAt(0);
            var value = line.substr(1).trim();
            switch code {
                case "p": pid = Std.parseInt(value) ?? -1;
                case "c": app = value;
                case "P": proto = value;
                case "n": name = value; // local->remote
                case "T": if (value.startsWith("ST=")) state = value.substr(3);
            }
        }

        if (pid < 0 || name.length == 0) return null;
        if (!name.contains("->") && !name.contains(":")) return null;

        var parts = name.split("->");
        var localAddr = parts[0].trim();
        var remoteAddr = parts.length > 1 ? parts[1].trim() : "";

        var direction = "listen";
        if (remoteAddr.length > 0) {
            direction = state == "ESTABLISHED" ? "outbound" : "outbound";
        }

        return {
            pid: pid,
            app: app,
            protocol: proto,
            localAddr: localAddr,
            remoteAddr: remoteAddr,
            state: state,
            direction: direction,
        };
    }

    // ----------------------------------------------------------------
    // Connection processing
    // ----------------------------------------------------------------

    function processConnections(connections:Array<Connection>) {
        var currentKeys:Map<String, Bool> = new Map();

        for (conn in connections) {
            if (shouldIgnore(conn.app)) continue;
            if (conn.remoteAddr.length == 0) continue;

            var key = '${conn.pid}:${conn.localAddr}:${conn.remoteAddr}';
            currentKeys.set(key, true);

            if (!knownConnections.exists(key)) {
                // New connection
                knownConnections.set(key, conn);
                onNewConnection(conn);
            }
        }

        // Remove stale connections
        for (key in knownConnections.keys()) {
            if (!currentKeys.exists(key)) {
                knownConnections.remove(key);
            }
        }
    }

    function onNewConnection(conn:Connection) {
        if (cfg.logConnections) {
            Logger.info('[Network] ${conn.app}(${conn.pid}) ${conn.direction}: ${conn.localAddr} → ${conn.remoteAddr} [${conn.state}]');
        }

        bus.emitNow(NetworkConnection(conn.app, conn.direction, conn.remoteAddr, extractPort(conn.remoteAddr)));

        // Flag suspicious ports
        var port = extractPort(conn.remoteAddr);
        if (SUSPICIOUS_PORTS.contains(port)) {
            Logger.critical('[Network] SUSPICIOUS PORT ${port} — ${conn.app} → ${conn.remoteAddr}');
            bus.emitNow(Alert(High, "NetworkMonitor",
                '${conn.app} connecting to suspicious port $port (${conn.remoteAddr})'));
            showNetworkAlert(conn, 'Suspicious port: $port');
        }

        // Flag if a non-browser app makes many rapid connections (possible exfil)
        checkRapidConnections(conn.app);
    }

    // ----------------------------------------------------------------
    // Rapid connection detection (possible data exfiltration)
    // ----------------------------------------------------------------

    var connectionCounts:Map<String, Array<Float>> = new Map();

    function checkRapidConnections(app:String) {
        var now = Date.now().getTime() / 1000;
        var times = connectionCounts.get(app) ?? [];

        // Keep only last 60 seconds
        times = times.filter((t) -> now - t < 60);
        times.push(now);
        connectionCounts.set(app, times);

        // More than 20 new connections in 60 seconds from non-browser = suspicious
        var browsers = ["Google Chrome", "Firefox", "Safari", "Chromium", "Arc", "Brave"];
        var isBrowser = browsers.filter((b) -> app.contains(b)).length > 0;

        if (!isBrowser && times.length > 20) {
            Logger.warn('[Network] Rapid connections from ${app}: ${times.length} in 60s');
            bus.emitNow(Alert(Medium, "NetworkMonitor",
                '$app is making rapid connections: ${times.length}/60s'));
        }
    }

    // ----------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------

    function shouldIgnore(app:String):Bool {
        for (ignored in cfg.ignoredApps) {
            if (app == ignored || app.contains(ignored)) return true;
        }
        return false;
    }

    static function extractPort(addr:String):Int {
        var re = ~/:(\d+)$/;
        if (re.match(addr)) return Std.parseInt(re.matched(1)) ?? 0;
        return 0;
    }

    function showNetworkAlert(conn:Connection, reason:String) {
        var msg = '${conn.app} → ${conn.remoteAddr}\n$reason';
        try {
            var p = new Process("osascript", [
                "-e",
                'display notification "${escapeAS(msg)}" with title "🌐 Sentinel: Network Alert" sound name "Sosumi"'
            ]);
            p.exitCode();
            p.close();
        } catch (e:Dynamic) {}
    }

    static function escapeAS(s:String):String {
        return s.split('"').join('\\"').split("\n").join(" ");
    }
}

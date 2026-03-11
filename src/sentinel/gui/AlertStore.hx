package sentinel.gui;

import sentinel.core.EventBus;
import sentinel.core.RiskLevel;
import sentinel.core.Logger;
import haxe.Json;
import sys.io.File;
import sys.FileSystem;


class AlertStore {

    static inline final MAX_ALERTS  = 500;
    static inline final ALERTS_FILE = "/.sentinel/alerts.json";

    var alerts:Array<Alert> = [];
    var nextId:Int = 1;
    var alertsPath:String;

    public function new(bus:EventBus) {
        alertsPath = (Sys.getEnv("HOME") ?? "/tmp") + ALERTS_FILE;
        load();
        bus.subscribe(onEvent);
    }

    public function getAll():Array<Alert>        return alerts.copy();
    public function getUnreviewed():Array<Alert> return alerts.filter(a -> a.status == "new");

    public function markReviewed(id:Int) {
        for (a in alerts) if (a.id == id) { a.status = "reviewed"; save(); return; }
    }

    public function dismiss(id:Int) {
        for (a in alerts) if (a.id == id) { a.status = "dismissed"; save(); return; }
    }

    function onEvent(event:SecurityEvent) {
        var alert:Null<Alert> = switch event {
            case TerminalCommand(cmd, risk, reason):
                make("Terminal", risk, 'Command intercepted', 'cmd: $cmd\n$reason');
            case RepoScanned(url, risk, report):
                make("Terminal", risk, 'Repo scanned: $url', report);
            case UpdateDetected(app, _, url):
                make("Updates", RiskLevel.Low, 'Update detected: $app', 'Download URL: $url');
            case UpdateValidated(app, trusted, reason):
                make("Updates", trusted ? RiskLevel.Safe : RiskLevel.High,
                    'Update validated: $app', reason);
            case ExtensionFlagged(id, name, perms):
                make("Extensions", RiskLevel.High, 'Extension flagged: $name',
                    'ID: $id\nPermissions: ' + perms.join(", "));
            case NetworkConnection(app, dir, host, port):
                make("Network", RiskLevel.Low, '$dir connection: $app', '$app -> $host:$port');
            case Alert(severity, source, message):
                make(source, severity, message, "");
        }
        if (alert != null) { push(alert); save(); }
    }

    function make(source:String, risk:RiskLevel, title:String, detail:String):Alert {
        return {
            id:        nextId++,
            timestamp: timestamp(),
            source:    source,
            risk:      riskName(risk),
            title:     title,
            detail:    detail,
            status:    "new",
        };
    }

    function push(alert:Alert) {
        alerts.unshift(alert);
        if (alerts.length > MAX_ALERTS) alerts = alerts.slice(0, MAX_ALERTS);
    }

    function save() {
        try {
            var dir = haxe.io.Path.directory(alertsPath);
            if (!FileSystem.exists(dir)) FileSystem.createDirectory(dir);
            File.saveContent(alertsPath, Json.stringify({
                nextId: nextId,
                alerts: alerts,
            }, null, "  "));
        } catch (e:Dynamic) {}
    }

    function load() {
        try {
            if (!FileSystem.exists(alertsPath)) return;
            var data = Json.parse(File.getContent(alertsPath));
            nextId = data.nextId;
            alerts = data.alerts;
        } catch (e:Dynamic) {}
    }

    static function riskName(r:RiskLevel):String {
        return switch r {
            case Safe: "safe"; case Low: "low"; case Medium: "medium";
            case High: "high"; case Critical: "critical";
        };
    }

    static function timestamp():String {
        var d = Date.now();
        var pad = (n:Int) -> n < 10 ? "0" + n : "" + n;
        return '${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} '
             + '${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}';
    }
}

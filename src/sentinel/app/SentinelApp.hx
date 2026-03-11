package sentinel.app;

import haxe.ui.HaxeUIApp;
import haxe.ui.ComponentBuilder;
import haxe.ui.core.Screen;
import haxe.ui.Toolkit;
import sentinel.config.Config;

/**
 * SentinelApp — native macOS GUI for the Sentinel Security daemon.
 *
 * Uses HaxeUIApp (the correct haxeui-hxwidgets entry point) which handles
 * Frame creation, Toolkit.init, and the wxWidgets event loop internally.
 *
 * Frame config is set via haxeui-hxwidgets.properties (or Toolkit.backendProperties)
 * rather than Frame constructor arguments.
 *
 * Build:
 *   haxelib install hxWidgets
 *   haxelib install haxeui-core
 *   haxelib install haxeui-hxwidgets
 *   haxe build-app.hxml
 *   ./build/app/SentinelApp
 */
class SentinelApp {

    static var app:HaxeUIApp;
    static var alertsView:AlertsView;
    static var configView:ConfigView;
    static var refreshTimer:haxe.Timer;

    static function main() {
        app = new HaxeUIApp();

        // Frame config — title, size, min size
        Toolkit.backendProperties.setProp("haxe.ui.hxwidgets.frame.title",     "Sentinel Security");
        Toolkit.backendProperties.setProp("haxe.ui.hxwidgets.frame.width",     "900");
        Toolkit.backendProperties.setProp("haxe.ui.hxwidgets.frame.height",    "640");
        Toolkit.backendProperties.setProp("haxe.ui.hxwidgets.frame.minWidth",  "720");
        Toolkit.backendProperties.setProp("haxe.ui.hxwidgets.frame.minHeight", "480");

        app.ready(function() {
            Config.load();

            // Build root UI from XML
            var ui = ComponentBuilder.fromFile("assets/main.xml");
            app.addComponent(ui);

            // Wire up views
            alertsView = new AlertsView(ui);
            configView  = new ConfigView(ui);

            alertsView.reload();
            configView.load();
            updateStatusLabel(ui);

            // Poll every 5 seconds
            refreshTimer = new haxe.Timer(5000);
            refreshTimer.run = function() {
                alertsView.reload();
                updateStatusLabel(ui);
            };

            app.start();
        });
    }

    static function updateStatusLabel(ui:haxe.ui.core.Component) {
        var sockPath  = (Sys.getEnv("HOME") ?? "/tmp") + "/.sentinel/sentinel.sock";
        var daemonOn  = sys.FileSystem.exists(sockPath);
        var newCount  = alertsView != null ? alertsView.newCount() : 0;

        var status = ui.findComponent("status-label", haxe.ui.components.Label, true);
        if (status == null) return;

        var parts = [];
        parts.push(daemonOn ? "● Daemon: running" : "○ Daemon: offline");
        parts.push(newCount > 0 ? '$newCount new alert${newCount == 1 ? "" : "s"}' : "No new alerts");
        status.text = parts.join("    |    ");
    }
}

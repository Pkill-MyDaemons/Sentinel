package sentinel;

import sentinel.config.Config;
import sentinel.core.EventBus;
import sentinel.core.Logger;
import sentinel.modules.TerminalWatcher;
import sentinel.modules.UpdateMonitor;
import sentinel.modules.ExtensionMonitor;
import sentinel.modules.NetworkMonitor;
import sentinel.ai.AIEngine;
import sentinel.platform.Signal;
import sentinel.gui.AlertStore;

/**
 * Sentinel Security — AI-powered macOS security monitor
 *
 * Modules:
 *   1. TerminalWatcher  — intercepts shell commands, fetches repos, runs AI + codesign analysis
 *   2. UpdateMonitor    — inspects app update popups, validates via Info.plist + AI research
 *   3. ExtensionMonitor — audits Chrome extensions for excessive permissions, blocks wss/https
 *   4. NetworkMonitor   — tracks per-app incoming/outgoing connections
 *
 * Compile targets:
 *   HashLink bytecode : haxe build-hl.hxml  → hl sentinel.hl
 *   HashLink/C native : haxe build-hlc.hxml → cmake + make
 *   C++ native        : haxe build-cpp.hxml → hxcpp binary
 */
class Main {

    static var bus:EventBus;
    static var ai:AIEngine;
    static var alertStore:AlertStore;

    static function main() {
        Logger.init();
        Logger.info("Sentinel Security v" + Config.VERSION + " starting...");

        // Load configuration (API keys, thresholds, local model path)
        Config.load();

        // Central event bus — all modules communicate through here
        bus = new EventBus();

        // Alert store — subscribes to bus, persists alerts to ~/.sentinel/alerts.json
        alertStore = new AlertStore(bus);

        // AI engine — defaults to local Ollama; falls back to Anthropic/OpenAI if configured
        ai = new AIEngine(Config.get());

        // Boot all monitoring modules
        var modules:Array<sentinel.core.IModule> = [
            new TerminalWatcher(bus, ai),
            new UpdateMonitor(bus, ai),
            new ExtensionMonitor(bus, ai),
            new NetworkMonitor(bus),
        ];

        for (mod in modules) {
            try {
                mod.start();
                Logger.info('[Module] ${mod.name()} started');
            } catch (e:Dynamic) {
                Logger.error('[Module] ${mod.name()} failed to start: $e');
            }
        }

        Logger.info("All modules active. Sentinel is watching.");

        // Keep the process alive (native event loop)
        runLoop(modules);
    }

    static function runLoop(modules:Array<sentinel.core.IModule>) {
        #if (hl || hlc || cpp)
        // Native: use a blocking loop with OS signals
        var running = true;
        Signal.onInterrupt(() -> {
            Logger.info("Shutting down Sentinel...");
            for (mod in modules) mod.stop();
            running = false;
        });
        while (running) {
            Sys.sleep(0.1);
            bus.flush();
        }
        #else
        // Interpreted fallback
        while (true) {
            Sys.sleep(0.1);
            bus.flush();
        }
        #end
    }
}

package sentinel.core;


/**
 * Lightweight synchronous event bus.
 * Modules publish typed SecurityEvents; other modules subscribe to react.
 */

enum SecurityEvent {
    /** Terminal: a command was intercepted */
    TerminalCommand(cmd:String, risk:RiskLevel, reason:String);
    /** Terminal: a GitHub repo was fetched and scanned */
    RepoScanned(url:String, risk:RiskLevel, report:String);
    /** Update popup detected for an app */
    UpdateDetected(appName:String, plistPath:String, downloadUrl:String);
    /** Update validated */
    UpdateValidated(appName:String, trusted:Bool, reason:String);
    /** Chrome extension flagged */
    ExtensionFlagged(extId:String, name:String, permissions:Array<String>);
    /** Network connection detected */
    NetworkConnection(app:String, direction:String, host:String, port:Int);
    /** Generic alert */
    Alert(severity:RiskLevel, source:String, message:String);
}

typedef EventHandler = (event:SecurityEvent) -> Void;

class EventBus {

    var handlers:Array<EventHandler> = [];
    var queue:Array<SecurityEvent> = [];

    public function new() {}

    public function subscribe(handler:EventHandler) {
        handlers.push(handler);
    }

    /** Queue an event to be dispatched on next flush() */
    public function emit(event:SecurityEvent) {
        queue.push(event);
    }

    /** Emit immediately (synchronous, use from main thread only) */
    public function emitNow(event:SecurityEvent) {
        dispatch(event);
    }

    /** Drain the queue — called from main loop */
    public function flush() {
        var current = queue.copy();
        queue = [];
        for (event in current) dispatch(event);
    }

    function dispatch(event:SecurityEvent) {
        for (h in handlers) {
            try {
                h(event);
            } catch (e:Dynamic) {
                Logger.error('EventBus handler error: $e');
            }
        }
    }
}

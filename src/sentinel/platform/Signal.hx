package sentinel.platform;

/**
 * Signal handling for native HashLink and C++ builds.
 * Wraps SIGINT / SIGTERM for clean daemon shutdown.
 *
 * HashLink (.hl / hlc):
 *   Uses hl.Api.signal() — built into the HashLink runtime (no extra .hdll).
 *   hl.Api.signal(2, cb) = SIGINT, hl.Api.signal(15, cb) = SIGTERM.
 *
 * C++ (hxcpp):
 *   Uses Sys.exit signal hook via untyped __cpp__ + signal.h (included at
 *   file scope via @:cppFileCode so the macOS SDK headers parse correctly).
 *
 * Interpreted / other targets: no-op (Ctrl+C terminates normally).
 */
@:cppFileCode('#include <signal.h>')
class Signal {

    static var handler:Null<() -> Void>;

    /**
     * Register a callback to run on SIGINT / SIGTERM.
     * Call once at startup. The callback should set a `running = false`
     * flag and let the main loop exit cleanly.
     */
    public static function onInterrupt(fn:() -> Void) {
        handler = fn;

        #if (hl || hlc)
        // hl.Api.signal is part of the HashLink standard library —
        // no sentinel.hdll or any other .hdll required.
        // Signal numbers: 2 = SIGINT, 15 = SIGTERM.
        hl.Api.signal(2,  function() { if (handler != null) handler(); });
        hl.Api.signal(15, function() { if (handler != null) handler(); });
        #elseif cpp
        cppInstall();
        #end
    }

    // ── C++ ────────────────────────────────────────────────────────

    #if cpp
    // Called from onInterrupt on the cpp target.
    // signal.h is pulled in at translation-unit level by @:cppFileCode.
    static function cppInstall():Void {
        untyped __cpp__('
            signal(SIGINT, [](int) {
                hx::SetTopOfStack((int*)99, true);
                sentinel::platform::Signal_obj::_handler_s();
            });
            signal(SIGTERM, [](int) {
                hx::SetTopOfStack((int*)99, true);
                sentinel::platform::Signal_obj::_handler_s();
            });
        ');
    }

    // Static trampoline the C++ lambda calls back into.
    // Must be a static function with a predictable mangled name.
    public static function _handler_s():Void {
        if (handler != null) handler();
    }
    #end
}

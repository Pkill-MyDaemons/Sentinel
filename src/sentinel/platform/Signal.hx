package sentinel.platform;

/**
 * Signal handling for native HashLink/C++ builds.
 * Wraps SIGINT/SIGTERM for clean shutdown.
 *
 * For HashLink: uses @:hlNative binding to sentinel.hdll
 * For C++:      uses hxcpp @:cppFileCode to emit the #include at file scope,
 *               then registers handlers via untyped __cpp__ inside the method.
 *
 * The #include MUST be at translation-unit level — injecting it inside a
 * function body via __cpp__ causes "expected unqualified-id" from the
 * macOS SDK headers (which use extern "C" { } blocks at file scope).
 */
@:cppFileCode('#include <signal.h>')
class Signal {

    static var handler:() -> Void;

    public static function onInterrupt(fn:() -> Void) {
        handler = fn;

        #if (hl || hlc)
        hlInterrupt();
        #elseif cpp
        cppInterrupt();
        #else
        // Interpreted targets: no-op (Ctrl+C terminates normally)
        #end
    }

    #if (hl || hlc)
    @:hlNative("sentinel", "register_interrupt")
    static function hlInterrupt():Void {}
    #end

    #if cpp
    static function cppInterrupt():Void {
        // signal.h is included at file scope via @:cppFileCode above.
        // hx::SetTopOfStack registers the signal handler with the hxcpp GC
        // so it can safely call back into Haxe from the signal context.
        untyped __cpp__('
            signal(SIGINT, [](int) {
                hx::SetTopOfStack((int*)99, true);
                sentinel::platform::Signal_obj::_handler();
            });
            signal(SIGTERM, [](int) {
                hx::SetTopOfStack((int*)99, true);
                sentinel::platform::Signal_obj::_handler();
            });
        ');
    }

    static function _handler():Void {
        if (handler != null) handler();
    }
    #end
}

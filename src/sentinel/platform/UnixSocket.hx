package sentinel.platform;

/**
 * UnixSocket — Haxe bindings for Unix domain socket operations.
 *
 * HashLink (.hl / hlc) → sentinel_socket.hdll via @:hlNative
 * C++ (hxcpp)          → sentinel_socket_cpp.cpp via untyped __cpp__
 *
 * @:buildXml injects into the generated Build.xml so hxcpp compiles
 * sentinel_socket_cpp.cpp as part of the build — this is what actually
 * provides the symbol definitions the linker needs.
 *
 * @:cppFileCode emits extern "C" forward declarations at the top of the
 * generated UnixSocket.cpp so the compiler knows the signatures at each
 * __cpp__ call site.
 *
 * Path in @:buildXml is relative to the hxcpp output directory (build/cpp).
 * ../../native/ reaches the project-root native/ folder from there.
 */
@:buildXml('
<files id="haxe">
  <file name="../../native/sentinel_socket_cpp.cpp"/>
</files>
')
@:cppFileCode('
extern "C" {
    int   sentinel_unix_create(const char* path);
    int   sentinel_unix_accept(int server_fd);
    char* sentinel_unix_read(int fd);
    void  sentinel_unix_write(int fd, const char* msg);
    void  sentinel_unix_close(int fd);
    void  sentinel_unix_destroy(int fd, const char* path);
    void  sentinel_unix_free_string(char* s);
    void  sentinel_unix_set_timeout(int fd, int ms);
    int   sentinel_unix_get_errno();
}
')
class UnixSocket {

    static inline var READ_BUF_SIZE = 4096;

    // ----------------------------------------------------------------
    // Public API
    // ----------------------------------------------------------------

    /**
     * Create, bind and listen on a Unix domain socket at `path`.
     * Returns a server fd >= 0, or -1 on failure (check lastError()).
     */
    public static function create(path:String):Int {
        #if (hl || hlc)
        return hlCreate(@:privateAccess path.bytes);
        #elseif cpp
        return untyped __cpp__('sentinel_unix_create({0})', path.c_str());
        #else
        throw "UnixSocket not supported on this target";
        return -1;
        #end
    }

    /**
     * Block until a client connects. Returns client fd or -1.
     * Call this in a dedicated thread — this blocks indefinitely.
     */
    public static function accept(serverFd:Int):Int {
        #if (hl || hlc)
        return hlAccept(serverFd);
        #elseif cpp
        return untyped __cpp__('sentinel_unix_accept({0})', serverFd);
        #else
        return -1;
        #end
    }

    /**
     * Read a newline-terminated message from a client fd.
     * Returns null on disconnect or timeout.
     *
     * For HL: pre-allocates a Haxe-managed buffer and passes it to C.
     * For C++: receives a heap-allocated char* from C, copies to String,
     *          then frees via sentinel_unix_free_string.
     */
    public static function read(clientFd:Int):Null<String> {
        #if (hl || hlc)
        var buf = new hl.Bytes(READ_BUF_SIZE);
        var n = hlRead(clientFd, buf, READ_BUF_SIZE);
        if (n <= 0) return null;
        // buf.sub(offset, length)
        var subBytes = buf.sub(0, n);
        return @:privateAccess String.fromUTF8(subBytes);

        #elseif cpp
        // Declare ptr as char* so nullptr comparison and free are unambiguous.
        // __cpp__ with a return-type cast avoids ::Dynamic operator== ambiguity.
        var ptr:cpp.Star<cpp.Char> = untyped __cpp__(
            '(char*)sentinel_unix_read({0})', clientFd
        );
        if (ptr == null) return null;
        var s:String = untyped __cpp__('::String((const char*){0})', ptr);
        untyped __cpp__('sentinel_unix_free_string((char*){0})', ptr);
        return s;
        #else
        return null;
        #end
    }

    /**
     * Write a response string to a client fd.
     * A newline is appended automatically by the C layer.
     */
    public static function write(clientFd:Int, msg:String):Void {
        #if (hl || hlc)
        hlWrite(clientFd, @:privateAccess msg.bytes);
        #elseif cpp
        untyped __cpp__('sentinel_unix_write({0}, {1})', clientFd, msg.c_str());
        #end
    }

    /**
     * Close a client connection fd.
     */
    public static function closeClient(clientFd:Int):Void {
        #if (hl || hlc)
        hlClose(clientFd);
        #elseif cpp
        untyped __cpp__('sentinel_unix_close({0})', clientFd);
        #end
    }

    /**
     * Close the server socket AND unlink the socket file.
     */
    public static function destroy(serverFd:Int, path:String):Void {
        #if (hl || hlc)
        hlDestroy(serverFd, @:privateAccess path.bytes);
        #elseif cpp
        untyped __cpp__('sentinel_unix_destroy({0}, {1})', serverFd, path.c_str());
        #end
    }

    /**
     * Set a receive timeout (milliseconds) on a fd.
     */
    public static function setTimeout(fd:Int, ms:Int):Void {
        #if (hl || hlc)
        hlSetTimeout(fd, ms);
        #elseif cpp
        untyped __cpp__('sentinel_unix_set_timeout({0}, {1})', fd, ms);
        #end
    }

    /**
     * Return the last OS errno — useful for diagnosing create() failures.
     */
    public static function lastError():Int {
        #if (hl || hlc)
        return hlErrno();
        #elseif cpp
        return untyped __cpp__('sentinel_unix_get_errno()');
        #else
        return 0;
        #end
    }

    // ----------------------------------------------------------------
    // HashLink @:hlNative bindings (hl / hlc targets only)
    // ----------------------------------------------------------------

    #if (hl || hlc)
    @:hlNative("sentinel_socket", "sentinel_socket_create")
    static function hlCreate(path:hl.Bytes):Int { return -1; }

    @:hlNative("sentinel_socket", "sentinel_socket_accept")
    static function hlAccept(fd:Int):Int { return -1; }

    @:hlNative("sentinel_socket", "sentinel_socket_read")
    static function hlRead(fd:Int, buf:hl.Bytes, bufLen:Int):Int { return -1; }

    @:hlNative("sentinel_socket", "sentinel_socket_write")
    static function hlWrite(fd:Int, msg:hl.Bytes):Void {}

    @:hlNative("sentinel_socket", "sentinel_socket_close")
    static function hlClose(fd:Int):Void {}

    @:hlNative("sentinel_socket", "sentinel_socket_destroy")
    static function hlDestroy(fd:Int, path:hl.Bytes):Void {}

    @:hlNative("sentinel_socket", "sentinel_socket_set_timeout")
    static function hlSetTimeout(fd:Int, ms:Int):Void {}

    @:hlNative("sentinel_socket", "sentinel_socket_errno")
    static function hlErrno():Int { return 0; }
    #end
}

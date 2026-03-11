/**
 * sentinel_socket.c — HashLink native extension (.hdll)
 *
 * Unix domain socket server for Sentinel's shell preexec hook.
 *
 * Key design decisions:
 *   - We do NOT call hl_alloc_bytes() or any GC-managed allocator from
 *     the accept/handler threads. Instead, sentinel_socket_read() fills
 *     a caller-supplied buffer (passed in as a vbyte*), which is allocated
 *     on the Haxe side via hl.Bytes.alloc(). This keeps GC interaction on
 *     the HL main thread only.
 *
 *   - The module init function (registered via HL_MODULE_INIT) is a no-op
 *     but satisfies HashLink's dynamic loader requirement.
 *
 * Exported functions (see DEFINE_PRIM table at the bottom):
 *
 *   sentinel_socket_create(path:bytes) : int
 *     Bind and listen on a Unix socket. Returns fd >= 0, or -1 on error.
 *
 *   sentinel_socket_accept(server_fd:int) : int
 *     Block until a client connects. Returns client fd, or -1.
 *
 *   sentinel_socket_read(client_fd:int, buf:bytes, buf_len:int) : int
 *     Read a newline-terminated message into caller-supplied buf.
 *     Returns bytes written (0 = disconnected, -1 = error).
 *     buf must be pre-allocated by Haxe: hl.Bytes.alloc(N)
 *
 *   sentinel_socket_write(client_fd:int, msg:bytes) : void
 *   sentinel_socket_close(fd:int) : void
 *   sentinel_socket_destroy(server_fd:int, path:bytes) : void
 *   sentinel_socket_set_timeout(fd:int, ms:int) : void
 *   sentinel_socket_errno() : int
 */
#define HL_NAME(n) sentinel_##n

#include <hl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

/* Module init — satisfies HashLink's dynamic loader */
HL_PRIM void HL_NAME(socket_init_module)(void) { }

/* Create + bind + listen */
HL_PRIM int HL_NAME(socket_create)(vbyte *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, (const char*)path, sizeof(addr.sun_path) - 1);
    unlink((const char*)path);
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
    if (listen(fd, 16) < 0) { close(fd); return -1; }
    return fd;
}

/* Block until a client connects */
HL_PRIM int HL_NAME(socket_accept)(int server_fd) {
    struct sockaddr_un addr;
    socklen_t len = sizeof(addr);
    return accept(server_fd, (struct sockaddr*)&addr, &len);
}

/*
 * Read a newline-terminated line into a CALLER-SUPPLIED buffer.
 * The buffer must be allocated on the Haxe side (hl.Bytes.alloc(N)).
 * Returns: bytes written (>=0), or -1 on error.
 */
HL_PRIM int HL_NAME(socket_read)(int client_fd, vbyte *buf, int buf_len) {
    if (!buf || buf_len < 1) return -1;
    int total = 0;
    char ch;
    while (total < buf_len - 1) {
        int n = (int)read(client_fd, &ch, 1);
        if (n < 0)  return -1;
        if (n == 0) break;
        if (ch == '\n') break;
        ((char*)buf)[total++] = ch;
    }
    ((char*)buf)[total] = '\0';
    return total;
}

/* Write msg + '\n' to fd */
HL_PRIM void HL_NAME(socket_write)(int client_fd, vbyte *msg) {
    if (!msg || client_fd < 0) return;
    size_t len = strlen((const char*)msg);
    (void)write(client_fd, (const char*)msg, len);
    (void)write(client_fd, "\n", 1);
}

/* Close a client fd */
HL_PRIM void HL_NAME(socket_close)(int fd) {
    if (fd >= 0) close(fd);
}

/* Close server fd + unlink socket file */
HL_PRIM void HL_NAME(socket_destroy)(int server_fd, vbyte *path) {
    if (server_fd >= 0) close(server_fd);
    if (path) unlink((const char*)path);
}

/* SO_RCVTIMEO in milliseconds */
HL_PRIM void HL_NAME(socket_set_timeout)(int fd, int ms) {
    struct timeval tv;
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

/* Return current errno */
HL_PRIM int HL_NAME(socket_errno)(void) {
    return errno;
}

/* -----------------------------------------------------------------------
 * HashLink export table
 * HL_NAME(socket_create) expands to sentinel_socket_create, which must
 * match the @:hlNative("sentinel_socket","sentinel_socket_create") binding.
 * ----------------------------------------------------------------------- 
 */
DEFINE_PRIM(_VOID, socket_init_module,  _NO_ARG);
DEFINE_PRIM(_I32,  socket_create,       _BYTES);
DEFINE_PRIM(_I32,  socket_accept,       _I32);
DEFINE_PRIM(_I32,  socket_read,         _I32 _BYTES _I32);
DEFINE_PRIM(_VOID, socket_write,        _I32 _BYTES);
DEFINE_PRIM(_VOID, socket_close,        _I32);
DEFINE_PRIM(_VOID, socket_destroy,      _I32 _BYTES);
DEFINE_PRIM(_VOID, socket_set_timeout,  _I32 _I32);
DEFINE_PRIM(_I32,  socket_errno,        _NO_ARG);
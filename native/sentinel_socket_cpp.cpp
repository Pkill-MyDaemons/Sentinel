/**
 * sentinel_socket_cpp.cpp
 *
 * Unix domain socket implementation for the hxcpp (C++) compile target.
 * Haxe/hxcpp calls these via untyped __cpp__ in UnixSocketServer.hx.
 *
 * This file is included automatically by hxcpp when present in the
 * project — no explicit linking needed beyond including it in build.xml.
 *
 * Build note: hxcpp will compile this alongside the generated C++.
 * Add to Build.xml: <file name="../../native/sentinel_socket_cpp.cpp"/>
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <string>

extern "C" {

int sentinel_unix_create(const char* path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    unlink(path); // remove stale socket

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd); return -1;
    }
    if (listen(fd, 16) < 0) {
        close(fd); return -1;
    }
    return fd;
}

int sentinel_unix_accept(int server_fd) {
    struct sockaddr_un addr;
    socklen_t len = sizeof(addr);
    return accept(server_fd, (struct sockaddr*)&addr, &len);
}

// Returns heap-allocated string — caller must free
char* sentinel_unix_read(int fd) {
    static char buf[4096];
    int total = 0;
    char ch;
    while (total < 4095) {
        int n = (int)read(fd, &ch, 1);
        if (n <= 0) break;
        if (ch == '\n') break;
        buf[total++] = ch;
    }
    if (total == 0) return nullptr;
    buf[total] = '\0';
    char* result = new char[total + 1];
    memcpy(result, buf, total + 1);
    return result;
}

void sentinel_unix_write(int fd, const char* msg) {
    if (!msg) return;
    write(fd, msg, strlen(msg));
    write(fd, "\n", 1);
}

void sentinel_unix_close(int fd) {
    if (fd >= 0) close(fd);
}

void sentinel_unix_destroy(int fd, const char* path) {
    if (fd >= 0) close(fd);
    if (path) unlink(path);
}

void sentinel_unix_free_string(char* s) {
    delete[] s;
}

void sentinel_unix_set_timeout(int fd, int ms) {
    struct timeval tv;
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int sentinel_unix_get_errno() {
    return errno;
}

} // extern "C"

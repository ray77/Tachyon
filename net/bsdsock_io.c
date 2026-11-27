#include <exec/types.h>
#include <exec/execbase.h>
#include <proto/exec.h>
#include "bsdsock_io.h"
#include "bsdsocket13.h"

extern struct ExecBase *SysBase;

static LONG bs_errno(bsdsock_io *io, const char *what) { io->err = __bs_Errno(io->base); io->fail = what; return io->err; }

int bsdsock_open(bsdsock_io *io)
{
    io->sock = -1; io->err = 0; io->fail = 0;
    io->base = OpenLibrary((STRPTR)"bsdsocket.library", 0);
    if (!io->base) { io->fail = "OpenLibrary bsdsocket.library"; return 0; }
    /* no break signals into blocking calls: the client polls with WaitSelect timeouts instead */
    __bs_SetSocketSignals(io->base, 0, 0, 0);
    return 1;
}

void bsdsock_close(bsdsock_io *io)
{
    bsdsock_disconnect(io);
    if (io->base) { CloseLibrary(io->base); io->base = 0; }
}

int bsdsock_stack_ready(bsdsock_io *io)
{
    LONG s;
    if (!io->base) return 0;
    s = __bs_socket(io->base, BS_AF_INET, BS_SOCK_STREAM, 0);
    if (s < 0) { bs_errno(io, "socket"); return 0; }
    __bs_CloseSocket(io->base, s);
    return 1;
}

ULONG bsdsock_parse_ip(const char *dotted)
{
    ULONG v = 0; int part = 0, digits = 0; ULONG acc = 0;
    if (!dotted) return 0;
    for (;; dotted++) {
        char c = *dotted;
        if (c >= '0' && c <= '9') { acc = acc * 10 + (ULONG)(c - '0'); digits++; if (acc > 255 || digits > 3) return 0; }
        else if (c == '.' || c == 0) {
            if (!digits) return 0;
            v = (v << 8) | acc; acc = 0; digits = 0; part++;
            if (c == 0) break;
            if (part > 3) return 0;
        } else return 0;
    }
    return part == 4 ? v : 0;    /* host order == network order on the 68000 (big-endian) */
}

void bsdsock_ntoa(ULONG a, char *buf)
{
    int i, o = 0;
    for (i = 3; i >= 0; i--) {
        ULONG b = (a >> (i * 8)) & 255; char tmp[4]; int n = 0;
        do { tmp[n++] = (char)('0' + b % 10); b /= 10; } while (b);
        while (n) buf[o++] = tmp[--n];
        if (i) buf[o++] = '.';
    }
    buf[o] = 0;
}

int bsdsock_resolve(bsdsock_io *io, const char *host, const char *fallback, ULONG *addr_be)
{
    struct bs_hostent *he;
    ULONG a = bsdsock_parse_ip(host);
    if (a) { *addr_be = a; return 1; }
    if (io->base) {
        he = __bs_gethostbyname(io->base, host);
        if (he && he->h_addrtype == BS_AF_INET && he->h_length == 4 && he->h_addr_list && he->h_addr_list[0]) {
            const UBYTE *p = (const UBYTE *)he->h_addr_list[0];
            *addr_be = ((ULONG)p[0] << 24) | ((ULONG)p[1] << 16) | ((ULONG)p[2] << 8) | p[3];
            return 1;
        }
        bs_errno(io, "gethostbyname");
    }
    a = bsdsock_parse_ip(fallback);
    if (a) { *addr_be = a; return 1; }
    return 0;
}

int bsdsock_connect(bsdsock_io *io, ULONG addr_be, UWORD port)
{
    struct bs_sockaddr_in sa; int i; LONG one = 1;
    if (!io->base) return 0;
    bsdsock_disconnect(io);
    io->sock = __bs_socket(io->base, BS_AF_INET, BS_SOCK_STREAM, 0);
    if (io->sock < 0) { bs_errno(io, "socket"); io->sock = -1; return 0; }
    for (i = 0; i < (int)sizeof sa; i++) ((UBYTE *)&sa)[i] = 0;
    sa.sin_len = sizeof sa; sa.sin_family = BS_AF_INET; sa.sin_port = port; sa.sin_addr.s_addr = addr_be;
    if (__bs_connect(io->base, io->sock, &sa, sizeof sa) != 0) { bs_errno(io, "connect"); bsdsock_disconnect(io); return 0; }
    /* TLS records and WebSocket frames are written whole: no Nagle delay on the small handshake messages
     * (ignored by stacks without the option - TheWire13 reports ENOPROTOOPT for unknown options) */
    __bs_setsockopt(io->base, io->sock, BS_IPPROTO_TCP, BS_TCP_NODELAY, &one, sizeof one);
    return 1;
}

int bsdsock_send(bsdsock_io *io, const uint8_t *p, uint32_t n)
{
    if (io->sock < 0) return 0;
    while (n) {
        LONG r = __bs_send(io->base, io->sock, p, (LONG)n, 0);
        if (r <= 0) { bs_errno(io, "send"); return 0; }
        p += r; n -= (uint32_t)r;
    }
    return 1;
}

LONG bsdsock_recv(bsdsock_io *io, uint8_t *p, uint32_t cap, uint32_t timeout_ms)
{
    bs_fd_set rf; struct bs_timeval tv; LONG r;
    if (io->sock < 0) return -1;
    BS_FD_ZERO(&rf); BS_FD_SET(io->sock, &rf);
    tv.tv_secs = (LONG)(timeout_ms / 1000); tv.tv_micro = (LONG)(timeout_ms % 1000) * 1000;
    r = __bs_WaitSelect(io->base, io->sock + 1, &rf, 0, 0, &tv, 0);
    if (r == 0) return 0;
    if (r < 0) { bs_errno(io, "WaitSelect"); return -1; }
    r = __bs_recv(io->base, io->sock, p, (LONG)cap, 0);
    if (r == 0) { io->fail = "recv (closed by peer)"; io->err = 0; return -1; }
    if (r < 0) { bs_errno(io, "recv"); return -1; }
    return r;
}

void bsdsock_disconnect(bsdsock_io *io)
{
    if (io->base && io->sock >= 0) __bs_CloseSocket(io->base, io->sock);
    io->sock = -1;
}

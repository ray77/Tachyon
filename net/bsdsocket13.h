/*
 * Tachyon - minimal bsdsocket.library bindings for Kickstart 1.3 (vbcc, no SDK).
 *
 * The AmiTCP-style bsdsocket.library ABI (library vector offsets and register conventions from the
 * AmiTCP `bsdsocket_lib.fd`): the same interface TheWire13's bsdsocket.library 4.x on OS 1.3 exposes and
 * every later stack (AmiTCP, Miami, Roadshow, UAE's emulated library) kept, so this header is the
 * whole network dependency of the client - any SANA-II card the stack drives works unchanged.
 * Only what the client uses is declared; the base is passed explicitly (a6), nothing global.
 * Structures follow 4.4BSD as AmiTCP does: sockaddr_in with sin_len, 64-descriptor fd_set,
 * timeval = { secs, micros } (same layout as timer.device's).
 */
#ifndef TACHYON_BSDSOCKET13_H
#define TACHYON_BSDSOCKET13_H

#include <exec/types.h>

struct bs_in_addr { ULONG s_addr; };                       /* network byte order */
struct bs_sockaddr_in {
    UBYTE sin_len; UBYTE sin_family; UWORD sin_port;      /* port in network byte order */
    struct bs_in_addr sin_addr; UBYTE sin_zero[8];
};
struct bs_hostent { char *h_name; char **h_aliases; LONG h_addrtype; LONG h_length; char **h_addr_list; };
struct bs_timeval { LONG tv_secs; LONG tv_micro; };
#define BS_FD_SETSIZE 64
typedef struct { ULONG fds_bits[BS_FD_SETSIZE / 32]; } bs_fd_set;
#define BS_FD_ZERO(s)   ((s)->fds_bits[0] = 0, (s)->fds_bits[1] = 0)
#define BS_FD_SET(d, s) ((s)->fds_bits[(d) >> 5] |= 1UL << ((d) & 31))
#define BS_FD_ISSET(d, s) (((s)->fds_bits[(d) >> 5] >> ((d) & 31)) & 1UL)

#define BS_AF_INET      2
#define BS_SOCK_STREAM  1
#define BS_IPPROTO_TCP  6
#define BS_SOL_SOCKET   0xffff
#define BS_SO_KEEPALIVE 0x0008
#define BS_TCP_NODELAY  0x01
#define BS_MSG_DONTWAIT 0x80
/* errno values (4.4BSD / AmiTCP netinclude/sys/errno.h) */
#define BS_EINTR        4
#define BS_EWOULDBLOCK  35
#define BS_EINPROGRESS  36
#define BS_ECONNRESET   54
#define BS_ETIMEDOUT    60
#define BS_ECONNREFUSED 61

/* library vectors: -30 socket, -36 bind, -42 listen, -48 accept, -54 connect, -60 sendto, -66 send,
 * -72 recvfrom, -78 recv, -84 shutdown, -90 setsockopt, -96 getsockopt, -102 getsockname, -108 getpeername,
 * -114 IoctlSocket, -120 CloseSocket, -126 WaitSelect, -132 SetSocketSignals, -138 getdtablesize,
 * -144 ObtainSocket, -150 ReleaseSocket, -156 ReleaseCopyOfSocket, -162 Errno, -168 SetErrnoPtr,
 * -174 Inet_NtoA, -180 inet_addr, ... -210 gethostbyname, -216 gethostbyaddr, ... -282 gethostname,
 * -288 gethostid, -294 SocketBaseTagList, -300 GetSocketEvents */
LONG  __bs_socket(__reg("a6") void *, __reg("d0") LONG domain, __reg("d1") LONG type, __reg("d2") LONG protocol) = "\tjsr\t-30(a6)";
LONG  __bs_connect(__reg("a6") void *, __reg("d0") LONG s, __reg("a0") const struct bs_sockaddr_in *name, __reg("d1") LONG namelen) = "\tjsr\t-54(a6)";
LONG  __bs_send(__reg("a6") void *, __reg("d0") LONG s, __reg("a0") const void *buf, __reg("d1") LONG len, __reg("d2") LONG flags) = "\tjsr\t-66(a6)";
LONG  __bs_recv(__reg("a6") void *, __reg("d0") LONG s, __reg("a0") void *buf, __reg("d1") LONG len, __reg("d2") LONG flags) = "\tjsr\t-78(a6)";
LONG  __bs_shutdown(__reg("a6") void *, __reg("d0") LONG s, __reg("d1") LONG how) = "\tjsr\t-84(a6)";
LONG  __bs_setsockopt(__reg("a6") void *, __reg("d0") LONG s, __reg("d1") LONG level, __reg("d2") LONG optname, __reg("a0") const void *optval, __reg("d3") LONG optlen) = "\tjsr\t-90(a6)";
LONG  __bs_IoctlSocket(__reg("a6") void *, __reg("d0") LONG s, __reg("d1") ULONG request, __reg("a0") void *argp) = "\tjsr\t-114(a6)";
LONG  __bs_CloseSocket(__reg("a6") void *, __reg("d0") LONG s) = "\tjsr\t-120(a6)";
LONG  __bs_WaitSelect(__reg("a6") void *, __reg("d0") LONG nfds, __reg("a0") bs_fd_set *readfds, __reg("a1") bs_fd_set *writefds,
                      __reg("a2") bs_fd_set *exceptfds, __reg("a3") struct bs_timeval *timeout, __reg("d1") ULONG *maskp) = "\tjsr\t-126(a6)";
VOID  __bs_SetSocketSignals(__reg("a6") void *, __reg("d0") ULONG intrmask, __reg("d1") ULONG iomask, __reg("d2") ULONG urgmask) = "\tjsr\t-132(a6)";
LONG  __bs_Errno(__reg("a6") void *) = "\tjsr\t-162(a6)";
char *__bs_Inet_NtoA(__reg("a6") void *, __reg("d0") ULONG in) = "\tjsr\t-174(a6)";
ULONG __bs_inet_addr(__reg("a6") void *, __reg("a0") const char *cp) = "\tjsr\t-180(a6)";
struct bs_hostent *__bs_gethostbyname(__reg("a6") void *, __reg("a0") const char *name) = "\tjsr\t-210(a6)";
LONG  __bs_gethostname(__reg("a6") void *, __reg("a0") char *name, __reg("d0") LONG namelen) = "\tjsr\t-282(a6)";

#endif

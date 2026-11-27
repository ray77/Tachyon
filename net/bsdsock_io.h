/*
 * Tachyon - network adapter for the Amiga: a TCP stream over bsdsocket.library (AmiTCP ABI, TheWire13 on
 * Kickstart 1.3), driven by the I/O-agnostic clients in crypto/ref (tls13.c moves bytes through
 * tls13_input / t->out, ws.c and noise.c sit above). Blocking calls only, with every wait bounded by a
 * timeout through WaitSelect(): the client is single-threaded and cooperative (CRYPTO_YIELD heartbeat),
 * nothing here runs from an interrupt or a second task.
 *
 * Life cycle: bsdsock_open (library; the stack must be running), bsdsock_stack_ready (socket() succeeds),
 * bsdsock_resolve (gethostbyname, else a dotted address), bsdsock_connect, send/recv, bsdsock_disconnect,
 * bsdsock_close.
 */
#ifndef TACHYON_BSDSOCK_IO_H
#define TACHYON_BSDSOCK_IO_H

#include <exec/types.h>
#include <stdint.h>

typedef struct {
    struct Library *base;       /* bsdsocket.library, 0 when not open */
    LONG sock;                  /* descriptor, -1 when no connection */
    LONG err;                   /* bsdsocket Errno() of the last failed call */
    const char *fail;           /* name of the last failed call ("connect", "recv", ...) */
} bsdsock_io;

int   bsdsock_open(bsdsock_io *io);                 /* 1 = library open (TheWire13 opens only while the stack runs) */
void  bsdsock_close(bsdsock_io *io);
int   bsdsock_stack_ready(bsdsock_io *io);          /* 1 = socket() works: the stack answers */
/* host name -> IPv4 in network byte order: gethostbyname (the stack's DNS), or the dotted form of `host`
 * / `fallback` (may be 0). 1 on success. */
int   bsdsock_resolve(bsdsock_io *io, const char *host, const char *fallback, ULONG *addr_be);
ULONG bsdsock_parse_ip(const char *dotted);         /* "a.b.c.d" -> network byte order, 0 if malformed */
int   bsdsock_connect(bsdsock_io *io, ULONG addr_be, UWORD port);
/* send the whole buffer (several send() calls if the stack takes part of it); 1 when all bytes are queued */
int   bsdsock_send(bsdsock_io *io, const uint8_t *p, uint32_t n);
/* wait up to timeout_ms for data: >0 bytes read, 0 timeout, -1 connection closed or error (io->err) */
LONG  bsdsock_recv(bsdsock_io *io, uint8_t *p, uint32_t cap, uint32_t timeout_ms);
void  bsdsock_disconnect(bsdsock_io *io);
/* a.b.c.d of a network-order address into buf (16 bytes) */
void  bsdsock_ntoa(ULONG addr_be, char *buf);

#endif

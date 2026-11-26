/* SHA-1 - only for the WebSocket Sec-WebSocket-Accept handshake (RFC 6455), not for security. */
#ifndef WHATSA500_SHA1_H
#define WHATSA500_SHA1_H
#include <stdint.h>
void sha1(uint8_t out[20], const uint8_t *data, uint32_t len);
#endif

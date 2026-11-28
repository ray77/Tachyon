/*
 * Unity build for the Amiga WhatsApp probe (TCP/IP over bsdsocket.library): without a linker
 * (see docs/TOOLCHAIN.md) every C module is compiled as one translation unit so vbcc emits a single
 * assembler file; bench/amiga/startup_probe.s includes it together with the assembler backends.
 */
#define WA_PROBE_ALLOC 1          /* the core's big receive buffers come from chip_alloc (bench/wa_probe_amiga.c) */
#include "../../crypto/ref/x25519_ref.c"
#include "../../crypto/ref/sha512.c"
#include "../../crypto/ref/ed25519.c"
#include "../../crypto/ref/sha256.c"
#include "../../crypto/ref/aes.c"
#include "../../crypto/ref/drbg.c"
#include "../../crypto/ref/noise.c"
#include "../../crypto/ref/rsa.c"
#include "../../crypto/ref/x509.c"
#include "../../crypto/ref/tls13.c"
#include "../../crypto/ref/sha1.c"
#include "../../crypto/ref/ws.c"
#include "../../crypto/ref/heartbeat.c"
#include "../../crypto/ref/yield.c"
#include "../../net/bsdsock_io.c"
#include "../../tests/wa_probe_core.c"
#include "../wa_probe_amiga.c"
/* pairing (docs/PROTOCOL.md 11): protocol modules, QR encoder, the client screen for the code */
#include "../../proto/wabinary.c"
#include "../../proto/identity.c"
#include "../../proto/clientpayload.c"
#include "../../proto/pairing.c"
#include "../../proto/creds.c"
#include "../../proto/prekeys.c"
#include "../../proto/inflate.c"
#include "../../proto/nextkeys.c"
#include "../../proto/signal.c"
#include "../../ui/qr.c"
#include "../../ui/screen.c"
/* the chat interface (docs/UI.md "Client-Oberfläche"): after ui/screen.c, as in bench/amiga/gui_demo_unity.c */
#include "../../ui/font8.c"
#include "../../ui/ftext.c"
#include "../../ui/gui.c"

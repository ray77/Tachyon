/*
 * Tachyon - the Noise ClientFinish payload (waWa6.ClientPayload), byte for byte what whatsmeow c2ce5c3
 * store/clientpayload.go produces (checked by tests/clientpayload_test.c against tools/pairvectors):
 *   registration (no JID yet):  passive=false, userAgent, webInfo, connectType WIFI_UNKNOWN, connectReason
 *                               USER_ACTIVATED, devicePairingData{eRegid, eKeytype 05, eIdent, eSkeyId, eSkeyVal,
 *                               eSkeySig, buildHash = MD5(WA version), deviceProps}, pull=false
 *   login (paired):             username = JID user as uint64, passive=true, userAgent, webInfo, connectType,
 *                               connectReason, device, lc=1, pull=true, lidDbMigrated=true
 * The WA web version and its MD5 are constants taken from whatsmeow's store.GetWAVersion (WA_VERSION_*); the
 * device props are whatsmeow's companion DeviceProps with os = WA_DEVICE_OS. Freestanding, 32-bit only.
 */
#ifndef TACHYON_CLIENTPAYLOAD_H
#define TACHYON_CLIENTPAYLOAD_H

#include <stdint.h>
#include "identity.h"

#define WA_VERSION_PRIMARY   2u
#define WA_VERSION_SECONDARY 3000u
#define WA_VERSION_TERTIARY  1054751086u
#define WA_VERSION_STRING    "2.3000.1054751086"
#define WA_DEVICE_OS         "Amiga 500"
/* DeviceProps.platformType and the matching QR client id (whatsmeow getQRClientType): 0 UNKNOWN -> "0" (the whatsmeow
 * default), 1 CHROME -> "1", 2 FIREFOX -> "3", 5 SAFARI -> "6", 6 EDGE -> "2". With UNKNOWN the phone lists the
 * companion as "other device" (seen 2026-11-27); FIREFOX makes it "Firefox (Amiga 500)" like an ordinary web session,
 * which is what the user wants shown. The value is sent at registration only, so a change needs a new pairing. */
#define WA_PLATFORM_TYPE     2u
#if WA_PLATFORM_TYPE == 0
#define WA_PAIR_CLIENT_ID    "0"
#elif WA_PLATFORM_TYPE == 1
#define WA_PAIR_CLIENT_ID    "1"
#elif WA_PLATFORM_TYPE == 2
#define WA_PAIR_CLIENT_ID    "3"
#elif WA_PLATFORM_TYPE == 5
#define WA_PAIR_CLIENT_ID    "6"
#elif WA_PLATFORM_TYPE == 6
#define WA_PAIR_CLIENT_ID    "2"
#else
#error "no QR client id for this WA_PLATFORM_TYPE"
#endif
#define WA_CLIENTPAYLOAD_MAX 512u       /* the registration payload is about 330 bytes */

/* both return the length written, 0 if cap is too small */
uint32_t wa_clientpayload_registration(uint8_t *out, uint32_t cap, const wa_identity *id);
uint32_t wa_clientpayload_login(uint8_t *out, uint32_t cap, const char *jid_user, uint32_t device);

/* decimal string -> 64-bit value in two halves (JID users are phone numbers above 2^32); 1 = all digits */
int wa_parse_u64(const char *s, uint32_t *hi, uint32_t *lo);

#endif

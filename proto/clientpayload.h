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
#define WA_CLIENTPAYLOAD_MAX 512u       /* the registration payload is about 330 bytes */

/* both return the length written, 0 if cap is too small */
uint32_t wa_clientpayload_registration(uint8_t *out, uint32_t cap, const wa_identity *id);
uint32_t wa_clientpayload_login(uint8_t *out, uint32_t cap, const char *jid_user, uint32_t device);

/* decimal string -> 64-bit value in two halves (JID users are phone numbers above 2^32); 1 = all digits */
int wa_parse_u64(const char *s, uint32_t *hi, uint32_t *lo);

#endif

/*
 * Tachyon - stored credentials: everything needed to log in again without pairing, one flat record (big endian,
 * fixed offsets, version byte first, SHA-256 over the rest at the end). Host: build/tachyon.creds; Amiga:
 * SYS:tachyon.creds (later ENVARC:). A record whose checksum, version or size is wrong is rejected as a whole.
 * The identity's public keys are stored with the private ones; wa_identity_check() recomputes them when the caller
 * wants that extra check (3 comb multiplications + 1 XEdDSA verify, ~20 s on the 68000). Freestanding.
 */
#ifndef TACHYON_CREDS_H
#define TACHYON_CREDS_H

#include <stdint.h>
#include "identity.h"
#include "pairing.h"

#define WA_CREDS_VERSION 1u
#define WA_CREDS_SIZE 810u
#define WA_JID_USER_MAX 24u
#define WA_CREDS_NAME_MAX 32u
#define WA_CREDS_BIZ_MAX 64u

typedef struct wa_creds {
    wa_identity id;
    int paired;                                   /* JID and ADV identity present: log in instead of pairing */
    char jid_user[WA_JID_USER_MAX]; uint32_t jid_device;        /* ours, e.g. 4917612345678 : 7 @s.whatsapp.net */
    char lid_user[WA_JID_USER_MAX]; uint32_t lid_device;        /* hidden-user JID (@lid), may be empty */
    char platform[WA_CREDS_NAME_MAX];             /* the phone's platform name from pair-success */
    char business[WA_CREDS_BIZ_MAX];              /* business name, usually empty */
    wa_adv_identity adv;                          /* ADVSignedDeviceIdentity incl. account key and our device signature */
    uint8_t noise_cache_fp[32]; int noise_cache_valid;          /* fingerprint of WhatsApp's verified intermediate Noise cert */
} wa_creds;

uint32_t wa_creds_write(uint8_t *out, uint32_t cap, const wa_creds *c);   /* WA_CREDS_SIZE, or 0 if cap is too small */
int      wa_creds_read(wa_creds *c, const uint8_t *in, uint32_t len);     /* 1 = version, size and checksum ok */

/* copy a JID user slice (no NUL) into a creds field; 1 if it fits and is all digits */
int wa_creds_set_user(char *dst, const uint8_t *user, uint32_t len);

#endif

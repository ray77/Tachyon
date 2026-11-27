/*
 * Tachyon - one-time prekeys (Signal/X3DH) for the companion device. whatsmeow uploads 50 at a time (812 right after
 * pairing) when the server reports fewer than 5 (prekeys.go); each is an X25519 key pair with a 24-bit id counted
 * from 1. On the 68000 a key pair costs 3.3 s (fixed-base comb), so the A500 computes a small batch before the
 * connection (like the identity) and uploads it after <success>:
 *   <iq xmlns=encrypt type=set to=s.whatsapp.net><registration>regid BE32</registration><type>05</type>
 *       <identity>identityPub</identity><list><key><id>id BE24</id><value>pub</value></key>...</list>
 *       <skey><id>spkId BE24</id><value>spkPub</value><signature>spkSig</signature></skey></iq>
 * The private keys are needed later to complete sessions that others start with them, so the batch is persisted
 * (version byte, counts, keys, SHA-256) next to the credentials. Freestanding; docs/PROTOCOL.md 11.
 */
#ifndef TACHYON_PREKEYS_H
#define TACHYON_PREKEYS_H
#include <stdint.h>
#include "drbg.h"
#include "wabinary.h"
#include "identity.h"

#define WA_PREKEYS_MAX 64
#define WA_PREKEY_REC  69                                   /* id 4, priv 32, pub 32, uploaded 1 */
#define WA_PREKEYS_SIZE(n) (1u + 4u + 4u + (n) * WA_PREKEY_REC + 32u)
#define WA_PREKEYS_MAX_SIZE WA_PREKEYS_SIZE(WA_PREKEYS_MAX)
#define WA_PREKEYS_MIN_SERVER 5                             /* whatsmeow MinPreKeyCount */

typedef struct wa_prekey { uint32_t id; uint8_t priv[32], pub[32]; uint8_t uploaded; } wa_prekey;
typedef struct wa_prekeys { uint32_t n, next_id; wa_prekey k[WA_PREKEYS_MAX]; } wa_prekeys;

void     wa_prekeys_init(wa_prekeys *ps);                                       /* empty, next id 1 */
uint32_t wa_prekeys_generate(wa_prekeys *ps, uint32_t count, hmac_drbg *rng);   /* appends up to count; returns how many */
uint32_t wa_prekeys_pending(const wa_prekeys *ps);                              /* not uploaded yet */
void     wa_prekeys_mark_uploaded(wa_prekeys *ps);
uint32_t wa_prekeys_write(uint8_t *out, uint32_t cap, const wa_prekeys *ps);    /* bytes written, 0 = does not fit */
int      wa_prekeys_read(wa_prekeys *ps, const uint8_t *in, uint32_t len);      /* 1 = valid record */

/* node storage for one upload IQ (the nodes point into this struct, into ps and into iq_id) */
typedef struct wa_prekey_upload {
    wab_node iq;
    wab_node iq_children[5];                    /* registration, type, identity, list, skey */
    wab_node key[WA_PREKEYS_MAX];               /* <key> */
    wab_node pair[2 * WA_PREKEYS_MAX];          /* (<id>, <value>) of key j at pair[2j], pair[2j+1] */
    wab_node skey_children[3];                  /* <id>, <value>, <signature> */
    wab_attr iq_attrs[4];
    uint8_t regid[4], typeb[1], ids[WA_PREKEYS_MAX][3], skid[3];
} wa_prekey_upload;

/* the upload IQ with every pending prekey; *n_included receives their number (0 = nothing to upload, node still valid) */
const wab_node *wa_prekeys_upload_node(wa_prekey_upload *u, const char *iq_id, const wa_identity *idn, const wa_prekeys *ps, uint32_t *n_included);

#endif

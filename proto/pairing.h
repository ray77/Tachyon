/*
 * Tachyon - companion pairing, the protocol part without any I/O (whatsmeow c2ce5c3 pair.go, Baileys bb0a87e
 * Utils/validate-connection.ts; docs/PROTOCOL.md section 11):
 *
 *   server -> <iq from=s.whatsapp.net type=set id=I><pair-device><ref>..</ref> x6</pair-device></iq>
 *   client -> <iq to=s.whatsapp.net type=result id=I/>, shows QR codes
 *             "https://wa.me/settings/linked_devices#REF,b64(noisePub),b64(identityPub),b64(advSecret),0"
 *             (the first ref for 60 s, every further one for 20 s; the phone scans one)
 *   server -> <iq ... id=J><pair-success><device-identity>ADVSignedDeviceIdentityHMAC</device-identity>
 *             <device jid=.. lid=../><platform name=../><biz name=../></pair-success></iq>
 *   client    HMAC-SHA256(advSecret, [06 05 if hosted ||] details) == HMAC (constant time), else error 401 hmac-mismatch
 *             ADVSignedDeviceIdentity{details, accountSignatureKey, accountSignature}; ADVDeviceIdentity{rawId, keyIndex..}
 *             XEdDSA verify accountSignature over 06 00 || details || identityPub under accountSignatureKey (06 05 hosted),
 *             else error 401 signature-mismatch
 *             deviceSignature = XEdDSA sign over 06 01 || details || identityPub || accountSignatureKey with identityPriv
 *   client -> <iq to=s.whatsapp.net type=result id=J><pair-device-sign><device-identity key-index=K>
 *             ADVSignedDeviceIdentity{details, accountSignature, deviceSignature} (account key cleared)</device-identity>..
 *   server -> <stream:error code=515/>, closes; the client reconnects with the login ClientPayload.
 *
 * Everything here is pure: bounded parsing, constant-time HMAC compare, the signature primitives of crypto/ref.
 * tests/pairing_test.c runs it against a synthetic pair-success IQ from tools/pairvectors.
 */
#ifndef TACHYON_PAIRING_H
#define TACHYON_PAIRING_H

#include <stdint.h>
#include "identity.h"
#include "wabinary.h"

#define WA_ADV_DETAILS_MAX 128u
#define WA_ADV_E2EE 0u
#define WA_ADV_HOSTED 1u
#define WA_PAIR_QR_MAX 400u             /* the QR text: 38 + ref (~100) + 3 x 44 + 5 separators + 1 */
#define WA_SERVER_JID "s.whatsapp.net"

typedef struct wa_adv_identity {
    uint8_t details[WA_ADV_DETAILS_MAX]; uint32_t details_len;   /* ADVDeviceIdentity as the account signed it */
    uint8_t account_sig_key[32], account_sig[64], device_sig[64];
    uint32_t key_index, raw_id;
    uint8_t account_type, device_type;                            /* ADVEncryptionType of the HMAC container / details */
    uint8_t signed_by_us;                                         /* device_sig valid */
} wa_adv_identity;

enum { WA_PAIR_OK = 0, WA_PAIR_ERR_PARSE, WA_PAIR_ERR_HMAC, WA_PAIR_ERR_SIG, WA_PAIR_ERR_SIZE };
const char *wa_pair_errstr(int err);

/* <device-identity> content -> adv (details, keys, account signature verified). 1 XEdDSA verification. */
int wa_pair_verify(const uint8_t *container, uint32_t len, const wa_identity *id, wa_adv_identity *adv);
/* device signature over 06 01 || details || identityPub || accountSignatureKey. 1 XEdDSA signature (2 comb multiplications). */
void wa_pair_sign(wa_adv_identity *adv, const wa_identity *id, const uint8_t random[64]);
/* the same, verified under our own identity key (self-test after signing; another ~11 s on the 68000, host tests only) */
int  wa_pair_check_device_sig(const wa_adv_identity *adv, const wa_identity *id);
/* ADVSignedDeviceIdentity for pair-device-sign: details(1), accountSignature(3), deviceSignature(4); length or 0 */
uint32_t wa_pair_self_signed(uint8_t *out, uint32_t cap, const wa_adv_identity *adv);

/* the QR text for one ref; length or 0 if cap is too small */
uint32_t wa_pair_qr_text(char *out, uint32_t cap, const uint8_t *ref, uint32_t ref_len, const wa_identity *id);

/* ---- nodes ----------------------------------------------------------------------------------- */
typedef struct wa_pair_success {
    wab_str id;                                   /* the IQ id to answer */
    const uint8_t *device_identity; uint32_t device_identity_len;
    wab_jid jid, lid; int have_jid, have_lid;
    wab_str platform, biz;                        /* may be empty */
} wa_pair_success;
int wa_pair_parse_success(const wab_node *iq, wa_pair_success *ps);   /* 1 = usable */

/* the refs of a pair-device IQ: pointers into the decoded tree; returns the count (<= max) */
uint32_t wa_pair_refs(const wab_node *iq, wab_str *refs, uint32_t max);

/* storage for one reply node (the id is copied, the identity bytes are referenced) */
typedef struct wa_pair_reply {
    wab_node iq, child, devid, err;
    wab_attr iq_attrs[3], devid_attrs[1], err_attrs[2];
    char id[64], key_index[12], code[8];
} wa_pair_reply;
const wab_node *wa_pair_ack_node(wa_pair_reply *r, const wab_str *id);
const wab_node *wa_pair_sign_node(wa_pair_reply *r, const wab_str *id, uint32_t key_index, const uint8_t *self_signed, uint32_t len);
const wab_node *wa_pair_error_node(wa_pair_reply *r, const wab_str *id, uint32_t code, const char *text);

#endif

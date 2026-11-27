/* ClientPayload writer (see clientpayload.h). Field numbers from whatsmeow proto/waWa6 and proto/waCompanionReg. */
#include "clientpayload.h"
#include "pb.h"

/* MD5("2.3000.1054751086"), whatsmeow store.waVersionHash; recomputed by tools/pairvectors, no MD5 code on the target */
static const uint8_t wa_build_hash[16] = { 0xb1, 0xb0, 0x8c, 0x67, 0x3d, 0xa5, 0x04, 0xec, 0x5d, 0x6a, 0xc8, 0x8b, 0x65, 0xe8, 0x8a, 0xc6 };

int wa_parse_u64(const char *s, uint32_t *hi, uint32_t *lo)
{
    uint16_t limb[4] = { 0, 0, 0, 0 };
    if (!*s) return 0;
    for (; *s; s++) {
        uint32_t carry, i;
        if (*s < '0' || *s > '9') return 0;
        carry = (uint32_t)(*s - '0');
        for (i = 0; i < 4; i++) { uint32_t t = (uint32_t)limb[i] * 10u + carry; limb[i] = (uint16_t)t; carry = t >> 16; }
        if (carry) return 0;                          /* above 2^64 */
    }
    *lo = (uint32_t)limb[0] | ((uint32_t)limb[1] << 16);
    *hi = (uint32_t)limb[2] | ((uint32_t)limb[3] << 16);
    return 1;
}

/* ClientPayload.UserAgent (5): whatsmeow store.BaseClientPayload.UserAgent */
static void user_agent(pb_writer *w)
{
    uint8_t av[16]; pb_writer a;
    pb_w_init(&a, av, sizeof av);
    pb_w_uint(&a, 1, WA_VERSION_PRIMARY); pb_w_uint(&a, 2, WA_VERSION_SECONDARY); pb_w_uint(&a, 3, WA_VERSION_TERTIARY);
    pb_w_uint(w, 1, 14);                              /* platform WEB */
    pb_w_bytes(w, 2, av, a.len);                      /* appVersion */
    pb_w_str(w, 3, "000");                            /* mcc */
    pb_w_str(w, 4, "000");                            /* mnc */
    pb_w_str(w, 5, "0.1");                            /* osVersion */
    pb_w_str(w, 6, "");                               /* manufacturer (present, empty) */
    pb_w_str(w, 7, "Desktop");                        /* device */
    pb_w_str(w, 8, "0.1");                            /* osBuildNumber */
    pb_w_uint(w, 10, 0);                              /* releaseChannel RELEASE */
    pb_w_str(w, 11, "en");                            /* localeLanguageIso6391 */
    pb_w_str(w, 12, "US");                            /* localeCountryIso31661Alpha2 */
}

/* waCompanionReg.DeviceProps: whatsmeow store.DeviceProps with Os replaced */
static uint32_t device_props(uint8_t *out, uint32_t cap)
{
    uint8_t ver[8], hs[64]; pb_writer v, h, w;
    pb_w_init(&v, ver, sizeof ver);
    pb_w_uint(&v, 1, 0); pb_w_uint(&v, 2, 1); pb_w_uint(&v, 3, 0);      /* version 0.1.0 */
    pb_w_init(&h, hs, sizeof hs);                                         /* HistorySyncConfig */
    pb_w_uint(&h, 3, 10240);                          /* storageQuotaMb */
    pb_w_bool(&h, 4, 1);                              /* inlineInitialPayloadInE2EeMsg */
    pb_w_bool(&h, 6, 1);                              /* supportCallLogHistory */
    pb_w_bool(&h, 7, 1);                              /* supportBotUserAgentChatHistory */
    pb_w_bool(&h, 8, 1);                              /* supportCagReactionsAndPolls */
    pb_w_bool(&h, 9, 1);                              /* supportBizHostedMsg */
    pb_w_bool(&h, 10, 1);                             /* supportRecentSyncChunkMessageCountTuning */
    pb_w_bool(&h, 11, 1);                             /* supportHostedGroupMsg */
    pb_w_bool(&h, 12, 1);                             /* supportFbidBotChatHistory */
    pb_w_bool(&h, 14, 1);                             /* supportMessageAssociation */
    pb_w_bool(&h, 15, 1);                             /* supportGroupHistory */
    pb_w_uint(&h, 19, 60);                            /* thumbnailSyncDaysLimit */
    pb_w_bool(&h, 21, 1);                             /* supportManusHistory */
    pb_w_bool(&h, 22, 1);                             /* supportHatchHistory */
    pb_w_init(&w, out, cap);
    pb_w_str(&w, 1, WA_DEVICE_OS);                    /* os */
    pb_w_bytes(&w, 2, ver, v.len);                    /* version */
    pb_w_uint(&w, 3, 0);                              /* platformType UNKNOWN */
    pb_w_bool(&w, 4, 0);                              /* requireFullSync */
    pb_w_bytes(&w, 5, hs, h.len);                     /* historySyncConfig */
    return w.ok && v.ok && h.ok ? w.len : 0;
}

/* the fields both payloads share, in field order: userAgent(5), webInfo(6), connectType(12), connectReason(13) */
static void common_fields(pb_writer *w)
{
    uint8_t ua[96], wi[4]; pb_writer u, i;
    pb_w_init(&u, ua, sizeof ua); user_agent(&u);
    pb_w_init(&i, wi, sizeof wi); pb_w_uint(&i, 4, 0);                     /* webInfo.webSubPlatform WEB_BROWSER */
    pb_w_bytes(w, 5, ua, u.len);
    pb_w_bytes(w, 6, wi, i.len);
    pb_w_uint(w, 12, 1);                              /* connectType WIFI_UNKNOWN */
    pb_w_uint(w, 13, 1);                              /* connectReason USER_ACTIVATED */
    if (!u.ok || !i.ok) w->ok = 0;
}

uint32_t wa_clientpayload_registration(uint8_t *out, uint32_t cap, const wa_identity *id)
{
    static uint8_t props[160], pair[320];
    uint8_t regid[4], keytype[1] = { 0x05 }, skid[3]; uint32_t pl; pb_writer p, w;
    pl = device_props(props, sizeof props);
    if (!pl) return 0;
    regid[0] = (uint8_t)(id->reg_id >> 24); regid[1] = (uint8_t)(id->reg_id >> 16); regid[2] = (uint8_t)(id->reg_id >> 8); regid[3] = (uint8_t)id->reg_id;
    skid[0] = (uint8_t)(id->spk_id >> 16); skid[1] = (uint8_t)(id->spk_id >> 8); skid[2] = (uint8_t)id->spk_id;
    pb_w_init(&p, pair, sizeof pair);                 /* DevicePairingRegistrationData */
    pb_w_bytes(&p, 1, regid, 4);
    pb_w_bytes(&p, 2, keytype, 1);
    pb_w_bytes(&p, 3, id->ident_pub, 32);
    pb_w_bytes(&p, 4, skid, 3);
    pb_w_bytes(&p, 5, id->spk_pub, 32);
    pb_w_bytes(&p, 6, id->spk_sig, 64);
    pb_w_bytes(&p, 7, wa_build_hash, 16);
    pb_w_bytes(&p, 8, props, pl);
    pb_w_init(&w, out, cap);
    pb_w_bool(&w, 3, 0);                              /* passive */
    common_fields(&w);
    pb_w_bytes(&w, 19, pair, p.len);                  /* devicePairingData */
    pb_w_bool(&w, 33, 0);                             /* pull */
    return w.ok && p.ok ? w.len : 0;
}

uint32_t wa_clientpayload_login(uint8_t *out, uint32_t cap, const char *jid_user, uint32_t device)
{
    uint32_t hi, lo; pb_writer w;
    if (!wa_parse_u64(jid_user, &hi, &lo)) return 0;
    pb_w_init(&w, out, cap);
    pb_w_tag(&w, 1, PB_VARINT); pb_w_varint64(&w, hi, lo);   /* username */
    pb_w_bool(&w, 3, 1);                              /* passive */
    common_fields(&w);
    pb_w_uint(&w, 18, device);                        /* device */
    pb_w_uint(&w, 24, 1);                             /* lc */
    pb_w_bool(&w, 33, 1);                             /* pull */
    pb_w_bool(&w, 41, 1);                             /* lidDbMigrated */
    return w.ok ? w.len : 0;
}

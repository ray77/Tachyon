# Protokollrecherche: Was der Verbindungsaufbau wirklich kostet

Stand 2026-11-27 (TLS-Pfad korrigiert und TLS-1.3-Client live bestätigt, Abschnitt 7 und 9). Quellen: whatsmeow `c2ce5c3` (2026-11-26), Baileys `bb0a87e` (2026-11-13), libsignal-protocol-go v0.2.3, eigene TLS-Proben gegen `web.whatsapp.com:443` mit OpenSSL. Alle Angaben verifiziert am Code, nicht aus Erinnerung.

## 1. Transport: TLS zu `wss://web.whatsapp.com/ws/chat`

| Verhandelt | TLS 1.3 (Standardangebot) | TLS 1.2 (Standardangebot) | TLS 1.2 ohne ECDHE |
|---|---|---|---|
| Schlüsselaustausch | X25519 (P-256 nur, wenn X25519 nicht angeboten wird) | ECDHE P-256 (X25519 wird in TLS 1.2 **nicht** angenommen) | ~~RSA-2048-Schlüsseltransport~~ **wird gewählt, aber nie vollendet** (Abschnitt 7) |
| Cipher | AES-128-GCM wählbar (Server bevorzugt ChaCha20, nimmt aber GCM) | ECDHE-ECDSA-AES128-GCM-SHA256 | AES128-GCM-SHA256 |
| Serverzertifikat | ECDSA P-256 (`*.whatsapp.net`), signiert RSA-2048 (DigiCert G2 TLS RSA CA1), Wurzel DigiCert Global Root G2 (RSA) | gleich | RSA-2048-Zertifikat |
| Session-Resumption | **ja**, TLS-1.3-Tickets, Wiederaufnahme bestätigt (`Reused`) | – | – |

Asymmetrische Arbeit pro vollem TLS-1.3-Handshake auf dem Client: 1 × X25519 (Schlüsselpaar + Shared Secret = 2 Skalarmultiplikationen, das Schlüsselpaar ist vorberechenbar) + 1 × ECDSA-P-256-Verifikation (CertificateVerify) + 1 × RSA-2048-Verifikation (Blattzertifikat; Zwischenzertifikat lässt sich pinnen). Mit Resumption (PSK, ohne `psk_dhe`) entfällt alles bis auf symmetrische Kryptografie – ob der Server PSK ohne DHE akzeptiert, ist noch zu prüfen.

~~Option ohne Elliptische Kurven: TLS 1.2 mit RSA-Schlüsseltransport.~~ **Entfällt (2026-11-27, Abschnitt 7):** der Server wählt die Suite, kann den ClientKeyExchange aber nicht entschlüsseln – jeder Client (OpenSSL, LibreSSL, Go, unser `tls12.c`) bekommt `decrypt_error` auf sein Finished. Der A500-Pfad ist damit **TLS 1.3 mit X25519, TLS_AES_128_GCM_SHA256 und `rsa_pss_rsae_sha256`** (Server legt dann das RSA-2048-Zertifikat vor, bestätigt mit `openssl s_client -tls1_3 -groups X25519 -sigalgs rsa_pss_rsae_sha256`): 2 X25519 (Schlüsselpaar vorberechenbar, also 1 online), 1 RSA-PSS-Verifikation (CertificateVerify), RSA-Kettenprüfung wie bisher, HKDF-SHA256 statt PRF. Kein P-256 nötig.

Zeitlimits: **gemessen am 2026-11-27 (Abschnitt 8): 60,0 s** zwischen dem Server-Flight und unserem ClientKeyExchange/Finished (TLS 1.2 RSA). Der A500-Handshake (21 s, mit Zertifikatscache ≈ 2 s) passt.

## 2. Noise-Handshake `Noise_XX_25519_AESGCM_SHA256`

Ablauf laut `whatsmeow/handshake.go` (identisch in Baileys `noise-handler.ts`):

```text
Client → Server   ClientHello { ephemeral e }                        (e vorberechenbar)
Server → Client   ServerHello { re, enc(rs), enc(cert chain) }
Client:           DH(e, re)                                          1 × X25519
                  AES-GCM decrypt rs
                  DH(e, rs)                                          1 × X25519
                  AES-GCM decrypt cert
                  XEdDSA-Verify(WA-Root-Key, intermediate)           ≈ 2–3 × X25519-Äquivalent
                  XEdDSA-Verify(intermediate-Key, leaf)              ≈ 2–3 × X25519-Äquivalent
                  AES-GCM encrypt s
                  DH(s, re)                                          1 × X25519
                  AES-GCM encrypt ClientPayload
Client → Server   ClientFinish { enc(s), enc(payload) }
```

- 3 DH-Operationen und 2 Signaturprüfungen liegen zwingend zwischen Empfang von ServerHello und Senden von ClientFinish. Die Reihenfolge (erst Zertifikat prüfen, dann eigenen Static-Key senden) ist Teil des Sicherheitsmodells und wird nicht verändert.
- `ecc.VerifySignature` (libsignal `SignCurve25519.go`) wandelt den Montgomery-Schlüssel nach Edwards (eine Feldinversion) und führt eine Ed25519-Verifikation aus: eine Doppel-Skalarmultiplikation `[s]B − [h]A`. Mit vorberechneter Basispunkttabelle ≈ 1,5–2 X25519-Äquivalente, ohne ≈ 2,5–3.
- Das Zwischenzertifikat ist durch den fest einkompilierten WA-Root-Key signiert und ändert sich selten → nach erster erfolgreicher Prüfung pinnen (Bytes + Gültigkeit), spart eine Verifikation pro Verbindung.
- Clientseitiges Timeout in whatsmeow: 20 s auf die ServerHello (irrelevant für uns, da unsere Rechenzeit danach anfällt). **Serverseitig (gemessen 2026-11-27, Abschnitt 8): 10,0 s Leerlauf schließen die Verbindung – aber unaufgeforderte WebSocket-Pong-Frames setzen den Timer zurück, der Handshake selbst hat keine Frist (120 s geprüft).**

Rechnung mit heutigen 8,6 s/X25519: 3 × 8,6 + 2 Verifikationen à ≈ 17–25 s ≈ **60–75 s** online. Mit gepinntem Zwischenzertifikat ≈ 45–50 s. Das ist der kritische Pfad des Projekts.

## 3. Danach: Keepalive, Pairing, Prekeys

| Mechanismus | Wert (whatsmeow / Baileys) | Bedeutung für den A500 |
|---|---|---|
| Keepalive-Ping | alle 20–30 s, Antwort erwartet binnen 10 s (clientseitig) | Lange Krypto-Operationen dürfen den Ping-Verkehr nicht blockieren → Ping/Pong im Interrupt oder zwischen Feldoperationen bedienen |
| Query-Timeout | 60 s (Baileys), 75 s (whatsmeow) | Obergrenze, wie lange der Server auf Antworten wartet, ist nicht dokumentiert |
| QR-Code-Gültigkeit | 60 s erster Code, dann 20 s | Pairing: nach Scan muss der Client `pair-device-sign` beantworten: 1 × XEdDSA-Verify (Account-Signatur) + 1 × XEdDSA-Sign ≈ 25–35 s heute. Grenzwertig |
| Prekeys | `WantedPreKeyCount` 50, Nachladen unter 5; **Erstupload 812** (whatsmeow und Baileys) | 812 Schlüsselpaare = 812 Basispunkt-Multiplikationen. Mit Ladder 8,6 s → fast 2 h. Nur mit Festbasis-Vorberechnung (Edwards, Comb-Tabelle) tragbar, oder der Server akzeptiert weniger (zu prüfen, ob 812 Pflicht ist) |

## 4. Signal-Sitzungen im laufenden Betrieb

- Neue Sitzung (X3DH, `session/Session.go`): 1 Schlüsselpaar + 3–4 DH + 1 Ratchet-Schlüsselpaar ≈ 5–6 Skalarmultiplikationen ≈ 45–50 s vor der ersten Nachricht an einen neuen Kontakt. Einmalig pro Kontakt/Gerät.
- Double Ratchet (`SessionCipher.go`): bei jedem Richtungswechsel ein neues Ratchet-Schlüsselpaar + 1 DH beim Senden, 1 DH beim Empfangen → **≈ 17 s vor dem ersten Senden nach einer empfangenen Nachricht, ≈ 9 s beim Empfang einer Nachricht mit neuem Ratchet-Schlüssel.** Folgenachrichten in derselben Richtung sind rein symmetrisch.
- Gruppen: Sender Keys (symmetrisch), Verteilung über paarweise Sitzungen.
- Multi-Device: Nachrichten gehen an alle Geräte eines Kontakts → eine Sitzung pro Gerät.

## 5. Vollständiger Primitiv-Bedarf (aus den Imports von whatsmeow)

| Primitive | Verwendung | Priorität |
|---|---|---|
| X25519 | Noise (3 DH), X3DH, Double Ratchet, Prekeys | kritisch |
| XEdDSA / Ed25519-Verifikation | Noise-Zertifikate, Prekey-Signaturen, Pairing (ADV) | kritisch |
| XEdDSA-Sign | Pairing, Signed-Prekey | nötig, selten |
| AES-128/256-GCM | Noise-Transport (jede Nachricht), Pairing | kritisch, Durchsatz |
| AES-256-CBC + HMAC-SHA256 | Signal-Nachrichten, Medien, App-State | kritisch |
| SHA-256, HMAC-SHA256, HKDF-SHA256 | überall (20 Importstellen) | kritisch |
| SHA-512 / HMAC-SHA512 | App-State-Hashing (`appstate/hash.go`), LT-Hash | nötig |
| PBKDF2 | Pairing per Code (optional) | niedrig |
| MD5 | Medien-Upload-Metadaten | niedrig |
| RSA-2048 Verify (PKCS#1 v1.5 für die Kette, PSS für CertificateVerify) | nur TLS 1.3 mit `rsa_pss_rsae_sha256` | nötig; ECDSA P-256 entfällt |
| ChaCha20-Poly1305 | nicht nötig (Server akzeptiert AES-GCM) | – |

## 6. Konsequenzen

1. **Der Noise-Handshake ist 5–8 X25519-Äquivalente, nicht 2–3.** Die Signaturprüfung ist genauso wichtig wie DH. Nächster Krypto-Baustein: Ed25519-Verifikation auf derselben Feldarithmetik (Edwards-Punktaddition, Doppel-Skalarmultiplikation, Festbasis-Tabelle für B).
2. **Serverseitige Timeouts sind die offene Kernfrage.** Vorschlag: whatsmeow lokal mit einstellbarer Verzögerung vor ClientFinish betreiben und die Grenze messen (10/30/60/120 s). Das ist ein Test mit einem echten Konto gegen die Produktionsserver – nur mit ausdrücklichem Einverständnis.
3. **Alles Vorberechenbare vorberechnen:** Noise-Ephemeral, TLS-Ephemeral, Ratchet-Schlüsselpaare, Prekeys im Leerlauf; Zwischenzertifikat pinnen; TLS-Resumption nutzen.
4. **Antwortfähigkeit:** Krypto in Scheiben rechnen (eine Feldoperation ≈ 2–4 ms), dazwischen Netzwerk-Pings und GUI bedienen.
5. Latenz im Betrieb (9–17 s pro Richtungswechsel) ist für Version 1.0 hinnehmbar, aber dem Nutzer anzuzeigen.

## 6. Noise-Dialekt von WhatsApp – bitgenau (2026-11-26, whatsmeow c2ce5c3 `socket/noisehandshake.go`, `handshake.go`)

Implementiert in `crypto/ref/noise.c`, geprüft gegen 24 Handshakes, die whatsmeows eigener `NoiseHandshake`-Code erzeugt hat (`tools/genvectors -mode noise`; der Server ist ein aus derselben Quelle geschriebener Spiegel, der auch die Client-Seite nachrechnet und mit whatsmeow übereinstimmen muss).

* Start: `h = "Noise_XX_25519_AESGCM_SHA256" + 4×NUL` (32 Byte, nicht gehasht), `ck = h`, `k = AES-256-GCM(h)`; MixHash(Header `"WA" 0x06 DictVersion`). Der Header geht zusätzlich einmal im Klartext vor dem ersten Frame über die Leitung.
* MixHash(Client-Ephemeral), ClientHello{ephemeral}. MixHash(Server-Ephemeral), **ee**, Decrypt(static), **es**, Decrypt(payload = Zertifikatskette), Encrypt(Client-Static = Noise-Key), **se**, Encrypt(ClientPayload-Protobuf), Finish.
* MixKey(dh): `write, read = HKDF-SHA256(salt = ck, ikm = dh, info = leer)`, `ck = write`, `k = AES-256-GCM(read)`, Zähler = 0. (Kein Noise-„temp_k“-Schema mit 3 Ausgaben – WhatsApp-eigene Variante.)
* Encrypt/Decrypt: IV = 8 Nullbyte ‖ BE32-Zähler, AD = h; danach MixHash(Chiffrat). Jeder MixKey setzt den Zähler zurück.
* Finish: `write, read = HKDF(salt = ck, ikm = leer)`; der Client schreibt mit `write`, der Server dreht die Rollen. Transport: AES-256-GCM, IV-Zähler je Richtung, **kein AD**, Frame = 3-Byte-BE-Länge + Chiffrat.
* **Transport ist WebSocket** (`wss://web.whatsapp.com/ws/chat`, Binärnachrichten) – für den A500 heißt das TLS + HTTP-Upgrade + WebSocket-Framing (Masking der Client-Frames, 4-Byte-XOR) vor der Noise-Schicht. Der WebSocket-Teil ist billig; TLS bleibt der teure Teil (siehe Abschnitt 1).
* Kosten auf dem A500 (gemessen, Harness): 3 × X25519 + 6 × GCM-Schlüsselaufbau (je ≈ 100 ms, davon Tabellen) + HKDF ≈ 25 s **ohne** die beiden XEdDSA-Prüfungen der Zertifikatskette (2 × 9,7 s). Gesamt ≈ 45 s zwischen ServerHello und ClientFinish; der Server erlaubt das, solange alle ≤ 8 s ein WebSocket-Pong rausgeht (Abschnitt 8).

## 7. TLS-Pfad ohne elliptische Kurven – ~~bestätigt (2026-11-26)~~ **widerlegt (2026-11-27)**

**Korrektur 2026-11-27.** Die Bestätigung unten stützte sich auf `Cipher is AES128-GCM-SHA256` in der s_client-Ausgabe – diese Zeile erscheint auch, wenn der Handshake danach scheitert. Beim ersten Lauf unseres eigenen Stacks gegen den Server (`tests/wa_probe.c`) kam auf unser Finished `Alert fatal decrypt_error (51)`. Daraufhin systematisch geprüft (57.144.245.32, `*.whatsapp.net`-Edge, 2026-11-27 09:00 UTC+1):

| Client | Suite | Ergebnis |
|---|---|---|
| OpenSSL 3.0.16 `s_client -tls1_2 -cipher AES128-GCM-SHA256` | TLS_RSA_WITH_AES_128_GCM_SHA256 | ServerHello, Kette, unser CKE/Finished → **decrypt_error** |
| LibreSSL 3.3.6 (curl `--ciphers AES128-GCM-SHA256`) | dito | **decrypt_error** |
| Go crypto/tls (Suite erzwungen) | dito | Verbindung zurückgesetzt |
| unser `tls12.c` (mit und ohne Extended Master Secret) | dito | **decrypt_error**, 6 Versuche |
| OpenSSL, `-cipher kRSA` (jede RSA-Transport-Suite) | AES128-GCM-SHA256 | **decrypt_error** |
| OpenSSL gegen `www.facebook.com`, gleiche Suite | TLS_RSA_WITH_AES_128_GCM_SHA256 | **vollendet** |
| OpenSSL `-tls1_2 -cipher ECDHE -curves X25519:P-256` | ECDHE-ECDSA, **P-256** | vollendet, X25519 wird in TLS 1.2 nicht gewählt |
| OpenSSL `-tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -curves P-256` | ECDHE-RSA P-256, RSA-2048-Zertifikat | vollendet |
| OpenSSL `-tls1_3 -groups X25519 -ciphersuites TLS_AES_128_GCM_SHA256 -sigalgs rsa_pss_rsae_sha256` | TLS 1.3, X25519, **RSA-2048-Zertifikat** | **vollendet** |
| OpenSSL `-tls1_3 -groups X25519`, Standard-Sigalgs | TLS 1.3, X25519, ECDSA-P-256-Zertifikat | vollendet |

Lesart: Die Edge für `*.whatsapp.net` bietet RSA-Schlüsseltransport an, besitzt aber offenbar keinen Entschlüsselungszugriff auf den privaten RSA-Schlüssel (nur Signieren, wie für ECDHE-RSA und TLS 1.3 nötig); OpenSSL antwortet in diesem Fall mit zufälligem Premaster und das Finished scheitert als `decrypt_error`. Facebooks Edge kann es, WhatsApps nicht. Unser `tls12.c` verhält sich byteidentisch zu OpenSSL (gegen lokalen OpenSSL-`s_server` mit 3-Zertifikat-Kette und 1-Byte-Lesefragmenten bestanden, RSA-Chiffrat gegen Python `pow()` unter dem Live-Schlüssel geprüft) – der Fehler liegt nicht bei uns.

**Neuer TLS-Plan für den A500: TLS 1.3, `TLS_AES_128_GCM_SHA256`, Gruppe X25519, `signature_algorithms` = `rsa_pss_rsae_sha256` (+ `rsa_pkcs1_sha256` für die Kette).** Kosten online: 1 X25519 (Shared Secret; das Schlüsselpaar wird vorberechnet), 1 RSA-PSS-Verifikation (neu: MGF1-SHA256, Saltlänge 32 – ~1 RSA-Public-Op), RSA-Kette wie bisher, HKDF-SHA256 statt PRF, Record-Layer ohne expliziten Nonce (IV ⊕ Sequenznummer, innerer Content-Type). Das sind ≈ 8,6 s X25519 + RSA-Prüfungen (≈ 2 s mit gepinntem Zwischenzertifikat), weniger als die 21 s des RSA-Transport-Handshakes auf dem 68000. Wiederverwendbar aus `tls12.c`: Record-Layer-Gerüst, X.509, RSA, DRBG, Transkript-Hashing; `tls12.c` bleibt für den Go-Loopback-Test, die FS-UAE-Messung und als Vorlage. Das 60-s-Zeitlimit (Abschnitt 8) wurde für den TLS-1.2-Flight gemessen; für TLS 1.3 ist es neu zu messen, bevor der A500-Handshake darauf baut.

*Ursprünglicher Text (2026-11-26, nur noch historisch):*


`openssl s_client -tls1_2 -cipher AES128-GCM-SHA256` gegen web.whatsapp.com: der Server wählt **TLS_RSA_WITH_AES_128_GCM_SHA256** und präsentiert eine **reine RSA-2048/SHA-256-Kette**: Leaf `CN=*.whatsapp.net` (SAN u. a. `*.whatsapp.com`, `whatsapp.com`, gültig 2026-09-05 bis 2026-12-04, also ≈ 90-Tage-Rotation) ← DigiCert Global G2 TLS RSA SHA256 2020 CA1 ← DigiCert Global Root G2 (hier kreuzsigniert von High Assurance EV Root, für uns der Vertrauensanker per gepinntem G2-Schlüssel). Session-Tickets werden ausgegeben.

Konsequenz: Der A500 braucht für TLS **kein P-256 und kein X25519**: 1 × RSA-Verschlüsselung (Premaster) + 2 × RSA-Verifikation (Leaf, Zwischenzertifikat; das Zwischenzertifikat lässt sich pinnen → 1 ×) + PRF/HMAC-SHA256 + AES-128-GCM. Keine Forward Secrecy auf TLS-Ebene; der Inhalt ist zusätzlich Noise- und Signal-verschlüsselt, das TLS schützt hier vor allem die Metadaten des WebSocket-Transports. Implementiert: `crypto/ref/rsa.c`, `crypto/ref/x509.c` (minimaler DER-Parser: RSA-SPKI, tbs-Bereich, Signatur, SAN mit einstufigem Wildcard, Gültigkeit, basicConstraints; alle anderen Felder werden längenbasiert übersprungen, jede Lesung ist grenzgeprüft), Host-Test gegen die drei echten Zertifikate (`tests/certs/`).

Offen: **Uhrzeit**. Ein A500 ohne RTC startet 1978; Gültigkeitsprüfung braucht eine vertrauenswürdige Zeit. Optionen: Nutzer setzt die Uhr (Workbench), Zeit aus dem WhatsApp-Protokoll nach dem Noise-Handshake (authentifiziert, aber erst nach dem TLS-Aufbau → nachträglich prüfen und bei Verstoß trennen), oder Gültigkeit nur als „nicht älter als das Build-Datum“ prüfen. `x509_verify_chain(now = 0)` lässt die Zeitprüfung aus und ist als solche dokumentiert.

### TLS-1.2-Client implementiert (2026-11-26)

`crypto/ref/tls12.c`: genau eine Suite, `TLS_RSA_WITH_AES_128_GCM_SHA256`; ClientHello mit SNI, signature_algorithms (rsa_pkcs1_sha256) und leerem renegotiation_info; Zertifikatskette → `x509_verify_chain` gegen gepinnten Wurzelschlüssel **vor** jeder Schlüsselableitung; Premaster per PKCS#1 v1.5 mit DRBG-Padding; PRF P_SHA256; Record-Layer AES-128-GCM mit explizitem Nonce = Sequenznummer. Keine Session-Tickets, kein Extended Master Secret (nicht angeboten), kein Renegotiation. Geprüft gegen Go `crypto/tls` als Server (`make tls-test`: Handshake, Echo über die 16-KiB-Record-Grenze, gefälschter Record wird abgewiesen). Die aufgezeichnete Session (`tests/vectors/tls_session.bin`, deterministischer DRBG-Seed) wird im Harness auf dem 68000 wiederabgespielt und erreicht CONNECTED; Zeit siehe docs/BENCHMARKS.md.

### TLS-1.3-Client implementiert und gegen den Server bestätigt (2026-11-27)

`crypto/ref/tls13.c` / `tls13.h`, gleiche I/O-agnostische Form wie `tls12` (`tls13_client_start`, `tls13_input`, `tls13_send` → `t->out`, Klartext in `t->app`, Zustände bis `TLS13_ST_CONNECTED`, `tls13_errstr`). Genau ein Profil, das der `*.whatsapp.net`-Edge vollendet:

| Parameter | Wert (Bytes) |
|---|---|
| ClientHello | `legacy_version` 0x0303, 32 Byte Random (DRBG), leere `legacy_session_id`, Suites `{0x1301}` (TLS_AES_128_GCM_SHA256), Kompression null |
| Erweiterungen | `server_name` (0) = Host; `supported_groups` (10) = `{0x001d}` x25519; `signature_algorithms` (13) = `{0x0804 rsa_pss_rsae_sha256, 0x0401 rsa_pkcs1_sha256}`; `supported_versions` (43) = `{0x0304}`; `key_share` (51) = `{0x001d, 32 Byte X25519-Öffentlich}` |
| ServerHello | Version 0x0303, Random ≠ HRR-Kennwert `SHA256("HelloRetryRequest")` (sonst sauberer Fehler), Session-ID leer, Suite 0x1301, `supported_versions` = 0x0304, `key_share` x25519/32 Byte; jede andere Erweiterung ist ein Fehler |
| Schlüsselplan | HKDF-SHA256 (RFC 8446 7.1): `early = Extract(0, 0³²)`, `hs = Extract(Derive(early,"derived"), X25519-Shared)`, `c/s hs traffic` über Transkript(CH‥SH), `master = Extract(Derive(hs,"derived"), 0³²)`, `c/s ap traffic` über Transkript(CH‥Server-Finished); `key` 16 Byte, `iv` 12 Byte, `finished` 32 Byte per Expand-Label (`"tls13 "`-Präfix) |
| Record-Layer | äußerer Typ 23, Version 0x0303, Nonce = IV ⊕ 64-Bit-Sequenznummer (rechtsbündig), AAD = 5-Byte-Header, Inhalt ‖ innerer Typ, Nullpadding abgestreift; max. 2¹⁴ + 256 Byte Chiffretext; `change_cipher_spec` im Klartext wird verworfen, geschützt ist er ein Fehler; Alert → Fehler (`t->alert` hält die Beschreibung) |
| Server-Flight | EncryptedExtensions (Struktur geprüft), Certificate (Kontext leer, Einträge mit Erweiterungen; bis 4 DER-Zertifikate → `x509_parse`, `x509_verify_chain` gegen gepinnten Wurzelschlüssel + Host **bevor** irgendetwas anderes gilt), CertificateVerify (nur 0x0804; RSA-PSS über 64 × 0x20 ‖ `"TLS 1.3, server CertificateVerify"` ‖ 0x00 ‖ Transkript-Hash), Finished (HMAC, konstante Zeit) |
| Client-Flight | Finished unter `c hs traffic`, danach Anwendungsschlüssel; kein CCS, kein Zertifikat |
| Nicht unterstützt | PSK/Tickets (NewSessionTicket wird ignoriert), HelloRetryRequest, 0-RTT, CertificateRequest, KeyUpdate – jeweils definierter Fehler |

Neu dafür in `rsa.c`: `rsa_verify_pss_sha256` (EMSA-PSS-VERIFY, MGF1-SHA256, Saltlänge 32, jedes EM-Byte geprüft, kein früher Abbruch), Vektoren aus Go `rsa.SignPSS` (`tests/vectors/rsa_pss.txt`, 24 Schlüssel, 6 verfälscht), gegengeprüft mit Python `cryptography`. Das X25519-Schlüsselpaar kommt aus `tls13_keypair_generate` (DRBG + `x25519_base_comb`) und kann vor der Verbindung berechnet werden (`tls13_client_start_kp`); online bleibt eine X25519-Skalarmultiplikation (`x25519_ref`, mit `CRYPTO_YIELD()`), ein Nullergebnis wird abgewiesen.

Hosttest `make tls13-test` (Teil von `make host-test`): Go `crypto/tls` als Server (`tools/tls13server`, MinVersion 1.3, nur X25519, RSA-2048; Go wählt daraus 0x1301 und signiert mit `rsa_pss_rsae_sha256`): Handshake, Echo, 20 KiB über die 16-KiB-Record-Grenze, verfälschter Record abgewiesen, Kette unter falschem gepinntem Schlüssel abgewiesen – nach dem ClientHello wird nichts mehr gesendet, keine Client-Schlüssel entstehen –, Handshake mit 1-Byte-Lesefragmenten.

**Live (`make wa-probe GAP=30`, eigener Stack von TCP aufwärts):** TLS 1.3 zu `web.whatsapp.com` in 60 ms verbunden, 2 Zertifikate gegen den gepinnten G2-Schlüssel geprüft (der Server sandte in diesem Lauf kein Wurzelzertifikat mit), RSA-PSS-CertificateVerify und Finished geprüft; darüber WebSocket, Noise XX, 30 s Rechenpause mit 7 Pongs durch unseren Record-Layer, ClientFinish angenommen, erstes verschlüsseltes Server-Frame (695 Byte → 679 Byte `pair-device`-IQ) entschlüsselt: **`RESULT: handshake ACCEPTED by web.whatsapp.com with our TLS 1.3/WS/Noise stack`**. Der openssl-Tunnel (`make wa-probe-tunnel`) bleibt als Referenz.

**Zertifikatscache (2026-11-27 abends, `x509_cache` in `x509.h`):** ein Eintrag ist SHA-256 über gepinnten Wurzelschlüssel, Hostnamen und das DER des Blattzertifikats (jedes Feld längenpräfixiert), 36 Byte, auf dem A500 in `ENVARC:` ablegbar. Hängt ein Cache am Client (`tls13_set_cert_cache`), wird bei Treffer `x509_verify_chain` übersprungen – genau dieses Blatt wurde unter genau diesem Wurzelschlüssel für genau diesen Host schon einmal vollständig geprüft. Jede Verbindung prüft weiterhin: Gültigkeitszeitraum gegen die Uhr, Hostname gegen die SAN, und die RSA-PSS-Signatur im CertificateVerify, die den Besitz des Blattschlüssels beweist – ohne sie wäre ein gespeichertes Zertifikat nur ein öffentliches Dokument. Nach jeder vollständigen Prüfung wird das Blatt neu gespeichert (Rotation ≈ 90 Tage, dann ein voller Handshake). Vergleich in konstanter Zeit. Hosttest: leerer Cache → volle Prüfung + Speichern; Treffer auf der nächsten Verbindung; anderer Hostname → Fehltreffer, volle Prüfung; abgelaufenes Blatt trotz Treffer abgewiesen, nichts gesendet. Live (`TLS_CACHE=1 ./build/wa_probe`): erste Verbindung prüft die Kette und speichert, die zweite trifft (`cache HIT`), Handshake angenommen. Ersparnis auf dem 68000: die zwei RSA-Prüfungen der Live-Kette (19,5 s), siehe BENCHMARKS.md Schritt 15.

A500: `tls13.c` ist Teil des Unity-Builds (`make amiga`), die aufgezeichnete Loopback-Session (`tests/vectors/tls13_session.bin` → `bench/tls13_vector.h`, deterministischer DRBG-Seed) wird im Harness wiederabgespielt; Zeiten in docs/BENCHMARKS.md Schritt 14.

## 8. Serverseitige Zeitlimits – gemessen (2026-11-27, `tools/watimeout`)

Werkzeug: `go run ./tools/watimeout` führt den echten Handshake gegen `wss://web.whatsapp.com/ws/chat` (TLS mit Go, Noise mit whatsmeows `socket`-Paket, frischer Registrierungs-Payload wie beim ersten Pairing, kein Pairing abgeschlossen) und hält dabei eine Client-Nachricht künstlich zurück, während es mitliest, wann der Server schließt. `-tls-delay` hält die zweite TLS-Flight (ClientKeyExchange/Finished), `-noise-delay` den ClientFinish nach dem ServerHello, `-hello-delay` den ClientHello nach dem WebSocket-Upgrade, `-ping D -pingop 9|10` sendet währenddessen alle D Sekunden ein WebSocket-Ping- bzw. Pong-Frame. Ergebnis gilt als angenommen, wenn nach dem ClientFinish die erste verschlüsselte Server-Frame kommt (das `pair-device`-IQ, 0,2–0,3 s).

| Lücke | Verhalten des Servers (14 Verbindungen, 57.144.245.32) |
|---|---|
| TLS: Server-Flight → unsere zweite Flight (TLS 1.2, `TLS_RSA_WITH_AES_128_GCM_SHA256`) | Verbindung geschlossen nach **60,0 s** Stille (EOF, kein Alert) |
| TLS 1.3: Server-Flight → unser Finished (eigener Client `tls13.c`, X25519, RSA-PSS-Zertifikat; `TLS_HOLD=70 ./build/wa_probe`, nachgemessen 2026-11-27 abends, 3 Verbindungen) | geschlossen nach **60,0 s** Stille, davor ein verschlüsselter Alert `close_notify` (24-Byte-Record unter dem Server-Anwendungsschlüssel); Hold 50 s → **angenommen**, voller Handshake danach normal |
| dito mit Go (`watimeout -tls-delay 90s -tls13x25519 -addr …`, ECDSA-Zertifikat, da Go die Signaturalgorithmen nicht einschränkt) | geschlossen **60,1 s nach dem TCP-Connect** mit demselben Alert, obwohl Go sein Finished erst nach 30 bzw. 58 s hätte senden können (Go blieb in der Sandbox an der Zertifikatsprüfung hängen – Systemprüfer ohne Netz) → der Timer läuft ab dem Verbindungsbeginn/ClientHello, nicht erst ab unserer Untätigkeit |
| WebSocket offen → ClientHello | geschlossen nach **10,0 s** |
| ServerHello → ClientFinish, keine weiteren Frames | 8,0 s und 9,5 s **angenommen**, 12 s: geschlossen nach **10,0 s** (zweimal) |
| dito, WebSocket-**Ping** (Opcode 9) alle 2 s | Verbindung bleibt offen, aber der Handshake wird **nicht** mehr angenommen – auch nicht bei 8 s. Der Server antwortet auf den Ping mit einem Datenframe, der WA-Rahmenzustand ist danach kaputt. Ping ist tabu. |
| dito, unaufgefordertes WebSocket-**Pong** (Opcode 10, leer, maskiert) alle 2 s | 8 s, 12 s, **60 s, 120 s angenommen** |
| dito, Pong alle 8 s | 30 s angenommen |

Lesart: Es gibt kein Handshake-Zeitlimit, nur einen **Leerlauf-Timer von 10 s auf der WebSocket-Verbindung**, den jedes Frame zurücksetzt. Für TLS gilt unabhängig von der Version ein **60-s-Fenster vom Verbindungsbeginn bis zum Client-Finished**; der A500 hat dafür nach Schritt 14 ≈ 37 s (Live-Kette ohne Cache), 27 s mit gepinntem Zwischenzertifikat. Ein leeres Pong-Frame (RFC 6455 erlaubt unaufgeforderte Pongs als Herzschlag) ist für die WA-Schicht unsichtbar: 6 Byte auf der Leitung, als TLS-Record ≈ 35 Byte, kostet den A500 eine AES-GCM-Verschlüsselung von 6 Byte (≈ 3 ms). Der TLS-Timer (60 s) braucht keinen Herzschlag.

Konsequenz für den A500: Die ≈ 45 s zwischen ServerHello und ClientFinish (3 × X25519, 2 × XEdDSA-Verify, mit gepinntem Zwischenzertifikat ≈ 35 s) sind **zulässig**, wenn die Feldarithmetik alle ≤ 8 s (sicherheitshalber alle 4 s) ein Pong-Frame absetzt – entweder aus einer CIA-Timer-Unterbrechung heraus (der TLS-Record-Schreibpfad muss dann unterbrechungsfest sein: eigener Sequenznummernzähler, kein gleichzeitiger Schreibzugriff des Hauptprogramms) oder kooperativ zwischen Feldoperationen (`fe16_mul` dauert 3,7 ms, eine X25519-Leiter prüft also z. B. alle 256 Multiplikationen die Zeit). Gleiches gilt für Pairing (`pair-device-sign`, ≈ 14 s) und die Signal-Sitzungen (X3DH ≈ 45–50 s): während jeder langen Rechnung läuft der Pong-Herzschlag, dazu nach dem Handshake die Protokoll-Keepalives (Abschnitt 3).

Offen: Frist des Servers für `pair-device-sign` nach dem QR-Scan (braucht einen echten Scan, nicht automatisierbar), Verhalten der Mobil-Endpunkte (`g.whatsapp.net`, nicht unser Pfad), Verhalten über längere Zeit (die 120-s-Messung ist eine Stichprobe).

## 9. Herzschlag im Krypto-Code – umgesetzt und gegen den Server bestätigt (2026-11-27)

Entwurf: **kooperativ, keine Interrupts.** `crypto/ref/yield.h` definiert `CRYPTO_YIELD()`: ein Funktionszeiger `crypto_yield_hook(ctx)`, ohne Hook ein einzelner Branch. Aufrufstellen: X25519-Leiter (je Bit, ≈ 34 ms auf dem 68000), `fe16_sqr_n`/`ed_sqr_n` (alle 16 Quadrierungen in der Inversion), Ed25519 `ge_scalarmult`, `ge_double_scalarmult` (je Schleifendurchlauf) und `ge_scalarmult_base_ct` (je Fenster), RSA-Exponentenschleife (je Bit). Eine X25519-Operation ruft den Hook 268-mal, die Comb-Schlüsselerzeugung 77-mal, eine XEdDSA-Prüfung ≈ 290-mal (`tests/heartbeat_test.c`) – also alle 20–50 ms eine Gelegenheit.

`crypto/ref/heartbeat.c`: `heartbeat_tick` ist der Hook. Wenn seit dem letzten Pong `interval_ms` vergangen sind (Uhr per Callback, auf dem A500 DateStamp-Ticks), baut `ws_frame_pong` (neu in `ws.c`: Opcode 10, leer, maskiert, 6 Byte) ein Frame, das über einen Sende-Callback des Aufrufers geht (der es durch `tls13_send`/`tls12_send` als Record verschlüsselt und samt zuvor gepufferter Ausgabe abschickt, damit keine Records gemischt werden; der Herzschlag selbst kennt keinen TLS-Typ). Der Hook läuft nur zwischen Feldoperationen, nie innerhalb von `tls13_send` oder AES-GCM, der TLS-Schreibpfad bleibt deshalb unverändert und nicht re-entrant. Ohne offenen WebSocket oder ohne verbundenes TLS sendet er nichts; ein Sendefehler wird gemerkt (`error`) und beendet den Herzschlag. Ein künftiger Netzwerkstack (bsdsocket) kann unverändert benutzt werden, weil nichts im Interrupt läuft. Wiederverwendbar für GUI-Bedienung: derselbe Hook kann Intuition-Nachrichten abholen.

Hosttest (`make heartbeat-test`): gegen `tools/wsserver` (zählt Pongs per `OnPongReceived`), gefälschte Uhr, zehn X25519-Leitern zu je „5 s“ bei 8-s-Intervall → genau 5 Pongs gesendet und 5 empfangen, Ergebnisse unverändert, kein Pong bei geschlossenem Socket oder ohne Hook.

**Ende-zu-Ende gegen `web.whatsapp.com` (`make wa-probe-tunnel GAP=30`, `tests/wa_probe.c`):** unser WebSocket-Client, unser Noise-XX (`noise.c`), Zertifikatskette aus dem ServerHello per XEdDSA gegen den einkompilierten WA-Root-Key geprüft (Zwischenzertifikat Serial 3, Blatt Serial 366, Blattschlüssel = Server-Static), 30 s Wartezeit mit echten X25519-Leitern (53 466 Stück auf dem Host) und Herzschlag alle 4 s → **7 Pongs, ClientFinish 30,0 s nach ServerHello angenommen**, erstes verschlüsseltes Server-Frame (694 Byte) mit den Transportschlüsseln entschlüsselt (678 Byte Binary-Node, das `pair-device`-IQ). Transport in diesem Lauf: `openssl s_client` mit den TLS-1.3-Parametern des A500-Plans, weil `tls13.c` da noch nicht existierte; seit dem Abend desselben Tages läuft `make wa-probe` mit unserem eigenen TLS 1.3 und wird ebenso angenommen (Abschnitt 7). Der Registrierungs-Payload (`tests/vectors/wa_client_payload.h`, aus `tools/watimeout -dump-payload`) ist eine Wegwerfidentität; kein Pairing wird abgeschlossen.

Nebenbefund: `x509_verify_chain` akzeptiert jetzt Ketten, an deren Ende der Server sein kreuzsigniertes Wurzelzertifikat anhängt (der Vertrauensanker gilt per Schlüssel, das angehängte Zertifikat wird übersprungen, nicht geprüft) – die Live-Kette hat drei Zertifikate, der Hosttest bisher zwei. `tls12.c` bietet jetzt Extended Master Secret (RFC 7627) an und benutzt es, wenn der Server es bestätigt (Go- und OpenSSL-Loopback: ja).

# Protokollrecherche: Was der Verbindungsaufbau wirklich kostet

Stand 2026-11-26. Quellen: whatsmeow `c2ce5c3` (2026-11-26), Baileys `bb0a87e` (2026-11-13), libsignal-protocol-go v0.2.3, eigene TLS-Proben gegen `web.whatsapp.com:443` mit OpenSSL. Alle Angaben verifiziert am Code, nicht aus Erinnerung.

## 1. Transport: TLS zu `wss://web.whatsapp.com/ws/chat`

| Verhandelt | TLS 1.3 (Standardangebot) | TLS 1.2 (Standardangebot) | TLS 1.2 ohne ECDHE |
|---|---|---|---|
| Schlüsselaustausch | X25519 (P-256 nur, wenn X25519 nicht angeboten wird) | ECDHE P-256 | **RSA-2048-Schlüsseltransport** |
| Cipher | AES-128-GCM wählbar (Server bevorzugt ChaCha20, nimmt aber GCM) | ECDHE-ECDSA-AES128-GCM-SHA256 | AES128-GCM-SHA256 |
| Serverzertifikat | ECDSA P-256 (`*.whatsapp.net`), signiert RSA-2048 (DigiCert G2 TLS RSA CA1), Wurzel DigiCert Global Root G2 (RSA) | gleich | RSA-2048-Zertifikat |
| Session-Resumption | **ja**, TLS-1.3-Tickets, Wiederaufnahme bestätigt (`Reused`) | – | – |

Asymmetrische Arbeit pro vollem TLS-1.3-Handshake auf dem Client: 1 × X25519 (Schlüsselpaar + Shared Secret = 2 Skalarmultiplikationen, das Schlüsselpaar ist vorberechenbar) + 1 × ECDSA-P-256-Verifikation (CertificateVerify) + 1 × RSA-2048-Verifikation (Blattzertifikat; Zwischenzertifikat lässt sich pinnen). Mit Resumption (PSK, ohne `psk_dhe`) entfällt alles bis auf symmetrische Kryptografie – ob der Server PSK ohne DHE akzeptiert, ist noch zu prüfen.

Option ohne Elliptische Kurven: TLS 1.2 mit RSA-Schlüsseltransport (nur RSA-Verschlüsselung mit e = 65537 und RSA-Signaturprüfungen, beides billig). Keine Forward Secrecy auf TLS-Ebene; die eigentliche Nutzlast ist ohnehin Noise-verschlüsselt. Als Rückfalloption dokumentiert, nicht als Standard.

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
| ECDSA P-256 + RSA-2048 Verify | nur TLS | nötig (oder TLS 1.2 RSA-Pfad) |
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

## 7. TLS-Pfad ohne elliptische Kurven – bestätigt (2026-11-26)

`openssl s_client -tls1_2 -cipher AES128-GCM-SHA256` gegen web.whatsapp.com: der Server wählt **TLS_RSA_WITH_AES_128_GCM_SHA256** und präsentiert eine **reine RSA-2048/SHA-256-Kette**: Leaf `CN=*.whatsapp.net` (SAN u. a. `*.whatsapp.com`, `whatsapp.com`, gültig 2026-09-05 bis 2026-12-04, also ≈ 90-Tage-Rotation) ← DigiCert Global G2 TLS RSA SHA256 2020 CA1 ← DigiCert Global Root G2 (hier kreuzsigniert von High Assurance EV Root, für uns der Vertrauensanker per gepinntem G2-Schlüssel). Session-Tickets werden ausgegeben.

Konsequenz: Der A500 braucht für TLS **kein P-256 und kein X25519**: 1 × RSA-Verschlüsselung (Premaster) + 2 × RSA-Verifikation (Leaf, Zwischenzertifikat; das Zwischenzertifikat lässt sich pinnen → 1 ×) + PRF/HMAC-SHA256 + AES-128-GCM. Keine Forward Secrecy auf TLS-Ebene; der Inhalt ist zusätzlich Noise- und Signal-verschlüsselt, das TLS schützt hier vor allem die Metadaten des WebSocket-Transports. Implementiert: `crypto/ref/rsa.c`, `crypto/ref/x509.c` (minimaler DER-Parser: RSA-SPKI, tbs-Bereich, Signatur, SAN mit einstufigem Wildcard, Gültigkeit, basicConstraints; alle anderen Felder werden längenbasiert übersprungen, jede Lesung ist grenzgeprüft), Host-Test gegen die drei echten Zertifikate (`tests/certs/`).

Offen: **Uhrzeit**. Ein A500 ohne RTC startet 1978; Gültigkeitsprüfung braucht eine vertrauenswürdige Zeit. Optionen: Nutzer setzt die Uhr (Workbench), Zeit aus dem WhatsApp-Protokoll nach dem Noise-Handshake (authentifiziert, aber erst nach dem TLS-Aufbau → nachträglich prüfen und bei Verstoß trennen), oder Gültigkeit nur als „nicht älter als das Build-Datum“ prüfen. `x509_verify_chain(now = 0)` lässt die Zeitprüfung aus und ist als solche dokumentiert.

### TLS-1.2-Client implementiert (2026-11-26)

`crypto/ref/tls12.c`: genau eine Suite, `TLS_RSA_WITH_AES_128_GCM_SHA256`; ClientHello mit SNI, signature_algorithms (rsa_pkcs1_sha256) und leerem renegotiation_info; Zertifikatskette → `x509_verify_chain` gegen gepinnten Wurzelschlüssel **vor** jeder Schlüsselableitung; Premaster per PKCS#1 v1.5 mit DRBG-Padding; PRF P_SHA256; Record-Layer AES-128-GCM mit explizitem Nonce = Sequenznummer. Keine Session-Tickets, kein Extended Master Secret (nicht angeboten), kein Renegotiation. Geprüft gegen Go `crypto/tls` als Server (`make tls-test`: Handshake, Echo über die 16-KiB-Record-Grenze, gefälschter Record wird abgewiesen). Die aufgezeichnete Session (`tests/vectors/tls_session.bin`, deterministischer DRBG-Seed) wird im Harness auf dem 68000 wiederabgespielt und erreicht CONNECTED; Zeit siehe docs/BENCHMARKS.md.

## 8. Serverseitige Zeitlimits – gemessen (2026-11-27, `tools/watimeout`)

Werkzeug: `go run ./tools/watimeout` führt den echten Handshake gegen `wss://web.whatsapp.com/ws/chat` (TLS mit Go, Noise mit whatsmeows `socket`-Paket, frischer Registrierungs-Payload wie beim ersten Pairing, kein Pairing abgeschlossen) und hält dabei eine Client-Nachricht künstlich zurück, während es mitliest, wann der Server schließt. `-tls-delay` hält die zweite TLS-Flight (ClientKeyExchange/Finished), `-noise-delay` den ClientFinish nach dem ServerHello, `-hello-delay` den ClientHello nach dem WebSocket-Upgrade, `-ping D -pingop 9|10` sendet währenddessen alle D Sekunden ein WebSocket-Ping- bzw. Pong-Frame. Ergebnis gilt als angenommen, wenn nach dem ClientFinish die erste verschlüsselte Server-Frame kommt (das `pair-device`-IQ, 0,2–0,3 s).

| Lücke | Verhalten des Servers (14 Verbindungen, 57.144.245.32) |
|---|---|
| TLS: Server-Flight → unsere zweite Flight (TLS 1.2, `TLS_RSA_WITH_AES_128_GCM_SHA256`) | Verbindung geschlossen nach **60,0 s** Stille (EOF, kein Alert) |
| WebSocket offen → ClientHello | geschlossen nach **10,0 s** |
| ServerHello → ClientFinish, keine weiteren Frames | 8,0 s und 9,5 s **angenommen**, 12 s: geschlossen nach **10,0 s** (zweimal) |
| dito, WebSocket-**Ping** (Opcode 9) alle 2 s | Verbindung bleibt offen, aber der Handshake wird **nicht** mehr angenommen – auch nicht bei 8 s. Der Server antwortet auf den Ping mit einem Datenframe, der WA-Rahmenzustand ist danach kaputt. Ping ist tabu. |
| dito, unaufgefordertes WebSocket-**Pong** (Opcode 10, leer, maskiert) alle 2 s | 8 s, 12 s, **60 s, 120 s angenommen** |
| dito, Pong alle 8 s | 30 s angenommen |

Lesart: Es gibt kein Handshake-Zeitlimit, nur einen **Leerlauf-Timer von 10 s auf der WebSocket-Verbindung**, den jedes Frame zurücksetzt. Ein leeres Pong-Frame (RFC 6455 erlaubt unaufgeforderte Pongs als Herzschlag) ist für die WA-Schicht unsichtbar: 6 Byte auf der Leitung, als TLS-Record ≈ 35 Byte, kostet den A500 eine AES-GCM-Verschlüsselung von 6 Byte (≈ 3 ms). Der TLS-Timer (60 s) braucht keinen Herzschlag.

Konsequenz für den A500: Die ≈ 45 s zwischen ServerHello und ClientFinish (3 × X25519, 2 × XEdDSA-Verify, mit gepinntem Zwischenzertifikat ≈ 35 s) sind **zulässig**, wenn die Feldarithmetik alle ≤ 8 s (sicherheitshalber alle 4 s) ein Pong-Frame absetzt – entweder aus einer CIA-Timer-Unterbrechung heraus (der TLS-Record-Schreibpfad muss dann unterbrechungsfest sein: eigener Sequenznummernzähler, kein gleichzeitiger Schreibzugriff des Hauptprogramms) oder kooperativ zwischen Feldoperationen (`fe16_mul` dauert 3,7 ms, eine X25519-Leiter prüft also z. B. alle 256 Multiplikationen die Zeit). Gleiches gilt für Pairing (`pair-device-sign`, ≈ 14 s) und die Signal-Sitzungen (X3DH ≈ 45–50 s): während jeder langen Rechnung läuft der Pong-Herzschlag, dazu nach dem Handshake die Protokoll-Keepalives (Abschnitt 3).

Offen: Frist des Servers für `pair-device-sign` nach dem QR-Scan (braucht einen echten Scan, nicht automatisierbar), Verhalten der Mobil-Endpunkte (`g.whatsapp.net`, nicht unser Pfad), Verhalten über längere Zeit (die 120-s-Messung ist eine Stichprobe).

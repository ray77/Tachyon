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

**Zertifikatscache für das Noise-Zwischenzertifikat (2026-11-27, `noise_cert_cache` in `noise.h`):** die Kette im ServerHello ist `CertChain{leaf, intermediate}`, jedes `NoiseCertificate{details, signature}`. Das Zwischenzertifikat ist stabil (Seriennummer 3, `issuerSerial` 0 = WhatsApps Wurzelschlüssel `wa_cert_pub`), seine XEdDSA-Prüfung kostet auf dem 68000 aber 11,1 s – gleich viel wie die des Blatts, das mit dem Serverschlüssel wechselt. Ein Cacheeintrag ist SHA-256 über Wurzelschlüssel ‖ `details` ‖ `signature` (jedes Feld längenpräfixiert, Präfix „Tachyon noise cert cache v1“), 32 Byte, auf dem A500 in `ENVARC:` ablegbar; derselbe Aufbau wie `x509_cache`. Treffer (Vergleich in konstanter Zeit) heißt: genau diese `details` mit genau dieser Signatur wurden unter genau diesem Wurzelschlüssel schon einmal vollständig geprüft – die Prüfung wird übersprungen. Weiterhin bei jeder Verbindung: `issuerSerial` des Zwischenzertifikats = 0, die XEdDSA-Prüfung des Blatts unter dem Schlüssel *aus den gecachten details* und der Vergleich Blattschlüssel == entschlüsselter Server-Static aus dem Noise-Handshake (der Besitzbeweis; ohne ihn wäre die Kette nur ein öffentliches Dokument). Rotiert WhatsApp das Zwischenzertifikat oder den Wurzelschlüssel, ist der Fingerabdruck ein Fehltreffer: volle Prüfung, Eintrag überschrieben. Ein Angreifer, der die Cachedatei schreiben kann, könnte den Hash eines gefälschten Zwischenzertifikats hinterlegen – dieselbe Annahme wie beim TLS-Cache in `ENVARC:` (lokaler Schreibzugriff ist ohnehin das Ende). Hosttest in `tests/noise_test.c`: leerer Cache Fehltreffer, Treffer nach Speichern, geänderte Signatur / `details` / Wurzelschlüssel / Länge je Fehltreffer, Eintrag nach Fehltreffern unverändert. In der Probe: `NOISE_CACHE=<Datei>` (`make wa-probe` → `build/wa_noise_cache.bin`), `tools/run-fsuae-net.sh` reicht die Datei als `SYS:noisecache.bin` an den Amiga und holt sie zurück. Live: erste Verbindung „cache empty, entry stored“, zweite „cache HIT … XEdDSA skipped“, beide angenommen. Zeiten auf dem A500: BENCHMARKS.md Schritt 18.

**Blattzertifikat ebenfalls gecacht, TLS-Cache als Datei, Tickets (2026-11-27 abends, a382da5):** das Blatt (Seriennummer 366 seit allen Läufen des Tages) wechselt zwar mit dem Serverschlüssel, aber nicht je Verbindung; sein Fingerabdruck (SHA-256 über Zwischenschlüssel ‖ `details` ‖ `signature`, gleicher Aufbau) liegt als zweite 32-Byte-Hälfte in `SYS:noisecache.bin` (64 Byte). Treffer überspringt die zweite XEdDSA-Prüfung (11 s); bei jeder Verbindung bleiben `issuerSerial` des Blatts == Seriennummer des Zwischenzertifikats und Blattschlüssel == entschlüsselter Server-Static (der Besitzbeweis). Der TLS-Zertifikatscache (`x509_cache`) ist seitdem als portable Datei schreibbar (`x509_cache_write`/`x509_cache_read`, Version 1, Big-Endian, Fingerabdruck + vorbereiteter `rsa_pub` + SHA-256 über alles, 585 Byte für RSA-2048): der Host (`build/wa_tls_cache.bin`) und der A500 (`SYS:tlscache.bin`) füllen und lesen dieselbe Datei; ein verfälschter Eintrag (Prüfsumme, Version, Kürzung) zählt als leerer Cache. **NewSessionTickets schickt der Server keine** (Zähler `tls: 0 NewSessionTicket(s)` über eine volle Login-Verbindung mit Anwendungsdaten): TLS-PSK-Resumption, die den TLS-DH (`psk_ke`) oder zumindest CertificateVerify gespart hätte, fällt als Hebel weg. Live-Zahlen: Abschnitt 11, BENCHMARKS.md Schritt 21.

**`es` vor der Verbindung (2026-11-27 abends, `noise_es_pre` in `noise.h`):** von den drei X25519-Leitern des Clients im XX-Handshake (`ee`, `es`, `se`) hat nur `es` = DH(e_c, s_s) einen vorab bekannten öffentlichen Eingang – der Server-Static ist der Blattschlüssel, bei jeder Verbindung geprüft und seit allen Läufen derselbe. Er liegt als dritte 32-Byte-Hälfte in `SYS:noisecache.bin` (96 Byte: Zwischen-Fingerabdruck, Blatt-Fingerabdruck, Static); `connection_keys()` rechnet damit `es` zusammen mit den Schlüsselpaaren **vor dem Connect** (eine Leiter, 7,7 s, außerhalb der Server-Uhr; nach dem 515-Neustart noch einmal mit dem neuen Ephemeral, dann mit dem gerade geprüften Static). `noise_client_finish` nimmt den Vorab-Wert nur, wenn der aus dem ServerHello entschlüsselte Static byteweise (konstante Zeit) gleich dem ist, aus dem er gerechnet wurde; sonst läuft die Leiter wie bisher. Der entschlüsselte Static ist durch das `ee`-AEAD authentisiert, und die Blattprüfung „Blattschlüssel == Server-Static“ bleibt – ein falscher gespeicherter Schlüssel kostet nur die Vorausrechnung, nie Sicherheit. Dem Server gegenüber ist nichts anders. Hosttest in `tests/noise_test.c` auf allen 24 whatsmeow-Handshakes: Vorab-Wert genutzt, Chiffrate und Transportschlüssel identisch; gespeicherter Schlüssel um ein Bit anders → Leiter läuft, Ergebnis identisch; kein Eintrag → wie bisher. Online bleiben damit 2 Noise-Leitern + 1 TLS-Leiter.

**Schlüssel für die nächste Verbindung im Leerlauf (2026-11-27 abends, `proto/nextkeys.c`):** was vor jedem Connect noch zu rechnen war – TLS-Schlüsselpaar, Noise-Ephemeral (je ≈ 3,3 s Comb) und `es` (8 s Leiter) – rechnet der Client jetzt **nach** dem Login, solange er ohnehin online ist (`post_login()` nach `<active/>`, Pong-Herzschlag läuft mit), und legt es als 226-Byte-Datensatz ab (`SYS:tachyon.next`, Host `build/tachyon.next`: Version, Flags, beide Schlüsselpaare, Server-Static, `es`, SHA-256). Der nächste Start liest den Datensatz, **löscht ihn, bevor** ein Schlüssel auf die Leitung geht (`consume_nextkeys`; einmalige Verwendung, auch nach einem Absturz wird kein Ephemeral zweimal angeboten; ein verfälschter Datensatz wird ignoriert und gelöscht), und verbindet sofort. Nach dem 515-Neustart eines Pairings werden die Schlüssel der Login-Verbindung wie bisher frisch gerechnet (der Datensatz ist dann schon verbraucht). Private Ephemeral-Schlüssel auf der Platte: derselbe Datenträger hält bereits die Langzeit-Identität (`tachyon.creds`); wer ihn lesen kann, gewinnt durch den Datensatz nichts Neues. `tools/run-fsuae-net.sh` reicht die Datei hin und zurück und löscht die Host-Kopie, wenn der Amiga nach dem Lauf keine (neue) hinterlassen hat. Hosttest `make nextkeys-test` (Schlüsselkonsistenz, Rundreise, jedes verfälschte Bit, Kürzung, fremdes Flag, Wipe).

**Prekeys ebenfalls im Leerlauf (2026-11-27 abends):** `wa_probe_prepare` erzeugt keine Einmal-Prekeys mehr vor der Verbindung (das waren 33 s für 10 Schlüssel beim ersten Lauf und nach jedem Upload). Stattdessen füllt `post_login()` nach den Schlüsseln für den nächsten Start die anstehende Charge wieder auf `prekeys_wanted` auf, online, mit Herzschlag, und speichert den Datensatz; der Start selbst rechnet nichts. Hält der Server weniger als 5 und ist nichts anstehend (erster Login einer Identität, oder der Datensatz fehlt), wird die Charge online vor dem Upload erzeugt. Der Datensatz behält hochgeladene Schlüssel (ihre privaten Hälften werden für Sessions gebraucht, die mit ihnen aufgebaut werden) und fasst 64; ohne Signal-Schicht gibt es noch kein Kriterium zum Ausmisten. Simulator: Upload von 3, danach 3 neue anstehend (Datensatz 6); zweiter Login mit 3 auf dem Server und leerer Charge → 3 online erzeugt, hochgeladen, 3 neue anstehend. Live noch nicht gesehen: beim Stand des Abends (Server 6, Charge 10 anstehend) gäbe es nichts zu erzeugen; der nächste Login mit Server < 5 zeigt den Pfad.

Daneben rechnet die Probe seit demselben Tag die drei X25519-Schlüsselpaare (TLS, Noise-Static, Noise-Ephemeral; Festbasis-Comb, `wa_probe_prepare`) **vor** dem TCP-Connect – auf dem A500 noch während der Stack startet. Damit liegt zwischen ServerHello und ClientFinish nur noch: 3 × X25519 (Montgomery-Leiter, ≈ 8 s je), HKDF/AES-GCM und eine XEdDSA-Prüfung (Blatt).

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

**Zertifikatscache (2026-11-27 abends, `x509_cache` in `x509.h`):** ein Eintrag ist SHA-256 über gepinnten Wurzelschlüssel, Hostnamen und das DER des Blattzertifikats (jedes Feld längenpräfixiert), 36 Byte, auf dem A500 in `ENVARC:` ablegbar. Hängt ein Cache am Client (`tls13_set_cert_cache`), wird bei Treffer `x509_verify_chain` übersprungen – genau dieses Blatt wurde unter genau diesem Wurzelschlüssel für genau diesen Host schon einmal vollständig geprüft. Jede Verbindung prüft weiterhin: Gültigkeitszeitraum gegen die Uhr, Hostname gegen die SAN, und die RSA-PSS-Signatur im CertificateVerify, die den Besitz des Blattschlüssels beweist – ohne sie wäre ein gespeichertes Zertifikat nur ein öffentliches Dokument. Nach jeder vollständigen Prüfung wird das Blatt neu gespeichert (Rotation ≈ 90 Tage, dann ein voller Handshake). Vergleich in konstanter Zeit. Im Eintrag liegt außerdem der vorbereitete Blattschlüssel (`rsa_pub` mit Montgomery-Konstanten, ≈ 1 KiB); auf Treffer prüft `rsa_pub_check` ihn gegen das vorgelegte Blatt (Modulus und Exponent byteweise, n0inv neu berechnet, R² mod n mit einem Montgomery-Produkt – 0,45 s statt 1,9 s für `rsa_pub_set`), ein verfälschter Schlüssel gilt als Fehltreffer und wird nach der vollen Prüfung überschrieben. Hosttest: leerer Cache → volle Prüfung + Speichern; Treffer auf der nächsten Verbindung; verfälschter gespeicherter Schlüssel → Fehltreffer, Kette neu geprüft, Cache neu geschrieben; anderer Hostname → Fehltreffer, volle Prüfung; abgelaufenes Blatt trotz Treffer abgewiesen, nichts gesendet. Live (`TLS_CACHE=1 ./build/wa_probe`): erste Verbindung prüft die Kette und speichert, die zweite trifft (`cache HIT`), Handshake angenommen. Ersparnis auf dem 68000: die zwei RSA-Prüfungen der Live-Kette (19,5 s) und das `rsa_pub_set` des Blatts (1,5 s netto), gemessen in BENCHMARKS.md Schritt 15 (Replay 29,4 s → 18,3 s).

**Pin-Menge, Zwischenzertifikat mitgepinnt (`x509_pin`, `x509_verify_chain_pins`):** bis zu vier Vertrauensanker per Schlüssel; die Kette ist vollständig beim ersten Zertifikat, das ein gepinnter Schlüssel signiert hat (oder das selbst einen gepinnten Schlüssel trägt). Der A500 pinnt den G2-Wurzelschlüssel **und** den Schlüssel von „DigiCert Global G2 TLS RSA SHA256 2020 CA1“ (`tests/certs/wa_rsa_1.pem`, gültig bis 2030): das Live-Blatt ist von CA1 signiert, also **eine** RSA-Prüfung statt zwei; wechselt DigiCert das Zwischenzertifikat, läuft die Prüfung über die Wurzel weiter (zwei Prüfungen, kein Ausfall). `tls13_add_pin` hängt Anker an, `t->cert_pin` sagt, welcher die Kette abgeschlossen hat; der Fingerabdruck des Zertifikatscaches bindet die ganze Pin-Menge (Version 2). Live (`make wa-probe`): `chain completed at pin 1 (CA1 intermediate), 1 RSA verification`. Hosttest: Reihenfolge der Pins egal, Rückfall auf die Wurzel bei fremdem zweitem Pin, Ablehnung ohne passenden Pin. Zeit siehe BENCHMARKS.md Schritt 16.

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

## 10. WABinary – das Knotenformat nach dem Handshake (2026-11-27, `proto/wabinary.c`)

Alles nach dem Noise-Handshake sind „Binary Nodes“: ein XML-artiger Baum (Tag, Attribute, Inhalt) in einem kompakten Binärformat. Referenzen: whatsmeow `ae388b0` (2026-11-27 von GitHub, `binary/`), Baileys `bb0a87e` (`src/WABinary/`). Die Token-Tabellen beider Projekte sind identisch (`DictVersion` 3: 236 Ein-Byte-Token, davon Index 0 leer, 4 × 256 Zwei-Byte-Token, zusammen 1259 Strings, 10 663 Byte). `proto/wabinary_tokens.h` erzeugt `tools/gen_wab_tokens.py` aus beiden Quellen und bricht bei jeder Abweichung ab. Die Go-Referenzvektoren stammen aus der in `go.mod` festgelegten Version `c2ce5c3`; `token.go`, `decoder.go` und `encoder.go` sind in beiden whatsmeow-Ständen bytegleich.

### Format

Ein entschlüsselter Frame ist **1 Flag-Byte + 1 Knoten**. Flag-Bit 1 (Wert 2): der Rest ist zlib-komprimiert. Ein Knoten ist eine Liste aus `1 + 2·Attribute (+ 1 bei Inhalt)` Elementen: Tag, Schlüssel/Wert-Paare, Inhalt (ungerade Länge = ohne Inhalt).

| Byte | Bedeutung |
|---|---|
| `00` | LIST_EMPTY: leere Liste, leerer Wert, JID ohne User |
| `01`–`EB` | Ein-Byte-Token |
| `EC`–`EF` | Zwei-Byte-Token: Wörterbuch 0–3, ein Index-Byte folgt |
| `F5`, `F6` | Interop-JID (User, u16 Gerät, u16 Integrator, Server), FB-JID (User, u16 Gerät, Server) |
| `F7` | AD_JID: Domain-Byte (0 `s.whatsapp.net`, 1 `lid`, 128 `hosted`, 129 `hosted.lid`), Geräte-Byte, User |
| `F8`, `F9` | Liste mit 8-/16-Bit-Länge |
| `FA` | JID_PAIR: User (oder `00`), Server |
| `FB`, `FF` | HEX_8 (`0-9A-F`), NIBBLE_8 (`0-9 - .`): Längenbyte (Bit 7 = ungerade, Bits 0–6 = Bytes), 2 Zeichen je Byte, Füll-Nibble `F` |
| `FC`, `FD`, `FE` | Rohbytes mit 8-, 20-, 32-Bit-Länge (Big Endian) |

### API

```c
wab_arena_init(&arena, mem, size);                       /* Speicher stellt der Aufrufer, kein malloc */
int e = wab_decode_frame(frame, len, &arena, &node);     /* WAB_OK oder Fehlercode, wab_errstr(e) */
const wab_value *id = wab_get_attr(node, "id");          /* id->kind WAB_STR oder WAB_JID */
const wab_node *pd  = wab_get_child(node, "pair-device");
e = wab_encode_frame(node, out, cap, &outlen);           /* bei WAB_ERR_BUFFER ist outlen die nötige Größe */
```

Bauen: `wab_node_init`, `wab_text`, `wab_bytes`, `wab_jid_value`, dazu eigene Arrays für Attribute und Kinder. Freistehendes C, nur 32 Bit, keine Division.

- **Strings sind (Zeiger, Länge) ohne Nullbyte.** Sie zeigen in die Token-Tabelle, in den Eingabepuffer (Rohstrings und Byte-Inhalt, ohne Kopie) oder in die Arena (entpackte Nibble-/Hex-Strings). Puffer und Arena müssen leben, solange der Baum benutzt wird.
- **Grenzen:** jeder Lesezugriff geprüft, Längen und Anzahlen vor dem Reservieren gegen den Rest der Eingabe, Tiefe höchstens `WAB_MAX_DEPTH` = 16 Knoten (Rekursion nur dort, Stapelrahmen auf dem 68000 ≤ 60 Byte lokal), Fehlercode statt Abbruch.
- **Wire-Form bleibt erhalten:** der Server wählt nicht immer die kürzeste Form (im pair-device-IQ steht die rein numerische `id` als HEX_8). Der Decoder merkt sich je String, JID und Liste die Form, jeder angenommene Knoten wird bytegleich zurückcodiert. Selbst gebaute Knoten (Formfelder 0) bekommen die Wahl von whatsmeow: Token, sonst Nibble, sonst Hex (bis 127 Zeichen), sonst Rohbytes; JIDs mit Gerät > 0 an `s.whatsapp.net`/`lid` und alle `hosted`-JIDs als AD_JID, `msgr`/`interop` als FB-/Interop-JID, der Rest als JID_PAIR.
- **Abweichungen von den Vorlagen:** Attribute mit leerem Wert werden geschrieben (whatsmeow lässt sie weg). Strings, die wie JIDs aussehen, werden nicht umgedeutet (Baileys tut das) – JIDs übergibt der Aufrufer als JID. Rohe Inhalte decodieren als `WAB_BYTES`, Token und gepackte als `WAB_STR`. Strenger als die Vorlagen: Füll-Nibble muss `F` sein, `F` mitten im Nibble-String und gesetzte obere 4 Bit bei BINARY_20 sind Fehler.
- **Kompression: nicht unterstützt.** `wab_decode_frame` meldet für Frames mit Flag-Bit 1 `WAB_ERR_COMPRESSED` („compressed: unsupported“). Der aufgezeichnete Frame ist unkomprimiert (Flag `00`), ein Inflate (stored/fixed/dynamic) kommt, sobald ein echter komprimierter Frame vorliegt – vor dem Betrieb nach dem Pairing nötig, da beide Vorlagen ihn behandeln.

### Testergebnisse (`make wabinary-test`, ASan + UBSan)

Testvektor `tests/vectors/pair_device_iq.bin`: erstes entschlüsseltes Frame eines Laufs gegen `web.whatsapp.com` (`make wa-capture GAP=6`; `tests/wa_probe_core.c` unverändert, nur für diesen Build ist sein Transport-Decrypt über `tests/wa_capture.c` geleitet). 679 Byte:

```text
<iq from="s.whatsapp.net" type="set" id="1613398979" xmlns="md">
  <pair-device>
    <ref>2@…102 Byte…</ref>            6 × (QR-Referenzen einer Wegwerf-Registrierung)
  </pair-device>
</iq>
```

41 704 Prüfungen, 0 Fehler: alle 1259 Token; der IQ-Baum wie oben, bytegleich zurückcodiert, jede Kürzung und jeder zu kleine Arena- bzw. Ausgabepuffer ergibt den passenden Fehler; 60 Vektoren aus whatsmeows Encoder (`make wabinary-vectors`, `tools/wabvectors`) – gleicher Baum wie whatsmeows Decoder, und unsere bevorzugte Codierung ist bytegleich mit der von whatsmeow; jede Codierungsart von Hand Byte für Byte; fehlerhafte Eingaben (übergroße Längen und Anzahlen, ungültige Token, Tiefe); 300 000 mutierte Frames, 33 975 angenommen, alle bytegleich zurückcodiert.

Arena für den IQ: 736 Byte auf dem 68000, 1232 Byte auf dem 64-Bit-Host. Auf dem 68000 bisher nur ein Rauchtest unter vamos (nicht eingecheckt: IQ und 60 Vektoren bytegleich, alle Token gefunden); keine Zeitmessung, noch nicht Teil eines Amiga-Programms.

## 11. Pairing als verknüpftes Gerät (2026-11-27, `proto/pairing.c`, `proto/identity.c`, `proto/clientpayload.c`, `proto/creds.c`)

Vorlagen: whatsmeow `c2ce5c3` (`pair.go`, `qrchan.go`, `store/clientpayload.go`, `util/keys/keypair.go`, `connectionevents.go`), Baileys `bb0a87e` (`Utils/validate-connection.ts`, `Utils/companion-reg-client-utils.ts`), libsignal-go `v0.2.3` (`ecc/SignCurve25519.go`). Alles Offline-Prüfbare ist gegen diese Pakete selbst geprüft, nicht gegen eine Lesart davon (`tools/pairvectors`).

### Identität des Begleitgeräts (`proto/identity.c`)

| Teil | Erzeugung | Verwendung |
|---|---|---|
| Noise-Static `noise_priv/pub` | 32 Byte DRBG, geklemmt, Comb | Noise-Handshake; nach dem Pairing kennt der Server uns daran |
| Signal-Identität `ident_priv/pub` | wie oben | XEdDSA-Signaturen (Prekey, `pair-device-sign`), später Signal-Sitzungen |
| Signed Prekey `spk_priv/pub`, `spk_id` = 1 | wie oben; `spk_sig` = XEdDSA über `05 ‖ spk_pub` mit `ident_priv` | Registrierungs-Payload |
| `reg_id` | 16 Bit Zufall (≠ 0) | Registrierungs-Payload (whatsmeow nimmt 32 Bit, libsignal 14 – der Server nimmt alles) |
| `adv_secret` | 32 Byte DRBG | steht im QR-Code; das Telefon MACt damit unsere Geräte-Identität |

Drei Comb-Multiplikationen plus eine XEdDSA-Signatur (zwei weitere Comb-Multiplikationen) ≈ 18 s auf dem 68000, alles vor der Verbindung (`wa_probe_prepare`).

**XEdDSA-Signatur** (`xeddsa_sign`, `crypto/ref/ed25519.c`), bitgenau wie libsignal `ecc.CalculateSignature`: `a` = geklemmter Curve25519-Skalar, `A = [a]B` **ohne** Vorzeichenkorrektur (das Vorzeichenbit von `A` wandert in `sig[63]` Bit 7, der Prüfer baut `A` aus dem Montgomery-`u` und diesem Bit), `r = SHA-512(FE FF…FF ‖ a ‖ msg ‖ 64 Zufallsbytes) mod L`, `R = [r]B`, `h = SHA-512(R ‖ A ‖ msg) mod L`, `S = h·a + r mod L` (`sc_muladd`: Byte-Limbs in 32-Bit-Spalten, konstante Zeit). Die 64 Zufallsbytes sind nur eine Absicherung; jede Belegung ergibt eine gültige Signatur. Test: `tools/genvectors -mode xeddsa-sign` (eigener deterministischer Nachbau von libsignals `sign`, jede Signatur von `ecc.VerifySignature` bestätigt), `tests/ed25519_test.c` vergleicht 64 Signaturen byteweise.

### ClientPayload (`proto/clientpayload.c`)

Bytegleich mit `proto.Marshal(device.GetClientPayload())` von whatsmeow für dieselbe Identität (`make clientpayload-test`: 300 Byte Registrierung, 88 Byte Login). Felder in Nummernreihenfolge:

- **Registrierung:** `passive(3)=false`, `userAgent(5)` {platform WEB=14, appVersion 2.3000.1054751086, mcc/mnc "000", osVersion "0.1", manufacturer "", device "Desktop", osBuildNumber "0.1", releaseChannel RELEASE, en/US}, `webInfo(6)` {webSubPlatform WEB_BROWSER}, `connectType(12)=WIFI_UNKNOWN`, `connectReason(13)=USER_ACTIVATED`, `devicePairingData(19)` {eRegid 4 Byte BE, eKeytype `05`, eIdent, eSkeyId 3 Byte BE, eSkeyVal, eSkeySig, buildHash = MD5("2.3000.1054751086") = `b1b08c67…` (Konstante, kein MD5 auf dem Ziel), deviceProps}, `pull(33)=false`.
- **deviceProps:** whatsmeows `store.DeviceProps` mit `os = "Amiga 500"`, Version 0.1.0, `platformType UNKNOWN` (`WA_PLATFORM_TYPE`, treibt zugleich die Kennung am QR-Ende; Firefox wäre ein Einzeiler, siehe `clientpayload.h`), `requireFullSync=false`, HistorySyncConfig wie whatsmeow.
- **Login:** `username(1)` = JID-Nutzer als uint64 (Varint aus zwei 32-Bit-Hälften, Dezimalzahl mit 16-Bit-Limbs geparst), `passive(3)=true`, dieselben Felder 5/6/12/13, `device(18)`, `lc(24)=1`, `pull(33)=true`, `lidDbMigrated(41)=true`.

### Ablauf

```text
Server  <iq from=s.whatsapp.net type=set id=I xmlns=md><pair-device><ref>…</ref> ×6</pair-device></iq>
Client  <iq to=s.whatsapp.net type=result id=I/>
        QR-Text: https://wa.me/settings/linked_devices#REF,b64(noisePub),b64(identityPub),b64(advSecret),0
        Code 1 60 s, dann je 20 s (whatsmeow qrchan.go; die Rotation ist clientseitig, der Server schickt keine neuen IQs)
        währenddessen alle 4 s ein WebSocket-Pong (Abschnitt 8/9) und alle 25 s <iq xmlns=w:p type=get><ping/></iq>
Phone   scannt → Server  <iq … id=J><pair-success><device-identity>ADVSignedDeviceIdentityHMAC</device-identity>
                           <device jid=… lid=…/><platform name=…/><biz name=…/></pair-success></iq>
Client  HMAC-SHA256(advSecret, details) == hmac (konstante Zeit)            sonst <iq type=error><error code=401 text=hmac-mismatch/>
        ADVSignedDeviceIdentity{details, accountSignatureKey, accountSignature}; ADVDeviceIdentity{rawId, timestamp, keyIndex}
        XEdDSA-Verify accountSignature über 06 00 ‖ details ‖ identityPub       sonst … text=signature-mismatch; Verbindung zu
        deviceSignature = XEdDSA-Sign über 06 01 ‖ details ‖ identityPub ‖ accountSignatureKey  mit identityPriv
        <iq to=s.whatsapp.net type=result id=J><pair-device-sign><device-identity key-index=K>
            ADVSignedDeviceIdentity{details(1), accountSignature(3), deviceSignature(4)}   (accountSignatureKey entfernt)
Server  <stream:error code=515/>, schließt
Client  EINE neue Verbindung: TLS 1.3, WebSocket, Noise XX mit demselben Noise-Static und dem Login-Payload
Server  <success t=… lid=…/>   → fertig
```

HOSTED-Konten (`accountType`/`deviceType` = 1): Präfix `06 05` statt `06 00` im HMAC-Eingang bzw. der Account-Signatur, wie in beiden Vorlagen. Die Geräte-Signatur bleibt `06 01`.

QR-Text: 38 Zeichen Präfix + `ref` (102 Zeichen in den Aufzeichnungen) + 3 × 44 Base64 + 5 Trenner = **277 Zeichen → Version 11 L, 61 × 61 Module**. Auf dem Hires-Schirm 6 × 3 Pixel je Modul (414 × 207 mit Ruhezone), ab Version ≤ 9 8 × 4 (docs/UI.md). Decodiert mit zbar aus dem PBM/PNG des Hosts (`tools/pbm2png.py`).

### Nach `<success>`: Prekeys, `<active/>`, Bestätigungen (`post_login()`)

whatsmeows `handleConnectSuccess` – und seit 8b3e2ad die Probe – macht nach dem Login drei Dinge, bevor der Client Nachrichten verarbeitet:

1. **Prekey-Zählung:** `<iq id xmlns=encrypt type=get to=s.whatsapp.net><count/></iq>` → `<iq type=result><count value="N"/></iq>`.
2. **Prekey-Upload**, wenn `N < 5` (`MinPreKeyCount`; whatsmeow lädt 50 nach, beim ersten Mal 812): `<iq xmlns=encrypt type=set to=s.whatsapp.net><registration>regId BE32</registration><type>05</type><identity>identityPub</identity><list><key><id>id BE24</id><value>pub</value></key>…</list><skey><id>spkId BE24</id><value>spkPub</value><signature>spkSig</signature></skey></iq>` → `<iq type=result/>`. Die Einmal-Prekeys (`proto/prekeys.c`) sind X25519-Paare mit 24-Bit-IDs ab 1; die privaten Hälften werden gebraucht, wenn ein Gegenüber eine Session damit beginnt, deshalb liegen sie als Datensatz (Versionsbyte, Zähler, Schlüssel, SHA-256) neben den Zugangsdaten (`build/tachyon.prekeys`, A500 `SYS:tachyon.prekeys`). Auf dem 68000 kostet jedes Paar 3,3 s, der A500 rechnet deshalb **10 Stück vor dem Connect** (33 s) statt 50 oder 812; der Server nimmt die Liste in jeder Länge.
3. **`<iq xmlns=passive type=set to=s.whatsapp.net><active/></iq>`** → `<iq type=result/>`: erst jetzt schickt der Server Ereignisse.

Danach bleibt die Probe `linger_ms` online (Host 15 s, A500 10 s): `<receipt>` und `<notification>` werden wie `sendAck` bestätigt (`<ack class=tag id to=from [participant] [type]/>`), `<message>` bleibt unbestätigt (noch keine Signal-Session-Schicht; der Server behält sie), `<ib>` wird protokolliert, alle 25 s ein `w:p`-Ping; dann `close`. **Komprimierte Frames** (Flag-Bit 1 im ersten Byte) werden vorher mit `proto/inflate.c` entpackt – ein freistehender zlib-Decoder (stored, fixed, dynamic, Adler-32; `make inflate-test` gegen Go-Vektoren). Nachrichten größer als der 16-KiB-Puffer verwirft die WebSocket-Schicht als Ganzes und meldet es, statt die Verbindung aufzugeben (`ws.c`, `dropped`).

Live (A500, Gerät :9, 2026-11-27 16:30, Login mit gespeicherten Zugangsdaten): Prekeys 10 × in 32,9 s vor dem Connect; `<success>` 76,0 s nach Connect; Zählung → **0**; Upload von 10 Prekeys **angenommen** (1,3 s); `<active/>` angenommen **3,6 s nach `<success>`**; dann drei `<ib>` vom Server und nach 4 s eine Nachricht größer als der 16-KiB-Puffer, an der die erste Fassung die Verbindung beendete („ws error“) – seitdem wird sie verworfen und protokolliert (noch nicht live gesehen). `RESULT: LOGGED IN … server prekeys 0 + 10 uploaded, active, 6 stanzas`. Offline deckt `make pair-sim` den ganzen Ablauf gegen den Pseudo-Server ab, inklusive komprimierter Notification und zweier Acks.

### Zugangsdaten (`proto/creds.c`)

Ein flacher Datensatz von 810 Byte: Versionsbyte 1, Flags (gepaart, Noise-Cache gültig), alle sechs Schlüssel, Prekey-Signatur, `spk_id`, `reg_id`, `adv_secret`, JID-Nutzer/-Gerät, LID-Nutzer/-Gerät, Plattformname, Firmenname, ADV-Identität (details ≤ 128 Byte, Account-Schlüssel, Account- und Geräte-Signatur, key index, raw id, Typen), Fingerabdruck des Noise-Zwischenzertifikats, SHA-256 über alles davor. Host `build/tachyon.creds`, Amiga `SYS:tachyon.creds` (später ENVARC:). Jedes verfälschte Byte wird abgelehnt (Test über alle 810 Positionen); der Host prüft zusätzlich `wa_identity_check` (öffentliche Schlüssel und Prekey-Signatur nachgerechnet, ≈ 20 s auf dem 68000, dort deshalb übersprungen). Datensatz mit JID → Login-Payload, ohne → Pairing, keiner → neue Identität.

### Offline-Tests (vor jedem Live-Versuch)

- `make pairing-test` (ASan/UBSan): synthetisches `pair-success` aus `tools/pairvectors -mode pairsuccess` (Test-Account-Schlüssel signiert unsere Test-Identität, HMAC unter dem Test-ADV-Geheimnis, JID/LID/Plattform/Firma): Parsen, HMAC und Signatur **angenommen**; falsches Geheimnis, jedes veränderte Byte des Containers, fremde Identität, veränderte Signatur/Details/Schlüssel bei korrektem HMAC, Kürzungen: **abgelehnt**; Geräte-Signatur selbst geprüft; `pair-device-sign`-IQ codiert, von whatsmeow decodiert und von libsignal verifiziert, Bytes gleich whatsmeows eigenem `proto.Marshal` (`-mode verify-sign`); Refs und QR-Text aus dem aufgezeichneten pair-device-IQ; Ack- und Fehler-Knoten; Zugangsdaten hin und zurück. 77 Prüfungen.
- `make pair-sim`: der echte `pair_session()`-Code von `tests/wa_probe_core.c` an einem Pseudo-Server auf einem Pseudo-WebSocket (Transport-Verschlüsselung durch Durchreich-Stubs ersetzt, Handshake übersprungen): Ack, zwei Codes mit kurzer Gültigkeit (das „Telefon“ scannt den zweiten), Verify + Sign, `pair-device-sign` (von whatsmeow geprüft), 515, Schließen und der Punkt, an dem die Login-Verbindung beginnt; fremdes ADV-Geheimnis → 401 `hmac-mismatch` und Schließen; sechs Codes ohne Scan → Schließen ohne Reconnect, Pongs und Keepalives unterwegs; Login-Frame `<success>` / `<failure>`. 74 Prüfungen.

### Taktregel für Live-Versuche (verbindlich)

WhatsApp drosselt und sperrt Konten oder Adressen; das Konto ist ein echtes. Deshalb: kein automatischer Wiederholungsversuch irgendwo im Code oder in den Skripten (nach sechs Codes ohne Scan schließt der Client und endet; nach einem Fehler ebenso), höchstens eine Live-Verbindung zugleich, alles zuerst offline (oben), Pairing-Versuche angekündigt, höchstens drei je Sitzung, mindestens fünf Minuten Abstand, nach einem Fehlschlag erst die Ursache aus dem Log, nach zwei Fehlschlägen keine weiteren Live-Versuche, sondern die Analyse. Reine Handshake-Proben (`make wa-probe`) bleiben bei wenigen pro Stunde; Achtung: `make vamos-probe` ist seit amitools' bsdsocket-Nachbildung eine echte Verbindung.

### Live-Ergebnisse (2026-11-27)

Zwei angekündigte Pairing-Versuche, beide beim ersten Anlauf erfolgreich; dazu ein Login mit den gespeicherten Zugangsdaten. Mehr Live-Verbindungen gab es für diesen Abschnitt nicht.

**Host (`make wa-pair`, macOS):** 6 Refs, Telefon scannte den zweiten Code; `pair-success` → HMAC + Account-Signatur 3 ms, Geräte-Signatur 1 ms, `pair-device-sign` angenommen; `stream:error 515` 0,7 s später, Login-Verbindung (TLS, WebSocket, Noise mit Login-Payload) bis `<success>` **0,82 s**. Zweiter Lauf mit `build/tachyon.creds`: nur Login, `<success>` nach 0,66 s.

**Emulierter A500 (`make run-pair FAST=2048`, FS-UAE, A2065/slirp, TheWire13, Noise-Cache vorgewärmt):** Identität 18,3 s + drei Schlüsselpaare 6,5 s vor dem Connect; Registrierungs-Payload 300 Byte; TLS 32,1 s, Noise-ClientFinish 40,6 s nach ServerHello (10 Pongs); erster Code 80,3 s nach dem Connect (Encode 0,78 s, Zeichnen 0,92 s, 61 × 61 Module à 6 × 3 Pixel). Das Telefon las den Code **vom FS-UAE-Fenster ab**, `pair-success` 18,3 s nach dem Anzeigen. Prüfung (HMAC + XEdDSA) **11,30 s**, Geräte-Signatur **7,84 s**, 4 Pongs dazwischen; `pair-device-sign` **19,6 s nach `pair-success`** – der Server nahm das an, obwohl der Code längst „abgelaufen" war (die Gültigkeit zählt nur bis zum Scan). 515 nach 0,66 s; neue TLS- und Noise-Ephemeral-Schlüssel 6,6 s; Login-Verbindung bis `<success>` **76,0 s** (TLS 32 s, Noise 41,3 s, 87-Byte-Payload). Programmstart → `<success>` 228,7 s, 26 Pongs insgesamt. Zugangsdaten: `SYS:tachyon.creds` → `build/tachyon-a500.creds`. Benchmarks: BENCHMARKS.md Schritt 19.

Beobachtungen:

- **Mehrere Frames je WebSocket-Nachricht:** nach `pair-device-sign` schickt der Server `<stream:error code=515>` und `<xmlstreamend>` als zwei 3-Byte-längenpräfixierte Frames **in einer** Nachricht (23 Bytes Rest). Die erste Fassung wertete nur den ersten Frame aus und meldete „bad encrypted frame"; `recv_frame()` läuft seit 887110e die Frames einer Nachricht nacheinander ab (wie whatsmeows `framesocket.processData`). Der Simulator (`make pair-sim`) stellt den Fall nach.
- **Plattformtyp:** beide Live-Pairings liefen mit `platformType` UNKNOWN (0) – das Host-Pairing vor der Umstellung auf FIREFOX, das A500-Pairing mit einem Binary, das 37 s vor der Header-Änderung gebaut war (`proto/clientpayload.h` fehlte in den Make-Abhängigkeiten, seitdem `PROBE_HDR`). Das Telefon führt beide Einträge als „Anderes Gerät" (der Os-String „Amiga 500" erscheint nicht), verbunden sind sie trotzdem. Ob FIREFOX wie bei whatsmeow/Baileys „Firefox (Amiga 500)" ergibt, zeigt erst das nächste Pairing; der Typ wird nur bei der Registrierung gesendet, ein Wechsel braucht ein neues Pairing.
- **Dritter Versuch (A500, Plattformtyp FIREFOX, Binary mit `PROBE_HDR` neu gebaut):** wieder beim ersten Anlauf gepaart und eingeloggt (Gerät :9); das Telefon führt es als **„Firefox (Amiga 500)“** – Plattformtyp und Os-String aus den DeviceProps erscheinen also genau wie bei whatsmeow/Baileys, UNKNOWN ergibt „Anderes Gerät“. Scan 15,1 s nach dem ersten Code, Prüfung 12,04 s, Signatur 8,14 s, `pair-device-sign` 20,7 s nach `pair-success`, 515 nach 1,04 s, Login-Verbindung 79,9 s, Programmstart → `<success>` 234 s. Die Fortschrittsanzeige (ein Punkt je 2 s aus dem CRYPTO_YIELD-Hook) kostete etwa 5 % (Noise 42,8 s statt 40,6 s, Prüfung 12,0 s statt 11,3 s) – ein `DateStamp`-Aufruf je Yield; seitdem fragt der Hook nur jeden 16. Yield nach der Zeit. Drei Pairing-Versuche in dieser Sitzung, alle erfolgreich; damit ist das Kontingent der Taktregel aufgebraucht.
- **Keepalive vor dem Login:** `<iq xmlns=w:p type=get><ping/></iq>` alle 25 s wird auch auf der Pairing-Verbindung beantwortet; der WebSocket-Pong alle 4 s trägt die 19 s Rechenzeit zwischen `pair-success` und `pair-device-sign`.
- **Nach `<success>`** ist noch nichts getan: whatsmeow lädt dann Prekeys hoch und schickt `<iq xmlns=passive><active/>`; komprimierte Frames (Flag-Bit 1) kann die Probe noch nicht lesen. Das gehört zum Client, nicht zur Probe.
- `make vamos-probe` ist seit amitools' `bsdsocket`-Emulation eine echte Verbindung und zählt für die Taktregel.
- **Login mit beiden Caches (2026-11-27 19:11 und 19:19, zwei Logins mit Gerät :9, fünf Minuten Abstand):** Lauf 1 (TLS-Cache leer, Noise-Cache nur Zwischenzertifikat) Login-Verbindung **74,4 s** (TLS 31,7 s, Noise-ClientFinish 39,4 s nach ServerHello; die schnellere Leiter aus BENCHMARKS.md Schritt 20 brachte −1,6 s gegenüber 76,0 s), schreibt `SYS:tlscache.bin` (585 Byte) und das 64-Byte-`SYS:noisecache.bin`. Lauf 2: `tls: certificate cache HIT` und beide Noise-Zertifikate `cache HIT`, Login-Verbindung **52,0 s** (TLS **20,3 s**, Noise **28,5 s**, 6 Pongs), `<active/>` 5,7 s nach dem Connect-Ende angenommen; Programmstart → `<success>` **62 s** statt 122 s, weil der gespeicherte Prekey-Batch (10 anstehende Schlüssel) die 32 s Erzeugung ersparte. In beiden Läufen hielt der Server 6 unserer Prekeys (4 seit dem Upload verbraucht: andere Geräte haben Sessions zu uns aufgebaut; `<offline_preview count=29 message=5 …>`), kein Upload nötig. Die **170 698-Byte-Nachricht** des Servers (nach `<active/>`, vermutlich der Offline-Stapel) wird jetzt **verworfen statt die Verbindung zu beenden** („a 170698-byte message was dropped“), die Verbindung läuft weiter bis zum geplanten Schließen. **0 NewSessionTickets** in der ganzen Verbindung. Was von den 52 s bleibt: 4 × X25519 (30,8 s), RSA-PSS CertificateVerify (≈ 5 s), HKDF/AES-GCM-Schlüsselaufbauten, Netz. Nächster Hebel ohne Protokolländerung: `es` = DH(e_c, s_s) mit dem gecachten Server-Static vor dem Connect rechnen (−7,7 s), siehe X25519-PLAN.md.
- **Login mit vorgerechnetem `es` (2026-11-27 19:31 und 19:38, zwei Logins mit Gerät :9):** Lauf A (Caches wie oben) 52,5 s, schreibt den Server-Static als dritte Hälfte von `SYS:noisecache.bin` (96 Byte). Lauf B rechnet `es` in 8,0 s vor dem Connect („es = DH(ephemeral, stored server static) computed … before the connection“), der Server-Static im ServerHello ist derselbe („es taken from the precomputation, 2 X25519 ladders online“): Noise-ClientFinish **19,7 s** nach ServerHello (4 Pongs), Login-Verbindung **43,1 s** (TLS 20,3 s), Programmstart → `<success>` 61 s (die 8 s Vorausrechnung liegen davor, nicht in der Server-Uhr). Dem Server gegenüber unverändert, angenommen wie zuvor. Tagesbilanz der Login-Verbindung: 76,0 s → 43,1 s; online bleiben drei X25519-Leitern (23 s), RSA-PSS CertificateVerify (≈ 5 s), HKDF/GCM (≈ 5 s), Netz und Parsen. Live-Logins an diesem Abend: 4 (19:11, 19:19, 19:31, 19:38), keine Fehlversuche.
- **Schlüssel für den nächsten Start im Leerlauf (2026-11-27 19:50 und 19:57, zwei Logins mit Gerät :9):** Lauf C (wie B) rechnet nach `<active/>` in 15,9 s die beiden Schlüsselpaare und `es` für den nächsten Start (3 Pongs dabei) und schreibt `SYS:tachyon.next` (226 Byte). Lauf D liest ihn beim Start, löscht ihn („consumed (deleted)“), hat die Schlüssel nach **0,06 s** und verbindet 4,2 s nach Programmstart; Login-Verbindung 43,2 s, **Programmstart → `<success>` 47,4 s** (B: 61 s, mittags 122 s); danach in 18,0 s der Datensatz für den übernächsten Start. Vor dem Connect rechnet der A500 jetzt nichts mehr; was bleibt, sind die 43 s der Verbindung selbst (TLS 20,4 s, Noise 19,7 s). Live-Logins an diesem Abend: 6, keine Fehlversuche.

## 12. Nachrichten: Signal-Sessions, `<message>`, Quittungen (2026-11-27, `proto/signal.c`)

Eigenes Dokument: **[SIGNAL.md](SIGNAL.md)** – X3DH in beiden Rollen, Double Ratchet und Nachrichtenformate bitgenau zu libsignal (Go-Orakel `tools/signalvectors`), die WhatsApp-Schicht (`waE2E.Message`, Padding, `<message>`/`<enc>`, `DeviceSentMessage`, Geräteidentität, Quittungen wie whatsmeow), Byte-Layout des Sitzungsdatensatzes, Offline-Tests (`make signal-test`, `make pair-sim` Szenario E), der Interim-Chat auf Host und A500 und die Live-Ergebnisse. Die Taktregel aus Abschnitt 11 gilt unverändert; Nachrichten, die nicht entschlüsselt werden können, werden nur bestätigt, nie mit einer Retry-Quittung neu angefordert.

Stand (SIGNAL.md 6): im vierten Live-Versuch hat der emulierte A500 den ersten Text an die eigene Nummer gesendet (X3DH als Initiator 64 s, PreKeySignalMessage + Geräteidentität) und der Server ihn 0,5 s später bestätigt; der Text steht im Selbst-Chat des Telefons (Ende zu Ende). Versuch 8 blieb 22 Minuten online (Keepalive alle 20 s), verarbeitete den Offline-Stapel samt 166-KB-History-Frame, entschlüsselte eine Offline-Nachricht und sendete vier getippte Zeilen (auf dem Telefon angekommen); eine Antwort des Telefons auf dem A500 steht aus (Versuch 9).

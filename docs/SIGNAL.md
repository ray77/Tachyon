# Signal-Sessions und Nachrichten (Phase 5)

Stand 2026-11-27. Was hier steht, ist implementiert und offline gegen libsignal (Go, `go.mau.fi/libsignal` in der von whatsmeow verwendeten Fassung) bitgenau geprüft; die Live-Ergebnisse stehen am Ende. Dateien: `proto/signal.c/.h` (freistehend, nur die Krypto-Primitiven aus `crypto/ref`), die Nachrichtenschicht in `tests/wa_probe_core.c` (Abschnitt „messages“), der Interim-Chat in `tests/wa_probe.c` (Host) und `bench/wa_probe_amiga.c` (A500), Orakel `tools/signalvectors/main.go`, Tests `tests/signal_test.c` und Szenario E in `tests/wa_pair_sim.c`.

## 1. Einordnung

WhatsApp verschlüsselt Nachrichten zwischen zwei Geräten mit dem Signal-Protokoll (X3DH zum Sitzungsaufbau, Double Ratchet für die Nachrichten); der Server sieht nur die Umschläge. Das Begleitgerät hat seit dem Pairing eine Signal-Identität (`proto/identity.c`: Identitätsschlüssel, signierter Prekey mit XEdDSA-Signatur, Registrierungs-ID) und lädt einmalige Prekeys hoch (`proto/prekeys.c`). Diese Schicht macht daraus Sitzungen: zu jedem fremden Gerät eine, mit dem Zustand des Ratchets, und darüber das WhatsApp-Nachrichtenformat.

Außerhalb dieses Blocks: Gruppen (Sender Keys), Medien, Statusmeldungen, die Geräteliste eines Kontakts (`usync`). Nachrichten gehen vorerst nur an **Gerät 0, das Telefon** des Gegenübers; weitere Begleitgeräte des Gegenübers bekommen die Nachricht nicht (das Telefon zeigt sie trotzdem, und die eigene App zeigt ausgehende Nachrichten erst, wenn auch die eigenen Geräte adressiert werden – für den Selbst-Chat über `DeviceSentMessage`, siehe 3.3).

## 2. Protokoll, wie implementiert

Alles folgt libsignal-go; wo whatsmeow eine Eigenheit hat, ist sie übernommen. Primitiven: X25519 (`x25519_ref`, Schlüsselpaare mit `x25519_base_comb`), HKDF-SHA256, HMAC-SHA256, AES-256-CBC mit PKCS#7, XEdDSA-Verifikation (`xeddsa_verify`).

### 2.1 Sitzungsaufbau als Initiator (X3DH)

1. **Prekey-Bundle holen:** `<iq xmlns=encrypt type=get to=s.whatsapp.net><key><user jid=NUMMER[:GERÄT]@s.whatsapp.net reason=identity/></key></iq>`. Antwort: `<list><user jid><registration>BE32</registration><type>05</type><identity>32 Byte</identity><skey><id>BE24</id><value>32</value><signature>64</signature></skey>[<key><id>BE24</id><value>32</value></key>]</user></list>` (`sig_bundle_from_node`). Ohne `<key>` läuft X3DH mit drei statt vier DHs.
2. **Signatur prüfen (Pflicht):** `xeddsa_verify(signature, 05‖spk, 33, identity)`. Falsche Signatur → `SIG_ERR_SIGNATURE`, keine Sitzung.
3. **Master-Secret:** `FF×32 ‖ DH(ident_A, spk_B) ‖ DH(base_A, ident_B) ‖ DH(base_A, spk_B) [‖ DH(base_A, opk_B)]`, `base_A` frisch. `HKDF(salt = 32×00, ikm = master, info = "WhisperText", 64)` → Root-Key ‖ Chain-Key (die Empfangskette auf dem SPK des Gegenübers).
4. **Erste Sendekette:** frisches Ratchet-Schlüsselpaar, `HKDF(salt = root, ikm = DH(ratchet_A, spk_B), info = "WhisperRatchet", 64)` → neuer Root ‖ Sende-Chain-Key.
5. Der Zustand merkt sich `pend_opk_id`, `pend_spk_id`, `pend_base_pub` (`has_pending`); solange keine Nachricht des Gegenübers angekommen ist, geht jede Nachricht als **PreKeySignalMessage** hinaus.

Kosten auf dem 68000: XEdDSA 9,4 s + 4 Leitern 30,8 s + 2 Schlüsselpaare 6,2 s + 1 Leiter 7,7 s ≈ **54 s** (ohne einmaligen Prekey 46 s); der WebSocket-Pong alle 4 s hält die Verbindung (`heartbeat`).

### 2.2 Sitzungsaufbau als Responder

Eingehende PreKeySignalMessage: `preKeyId` → privater einmaliger Prekey aus `proto/prekeys.c` (`wa_prekeys_find`), `signedPreKeyId` muss unsere SPK-ID sein, sonst `SIG_ERR_NO_PREKEY`. Master-Secret spiegelbildlich (`DH(spk_A, ident_B) ‖ DH(ident_A, base_B) ‖ DH(spk_A, base_B) [‖ DH(opk_A, base_B)]`), Sendekette = unser SPK-Paar (libsignal), Empfangskette auf dem Ratchet-Schlüssel der Nachricht beim ersten Entschlüsseln. Nach erfolgreichem Entschlüsseln wird der einmalige Prekey aus dem Datensatz entfernt (`wa_prekeys_remove`, der private Teil genullt) und der Datensatz gespeichert. Kommt dieselbe PreKeySignalMessage noch einmal (gleicher `baseKey`), wird kein neuer Zustand angelegt (libsignal `HasSessionState`), sondern in der bestehenden Sitzung entschlüsselt – und dort mit `OLD_COUNTER` abgelehnt. Ein neuer `baseKey` legt einen neuen Zustand an und archiviert den bisherigen (ein Archivzustand je Sitzung; libsignal hält 40).

Kosten: 3–4 Leitern (23–31 s) für X3DH, dann für die erste Nachricht ein Ratchet-Schritt (2 Leitern + 1 Schlüsselpaar ≈ 18,5 s).

### 2.3 Double Ratchet

- Nachrichtenschlüssel: `HKDF(salt = 32×00, ikm = HMAC(ck, 01), info = "WhisperMessageKeys", 80)` = Cipher-Key 32 ‖ MAC-Key 32 ‖ IV 16; nächster Chain-Key `HMAC(ck, 02)`.
- Senden: `counter = send_index`, `previousCounter = send_index − 1` **als uint32** – für eine frische Kette also 0xFFFFFFFF (libsignal-go rechnet `max(index−1, 0)` auf uint32; whatsmeow sendet das so, und wir auch, sonst stimmen die Vektoren nicht).
- Empfangen mit unbekanntem Ratchet-Schlüssel: Empfangskette ableiten, frisches Schlüsselpaar, neue Sendekette (DH-Ratchet). Übersprungene Nachrichtenschlüssel werden gespeichert (höchstens `SIG_SKIPPED` = 12 je Zustand, 3 Empfangsketten; libsignal 2000 / 5), höchstens 2000 Zähler voraus (`SIG_MAX_FUTURE`), sonst `SIG_ERR_FUTURE`. Ein schon verbrauchter Zähler → `SIG_ERR_OLD_COUNTER` ohne Versuch im Archiv (libsignal: `ErrOldCounter` bricht ab).
- Entschlüsselt wird **auf einer Kopie**; nur Erfolg schreibt den Zustand zurück (libsignal-go verändert den Zustand auch bei MAC-Fehlern – ein Verhalten, das wir nicht teilen). Schlägt der aktuelle Zustand fehl, wird der Archivzustand versucht und bei Erfolg zum aktuellen gemacht (`DecryptWithRecord`).

### 2.4 Nachrichtenformate

- **SignalMessage** (Typ `msg`): Versionsbyte `0x33` (Version 3 in beiden Nibbles), dann Protobuf `ratchetKey(1) = 05‖pub (33 Byte)`, `counter(2)`, `previousCounter(3)`, `ciphertext(4)`, dann **8 Byte MAC** = `HMAC-SHA256(macKey, 05‖senderIdent ‖ 05‖receiverIdent ‖ Versionsbyte‖Protobuf)[0..8)`. Ciphertext = AES-256-CBC(cipherKey, iv) mit PKCS#7.
- **PreKeySignalMessage** (Typ `pkmsg`): Versionsbyte `0x33`, Protobuf `preKeyId(1)` (nur mit einmaligem Prekey), `baseKey(2) = 05‖pub`, `identityKey(3) = 05‖pub`, `message(4)` = die komplette SignalMessage, `registrationId(5)`, `signedPreKeyId(6)`.
- MAC und Signaturen werden zeitkonstant verglichen; jede Abweichung (Version, Längen, Typbyte 05, MAC) ist ein Fehler ohne Zustandsänderung.

### 2.5 WhatsApp-Schicht (`tests/wa_probe_core.c`)

- **Klartext:** `waE2E.Message`-Protobuf: `conversation(1)` = Text; für die **eigene Nummer** gewickelt als `deviceSentMessage(31){destinationJID(1) = "NUMMER@s.whatsapp.net", message(2)}` (so legt das Telefon die Nachricht in den Selbst-Chat). Dann whatsmeows **Padding:** 1–15 Kopien eines zufälligen Nibbles (0 → 15), beim Lesen umgekehrt (`wa_pad`/`wa_unpad`, letztes Byte = Länge, alle Padding-Bytes gleich, sonst Fehler).
- **Senden:** `<message id=ID type=text to=NUMMER@s.whatsapp.net><participants><to jid=NUMMER:GERÄT@s.whatsapp.net><enc v=2 type=pkmsg|msg>…</enc></to></participants>[<device-identity>ADVSignedDeviceIdentity</device-identity>]</message>`. Die Geräteidentität (`details(1)`, `accountSignatureKey(2)`, `accountSignature(3)`, `deviceSignature(4)` aus den Zugangsdaten) reist bei jeder PreKeySignalMessage mit, damit das Gegenüber unser Gerät dem Konto zuordnen kann. Nachrichten-ID wie whatsmeow: `"3EB0"` + 18 Großbuchstaben-Hex aus SHA-256(Zeit BE64 ‖ `NUMMER@c.us` ‖ 16 Zufallsbytes). Der Server bestätigt mit `<ack class=message id>` (Zeit `t_msg_ack`), das Gegenüber mit `<receipt id … type=…>` (`t_msg_receipt`).
- **Empfangen:** `<message from=… [participant]><enc v=2 type=pkmsg|msg>…</enc></message>`. Absender = `from` (Gruppen: `participant`); `@lid`-Absender bekommen eine eigene Sitzung (Schlüssel im Speicher: Nummer bzw. LID, Gerät, Art). Text aus `conversation(1)`, `extendedTextMessage(6).text(1)`, `deviceSentMessage(31).message(2)`; UTF-8 wird für die Konsole nach Latin-1 gewandelt (anderes → `?`).
- **Quittungen wie whatsmeow:** erfolgreich entschlüsselt → `<receipt id to=from [recipient] [participant] type=sender|inactive>` (`sender`, wenn der Absender unser eigenes Konto ist; `inactive`, weil wir keine Präsenz senden) – **kein** `<ack>`. Nicht entschlüsselbar → nur `<ack>`, **keine Retry-Quittung** (whatsmeow würde eine schicken und der Absender dann neu senden; Taktregel: keine Wiederholungen). Gruppen-, Broadcast-, Newsletter-Nachrichten und `<enc>` anderer Typen → `<ack>` und Log.
- **Sitzungsspeicher:** nach jeder Zustandsänderung (`save_sessions`) schreibt der Aufrufer den Datensatz als `….tmp` und benennt um (Host `rename`, AmigaDOS `DeleteFile` + `Rename`); ein Absturz lässt nie einen halben Datensatz unter dem echten Namen. Ein ungültiger Datensatz beim Start bricht ab (löschen heißt: alle Sitzungen neu).

## 3. Byte-Layouts

### 3.1 Sitzungsdatensatz (`sig_store_write`, Big-Endian, SHA-256 am Ende)

| Offset | Länge | Inhalt |
|---:|---:|---|
| 0 | 1 | Version 1 |
| 1 | 4 | Anzahl Sitzungen n (≤ 6) |
| 5 | 4 | LRU-Stempel |
| 9 | n × 3806 | Einträge |
| … | 32 | SHA-256 über alles davor |

Eintrag (3806 Byte): Nutzer 24 (Nummer oder LID, nullterminiert), Gerät 4, Art 1 (0 = `s.whatsapp.net`, 1 = `lid`), Stempel 4, Zustand aktuell 1886, Zustand Archiv 1886, `has_prev` 1.

Zustand (1886 Byte): `valid` 1, `has_pending` 1, eigene Identität 32, fremde Identität 32, eigene/fremde Registrierungs-ID 4+4, Root 32, Sende-Ratchet privat/öffentlich 32+32, Sende-Chain-Key 32, `send_index` 4, `prev_counter` 4, Empfangsketten: Anzahl 4 + 3 × (Ratchet-Pub 32, Chain-Key 32, Index 4), übersprungene Schlüssel: Anzahl 4 + 12 × (Ratchet-Pub 32, Zähler 4, Cipher 32, MAC 32, IV 16), `pend_opk_id` 4, `pend_spk_id` 4, `pend_base_pub` 32, `base_key` 32. Gesamt: 1 Sitzung 3847 Byte, 6 Sitzungen 22 877 Byte (`SIG_STORE_MAX_SIZE`).

### 3.2 Dateien

| Host (`tests/wa_probe.c`) | A500 (`bench/wa_probe_amiga.c`) | Inhalt |
|---|---|---|
| `build/tachyon.sessions` (`SESSIONS`) | `SYS:tachyon.sessions` (↔ `build/tachyon-a500.sessions`) | Sitzungsdatensatz (3.1) |
| `CHAT_TO`, `CHAT_DEVICE` (0), `CHAT_LID`, `CHAT_SEND` | `SYS:chat.txt`: Zeile 1 Nummer, Zeile 2 Text, Zeile 3 Sekunden online | Interim-Chat |
| stdin, zeilenweise (`select`), `/quit` | CON:-Fenster (`WaitForChar` + `Read`), `/quit` | Eingabe während der Verbindung |

`make run-chat CHAT_TO=NUMMER CHAT_SEND='Text' CHAT_LINGER=300 FAST=2048` schreibt `chat.txt`, kopiert Zugangsdaten, Prekeys, nächste Schlüssel und Sitzungen hin und zurück (`tools/run-fsuae-net.sh`). Die Nummer des Gegenübers taucht in `build/`-Logs auf, nie in `docs/` oder Commits.

## 4. Vektoren und Offline-Tests

- **`tools/signalvectors`** (`make signal-vectors` → `tests/vectors/signal_vectors.txt`, 152 Zeilen `name=hex`): libsignal spielt beide Seiten mit festen Schlüsseln (Alice = unsere Testidentität aus `tools/pairvectors`, Bob = das Telefon). Szenario s1: Alice baut die Sitzung, zwei PreKeySignalMessages, Bob antwortet (Ratchet-Schritt), Nachrichten außer der Reihe (msg2 vor msg1), weitere Schritte; s2: Bob baut mit Alices Bundle (einmaliger Prekey 5), Archivzustand; s3: unbekannter Prekey; **wa**: zwei echte `waE2E.Message`-Protobufs des Telefons mit whatsmeow-Padding (beides PreKeySignalMessages: libsignal schickt die, bis es eine Antwort gesehen hat). Zwischenwerte (X3DH-Root/Chain, Sende-Root/Chain, erste Nachrichtenschlüssel, Ratchet-Zustände) stehen mit dabei. `-mode check-message -in DATEI -want TEXT` lässt libsignal eine PreKeySignalMessage **unseres** Codes als Bob entschlüsseln, Padding und `DeviceSentMessage` prüfen.
- **`make signal-test`** (ASan/UBSan, 79 Prüfungen): beide Rollen bitgenau (Nachrichten, Zwischenwerte, Zustände nach jedem Schritt), abgelehnt: veränderte MAC, verändertes Typbyte, Kürzungen, falsche innere MAC, wiederholter Zähler (`OLD_COUNTER`), unbekannter Prekey, manipuliertes Bundle (Signatur); Fenster übersprungener Schlüssel (16 Nachrichten, die letzte zuerst); Sitzungsdatensatz hin und zurück, jedes gekippte Bit abgelehnt, LRU-Verdrängung bei 7 Sitzungen.
- **`make pair-sim`, Szenario E** (241 Prüfungen zusammen mit A–D): der echte Core gegen den Pseudo-Server: Bundle-IQ → Bobs Bundle; unser `<message>` (Struktur, `participants/to/enc`, Geräteidentität bei `pkmsg`, Nachrichten-ID) → `build/msg_pkmsg.bin`, das libsignal anschließend entschlüsselt (`check-message`, Text „Hallo vom Amiga“ als `DeviceSentMessage`); `<ack class=message>`; dann die beiden Nachrichten des Telefons (einmaliger Prekey 5 wird verbraucht, 6 bleiben), Quittungen `type=sender` mit den richtigen IDs, Texte am Konsolen-Callback (Latin-1), kein `<ack>` für entschlüsselte Nachrichten; Datensatz hin und zurück; zweite Verbindung schickt auf der Sitzung des Telefons eine **plain `msg`** ohne Bundle-Abfrage.

Reihenfolge vor jedem Live-Versuch: `make signal-test pair-sim host-test`.

## 5. Interim-Chat

Host: `CHAT_TO=NUMMER CHAT_SEND='Text' LINGER=300 ./build/wa_probe` nach dem Login (Zugangsdaten `build/tachyon.creds`); getippte Zeilen gehen an die Nummer, eingehende Texte erscheinen als `*** NUMMER:GERÄT: Text`. A500: `make run-chat …` (oben); im Konsolenfenster der Probe getippte Zeilen + Return werden gesendet, eingehende Texte erscheinen dort. Beides ist Behelf bis zur GUI (Phase 6); die Schicht darunter (`send_text`, `handle_message`, Sitzungsspeicher) bleibt.

Zusammenfassung am Ende jedes Laufs: `MESSAGES: sent …, received …, undecryptable …, receipts …, sessions started … (last X3DH … ms), encrypt … ms, decrypt … ms`.

## 6. Live-Ergebnisse

Taktregel (PROTOCOL.md 11): jede Live-Verbindung angekündigt, höchstens eine zugleich, wenige je Stunde, keine Wiederholungsschleifen; erstes Ziel ist die **eigene Nummer** (Selbst-Chat), eine Nachricht hinaus, eine herein je Versuch.

*Steht aus – wird nach dem ersten angekündigten Versuch nachgetragen.*

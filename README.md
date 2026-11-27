<p align="center"><img src="docs/img/tachyon.png" alt="Tachyon" width="220"></p>

# Tachyon – Native WhatsApp für den Amiga 500

## Ziel und verbindliche Hardware

Ein vollständig nativer WhatsApp-Multi-Device-Client, der echte Nachrichten direkt sendet und empfängt. Alle Protokolle und kryptografischen Operationen laufen lokal.

- Amiga 500, Motorola 68000, 7,09 MHz (PAL), OCS.
- 512 KiB Chip-RAM + **1 MiB echtes Fast-RAM** (insgesamt 1,5 MiB) als Benchmark-Maschine für die Kryptografie; der Netz-Client mit TCP/IP-Stack setzt **2 MiB Fast-RAM** voraus (docs/NETWORK.md Abschnitt 6).
- Keine Turbokarte, FPU, MMU, PiStorm, Gateway, Bridge oder externe Kryptografie.
- Kickstart/Workbench 1.3 als angestrebte Mindestplattform; Kompatibilität prüfen.
- Netzwerkadapter und Festplatte/CF zulässig; Netzwerkadapter darf keine WhatsApp- oder Kryptografie-Aufgaben übernehmen.
- Trapdoor-Slow-RAM ist kein Ersatz für echtes Fast-RAM.

## Architektur

```text
Intuition / graphics.library (native GUI)
        |
WhatsApp Core: Pairing, Kontakte, Chats, Gruppen
        |
Signal-kompatible Ende-zu-Ende-Verschlüsselung
        |
Binäre WhatsApp-Nodes / Protobuf
        |
Noise / WebSocket / TLS
        |
TCP/IP / Netzwerkadapter
        |
WhatsApp-Server
```

Die aktuelle Protokollstruktur, unterstützten Cipher-Suites, Endpunkte und Pairing-Verfahren anhand einer funktionierenden Referenzimplementierung verifizieren. Kein Browser, kein JavaScript-Runtime.

## Referenzen

| Projekt | Verwendung |
|---|---|
| [Whatsmeow](https://github.com/tulir/whatsmeow) | Go-Referenz für Multi-Device, Noise, Pairing, Nachrichten und Synchronisation |
| [Baileys](https://github.com/WhiskeySockets/Baileys) | Zweite Protokollreferenz, keine Node.js-Portierung |
| [BearSSL](https://bearssl.org/) | Kompaktes TLS, i15-Arithmetik, AES und Hashes |
| [Monocypher](https://github.com/LoupVaillant/Monocypher) | Einzelne geeignete kryptografische Primitive |
| [Nanopb](https://github.com/nanopb/nanopb) | Speicherarmes Protobuf-Parsing |
| [lwIP](https://github.com/lwip-tcpip/lwip) | Optionaler TCP/IP-Stack |
| [Roadshow](https://roadshow.apc-tcp.de/) | Amiga-TCP/IP; OS-1.3-Kompatibilität prüfen |

Nur benötigte Bestandteile übernehmen. Lizenzen, Versionen und Abhängigkeiten dokumentieren. Keine vollständige Portierung moderner Laufzeitumgebungen.

## Motorola 68000 optimieren

Der 68000 verfügt über acht 32-Bit-Datenregister, acht Adressregister, einen 16-Bit-Datenbus, native 16×16→32-Bit-Multiplikation, aber keine native 32×32-Bit-Multiplikation und keinen Instruktionscache.

- 15- und 16-Bit-Limbs sowie alternative Radix-Darstellungen vergleichen.
- MULU.W, ADDX, Registeroptimierung, Schleifenentrollung und spezialisierte modulare Reduktion einsetzen.
- Comba-Multiplikation untersuchen; Karatsuba nur bei messbarem Vorteil.
- Divisionen, unnötige Speicherzugriffe, Kopien und Funktionsaufrufe vermeiden.
- Big-Endian berücksichtigen; ausschließlich 68000-kompatible Instruktionen.
- Geheimnisabhängige Laufzeiten und Speicherzugriffe vermeiden; auch operandabhängige MULU-Laufzeiten berücksichtigen.
- Keine Veränderung mathematischer Definitionen oder Sicherheitsparameter.

## Custom-Chips als experimentelle Coprozessoren

### Agnus / Blitter

Drei 16-Bit-Eingänge A/B/C, Ausgang D, DMA, A/B-Shifter, Maskierung, auf-/absteigende Verarbeitung und alle 256 booleschen Funktionen. Kein nativer Addierer mit Carry-Propagation und keine Multiplikation.

| Operation | Minterm |
|---|---|
| A AND B | 0xC0 |
| A OR B | 0xFC |
| A XOR B | 0x3C |
| A XOR B XOR C | 0x96 |
| NOT A | 0x0F |
| SHA-256 Choose | 0xCA |
| SHA-256 Majority | 0xE8 |

```c
Ch    = (A & B) ^ (~A & C);
Maj   = (A & B) ^ (A & C) ^ (B & C);
SUM   = A ^ B ^ C;
CARRY = (A & B) | (A & C) | (B & C);
```

Forschungsansätze:

- AES: Bitslicing/Fixslicing, boolesche S-Box, XOR, MixColumns, mehrere unabhängige Blöcke.
- SHA-256: Choose/Majority, XOR, Shifts, unabhängige Hashzustände; serielle Runden und Additionen beachten.
- GHASH: Carryless-Multiplikation und XOR-Polynomreduktion.
- ChaCha20 (falls benötigt): hybride ARX-Operationen.
- X25519: experimentelle bitsliced Arithmetik gegen native Limb-Arithmetik testen; geringe Erfolgsaussicht bei einzelnen Handshakes.

### Copper

MOVE, WAIT und SKIP. Vorbereitete Blitter-Registersequenzen und verkettete Operationen untersuchen. COPCON, Registerbeschränkungen, DMA-Synchronisation und Betriebssystem-Koexistenz beachten. Kein universeller Prozessor.

```text
68000: X25519, Additionen, Netzwerk     Agnus: Copper → Blitter
               |                                  |
          1 MiB Fast-RAM                    512 KiB Chip-RAM
```

CPU möglichst im echten Fast-RAM arbeiten lassen, Blitter parallel im Chip-RAM. Blitter kann Fast-RAM nicht adressieren. Alle Kopier-, Setup-, Warte- und Synchronisationskosten messen. Bildschirm-DMA während Handshakes optional reduzieren. Blitter-Beschleunigung ist eine Hypothese, kein bewiesener Vorteil.

### Weitere Chips

- Denise: Bitplanes und Anzeige, keine allgemeine Arithmetik.
- Paula: Audio-DMA, serielle Schnittstelle, Interrupts, Benachrichtigungen und spätere Audioausgabe.
- CIA: Timer, Benchmark-Zeitmessung und mögliche Entropieerfassung. Timer allein sind keine sichere Zufallsquelle.

## Kryptografische Anforderungen

Aktuellen Bedarf anhand des Protokolls bestimmen:

- X25519 und Curve25519-Feldarithmetik, Signal-kompatible Signaturen.
- AES-128/256, AES-GCM, gegebenenfalls AES-CBC, GHASH.
- SHA-256, gegebenenfalls SHA-512, HMAC, HKDF.
- Noise, Signal Double Ratchet, Gruppenschlüsselverwaltung.
- TLS mit vollständiger Zertifikats- und Hostnamenvalidierung, passende Vertrauensanker und verlässliche Uhrzeit.
- Kryptografisch sicherer DRBG mit nachweislich ausreichender Entropie.

Historischer Ausgangspunkt für den Noise-Handshake: `Noise_XX_25519_AESGCM_SHA256`; aktuelle Gültigkeit prüfen. Keine deaktivierte Zertifikatsvalidierung, Nonce-Wiederverwendung oder unsicheren Zufallszahlen. Persistente Schlüssel und Ratchet-Zustände absturzsicher behandeln. Standardisierte und interoperable Testvektoren verwenden.

## Vorläufiges Speicherbudget

| Chip-RAM | KiB |
|---|---:|
| OS/Systemstrukturen | 192 |
| Bildschirm/GUI | 64 |
| Blitter-Arbeitsbereich | 96 |
| DMA/I/O-Puffer | 32 |
| Reserve | 128 |
| **Summe** | **512** |

| Fast-RAM | KiB |
|---|---:|
| Programmcode | 192 |
| Netzwerk/TLS | 160 |
| Kryptografie/Signal | 160 |
| WhatsApp Core | 128 |
| Protokollpuffer | 96 |
| Kontakte/Nachrichten | 96 |
| Stack/Heap | 64 |
| Reserve | 128 |
| **Summe** | **1024** |

Budgets sind ungemessene Ziele. Tatsächlichen OS- und Stackverbrauch, Fragmentierung sowie Spitzenbedarf messen. Streaming-Parsing, Streaming-Dekompression, statische Pools, wiederverwendbare Puffer, begrenzte Nachrichten- und Mediengrößen sowie bedarfsgerechtes Nachladen vom Datenträger nutzen. Große Synchronisationspakete niemals unkontrolliert komplett laden.

## Benutzeroberfläche und Funktionen

Native Intuition/graphics.library, bevorzugt 640×256 PAL in vier Farben. Kontaktliste, Chatfenster, Texteingabe, Senden, Status, ungelesene Nachrichten, scrollbarer Verlauf. Netzwerk und Kryptografie dürfen die GUI nicht dauerhaft blockieren.

Version 1.0: direkte Verbindung, QR-Pairing als verknüpftes Gerät, persistente Identität, Wiederverbindung, Text senden/empfangen, E2EE, Kontakte, Gruppen, lokale Historie und Lesebestätigungen.

Später: Emoji-Bitmaps, Bilder in 32 Farben/HAM6 (ggf. eigener Bildschirm), IFF/ILBM, Benachrichtigungstöne und Sprachnachrichten über Paula. Keine Priorität für Telefonie, Video oder vollständige historische Mediensynchronisation.

## Entwicklungsumgebung

C und Motorola-68000-Assembler; VBCC oder m68k-amigaos-gcc, VASM, native Amiga-Hunk-Binaries. Cross-Compilation auf macOS/Linux/Windows. WinUAE oder vergleichbare zyklusgenaue Emulation; abschließend reale Hardware. Automatisierte Tests und Git. Compileroptionen und Disassembly auf 68000-Kompatibilität prüfen.

## Teilprojekt AmigaCrypto

Backends `CPU000` (optimierte CPU), `BLITTER` (experimentell) und `HYBRID` (CPU/Copper/Blitter). Immer das schnellste nachweislich korrekte und sichere Backend wählen. Hardwarebeschleunigung ist kein Selbstzweck.

## Teilprojekt WhatsBench

| Messgröße | Einheit |
|---|---|
| X25519 | ms/Operation |
| AES-128/256, SHA-256/512, GHASH | Bytes/s |
| HMAC | Operationen/s |
| HKDF | ms/Operation |
| TLS- und Noise-Handshake | Gesamtdauer |

Zusätzlich Taktzyklen, Chip-/Fast-RAM-Spitzen, Stack, Blitter-Auslastung, Kopierkosten, Bildschirm-DMA, CPU/Blitter-Parallelität, Kaltstart, Wiederverbindung messen. Kleine Nachrichten und große Blöcke getrennt benchmarken. CPU-only als Baseline. Kryptografische Ergebnisse vor jedem Performancevergleich validieren. Tests auf echter Hardware wiederholen.

## Entwicklungsphasen

1. **Recherche:** aktuelles Protokoll, Multi-Device, Kryptografie, Zeitlimits, Netzwerkstack, sichere Entropie, Lizenzen.
2. **Kryptografie:** portable Referenz, X25519-Benchmark, 68000-Optimierung, AES/SHA/GHASH, Blitter/Copper-Experimente, Testvektoren.
3. **Netzwerk:** TCP/IP, DNS, TLS, Zertifikatsprüfung, WebSocket, Speicher- und Laufzeitmessung.
4. **WhatsApp-Verbindung:** binäres Protokoll, Noise, QR-Pairing, Identität, persistente Sitzung, Wiederverbindung.
5. **E2EE:** Signal-Sitzungen, Schlüsselverwaltung, Double Ratchet, erste echte gesendete und empfangene Textnachricht.
6. **GUI:** Intuition, Kontakte, Chats, Gruppen, Verlauf, Benachrichtigungen.
7. **Optimierung:** Speicher, Handshake-Laufzeit, CPU-Auslastung, Backend-Auswahl, Dauerbetrieb, Absturzsicherheit und Schlüsselablage.

## Risiken und offene Fragen

- Kein offiziell unterstütztes allgemeines WhatsApp-Client-Protokoll; Änderungen und Kontoeinschränkungen möglich.
- ~~68000 könnte serverseitige Handshake-Zeitlimits überschreiten.~~ Gemessen (docs/PROTOCOL.md Abschnitt 8): TLS 60 s, WebSocket-Leerlauf 10 s, per Pong-Herzschlag unbegrenzt verlängerbar (120 s geprüft). Herzschlag eingebaut (`CRYPTO_YIELD()` in X25519/Ed25519/RSA, `crypto/ref/heartbeat.c`) und mit unserem WebSocket/Noise-Stack gegen den Server bestätigt: 30 s Rechenpause, 7 Pongs, Handshake angenommen (Abschnitt 9).
- **TLS-Plan geändert (2026-11-27):** der Server wählt RSA-Schlüsseltransport, vollendet ihn aber für keinen Client (`decrypt_error`, auch OpenSSL/LibreSSL/Go). Der A500 geht über TLS 1.3 mit X25519 und RSA-PSS-Zertifikat – 1 X25519 online plus RSA-Prüfungen, kein P-256 (docs/PROTOCOL.md Abschnitt 7). Der TLS-1.3-Client (`crypto/ref/tls13.c`) ist geschrieben, gegen Go geprüft und wird vom Server angenommen (`make wa-probe`: eigener Stack von TCP aufwärts).
- **Netzwerk läuft (2026-11-27):** `net/bsdsock_io.c` über TheWire13s `bsdsocket.library` (Kickstart 1.3), FS-UAE mit emulierter A2065 auf slirp. Der emulierte A500 baut die komplette Verbindung selbst auf: DNS, TCP, TLS 1.3 (31,8 s), WebSocket, Noise XX mit Herzschlag (51,8 s, 12 Pongs) – `RESULT: handshake ACCEPTED by web.whatsapp.com` (docs/NETWORK.md, BENCHMARKS.md Schritt 17). Dafür nötig: eigene `utility.library` für 1.3 und der SANA-II-Wrapper `a2065fix.device`. Mit den drei X25519-Schlüsselpaaren vor dem Connect und dem Fingerabdruck-Cache für WhatsApps Noise-Zwischenzertifikat (PROTOCOL.md 6) schrumpft das Verbindungsfenster auf 78 s, Noise auf 40,1 s (Schritt 18).
- Blitter-Setup und Speichertransfers könnten jeden Geschwindigkeitsvorteil aufheben.
- 1,5 MiB RAM könnten für Synchronisation oder TLS nicht genügen.
- Netzwerkstack und Kickstart 1.3 sind noch nicht auf Kompatibilität geprüft.
- Sichere Entropie, Uhrzeit, Schlüsselablage und fehlende Speicherisolation sind Herausforderungen.
- Erfolgreiche Kryptografie-Benchmarks garantieren keinen funktionierenden WhatsApp-Client.
- Es liegen noch keine eigenen Benchmarks oder funktionierenden Prototypen vor.

## Konkreter Arbeitsauftrag an Claude

Nicht mit der GUI beginnen. Zuerst aktuelles Protokoll und tatsächliche Anforderungen verifizieren. Danach native 68000-Kryptografie entwickeln und insbesondere X25519 mit 15-/16-Bit-Limbs, spezialisierte Reduktion und Registeroptimierung untersuchen. AES, GHASH und SHA mit CPU-only und Blitter/Copper vergleichen. Aufteilung zwischen Chip- und Fast-RAM optimieren. Realistische TLS-/Noise-Handshake-Zeiten messen.

```text
Hypothese → Implementierung → Korrektheitstest → Benchmark
          → Vergleich → Optimieren oder verwerfen
```

Erfolgreiche und gescheiterte Ansätze, Messkonfigurationen und Testresultate dokumentieren. Keine unbelegten Performanceversprechen. Keine zusätzliche CPU und keine ausgelagerte Rechenleistung. Sicherheitsstandards niemals abschwächen. Hardware als Gesamtsystem betrachten, aber spekulative Ansätze ohne messbaren Vorteil verwerfen.

**Erster Meilenstein:** korrekte und ausreichend schnelle lokale kryptografische Verbindung auf dem originalen A500 mit 1 MiB Fast-RAM zusätzlich.

**Endgültiger Meilenstein:** echte WhatsApp-Textnachrichten direkt senden und empfangen, ohne Gateway oder externe Rechenunterstützung.

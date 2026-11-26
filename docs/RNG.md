# Zufallszahlen auf dem Amiga 500

Kickstart 1.3 hat keinen Zufallsgenerator. Der Client braucht Zufall für: Noise-Ephemeral-Keys (X25519, 32 Byte je Verbindung), Identity-/Signed-Prekey/Prekeys (Signal, 812 Schlüsselpaare beim Pairing), Registrierungs-IDs, GCM-IVs (Noise zählt; Signal-Nachrichten brauchen 16 Byte je Nachricht). Ein schwacher RNG macht jede andere Maßnahme wertlos (README: keine unsicheren RNGs).

## Was auf dem A500 *keine* Entropie liefert

Alle Takte des Rechners – CPU (7,09 MHz), CIA-E-Clock (CPU/10), Rasterstrahl (VHPOSR), Blitter, Audio-DMA – werden aus **einem** 28,375-MHz-Quarz abgeleitet. Das gegenseitige „Jitter“ von CIA-Timer gegen Strahlposition gegen CPU-Zyklen ist deshalb deterministisch bis auf Startphasen. Ein RNG aus „CIA-Timer bei VBlank auslesen“ (ein beliebtes Demo-Rezept) ist in Wahrheit ein Zähler mit festem Startwert und für Schlüssel unbrauchbar. Unter FS-UAE ist das Verhalten zudem vollständig reproduzierbar; eine Messung dort würde Entropie vortäuschen (oder keine zeigen), echte Hardware verhält sich anders – deshalb bauen wir nicht darauf.

Ebenso wenig: unausgelesener Speicherinhalt nach dem Einschalten (bei Warmstart identisch, unter Emulation null), Systemzeit (A500 ohne RTC startet 1978).

## Was Entropie liefert

| Quelle | Mechanismus | Rate | Verfügbarkeit |
|---|---|---|---|
| **Benutzereingabe** | Zeitpunkt (CIA-A-Timer-Tiefbyte + VHPOSR + Frame-Zähler) und Inhalt jedes Maus-/Tastatur-Ereignisses; der Mensch ist unabhängig vom Quarz | ≈ 2–4 Bit je Ereignis (konservativ 1 Bit gezählt) | immer; das QR-Pairing erfordert sowieso Interaktion |
| **Netzwerkadapter** | Ankunftszeit von Paketen (Fremdtakt: Server, Netz, Adapter-Quarz) gemessen mit CIA-Timer | ≈ 2–8 Bit je Paket | sobald die Verbindung steht; nicht für den ersten Schlüssel |
| **Floppy/Festplatte** | Rotations-/Suchzeiten sind mechanisch; Index-Puls vs. CPU-Takt | einige Bit je Zugriff | Laufwerk vorhanden |
| **RTC (A501 u. ä.)** | eigener 32-kHz-Quarz: Sekundenwechsel gegen CPU-Takt treibt | ≈ 1–3 Bit je Sekunde | nur mit Uhr |
| **Seed-Datei** | 32 Byte DRBG-Ausgabe beim Beenden auf Disk, beim Start eingemischt (wie `/var/lib/random-seed`) | überträgt gesammelte Entropie über Neustarts | Schreibzugriff auf SYS: |

Konsequenz für den Ablauf: Vor der ersten Schlüsselerzeugung zeigt der Client „Bitte Maus bewegen und Tasten drücken“ und sammelt, bis der konservative Zähler ≥ 256 Bit meldet (≈ 300 Ereignisse, einige Sekunden). Das ist derselbe Weg wie PGP 2.x auf Rechnern ohne Zufallsquelle. Danach wird kontinuierlich aus Netzwerk-Timing nachgeseedet.

## Architektur (implementiert in `crypto/ref/drbg.c`)

```
Ereignisse  ──rng_add()──▶  SHA-256-Pool (32 Byte, verkettet)  ──rng_seed_drbg()──▶  HMAC_DRBG (SP 800-90A, SHA-256)  ──drbg_generate()──▶  Schlüssel, IVs
```

* **Pool**: `pool = SHA-256(pool || sample)`. Kein Schätzer im Pool selbst; die Zählung der Entropie-Bits übernimmt der Sammler (konservativ, je Quelle).
* **HMAC_DRBG** nach SP 800-90A 10.1.2 mit HMAC-SHA-256: `Update`, `Instantiate`, `Reseed`, `Generate` (ohne Additional Input). Gegen eine unabhängige, aus der Spezifikation geschriebene Python-Implementierung geprüft (`tools/hmac_drbg_ref.py`, 40 Vektoren mit Reseed, `tests/drbg_test.c`). Deterministisch; Vorwärtssicherheit durch das abschließende `Update` je Generate.
* Reseed-Politik: nach jedem Pairing-Schritt, dann alle 1000 Generate-Aufrufe oder sobald ≥ 128 neue Bits gezählt sind.
* Kosten: ein `Generate` von 32 Byte = 3 HMAC = 6 SHA-256-Blöcke ≈ 40 ms (Assembler-SHA-256). Vernachlässigbar gegenüber den Kurvenoperationen.

## Was noch fehlt

* Der Sammler selbst (Input-Handler über input.device oder direkt Interrupt Level 2 auf dem A500, CIA-A-Timer als Zeitbasis) – Teil des Clients, nicht der Krypto-Bibliothek.
* Messung auf echter Hardware: Min-Entropie-Schätzung (SP 800-90B) der Eingabe-Timings. Unter Emulation nicht aussagekräftig.

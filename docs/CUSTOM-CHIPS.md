# Custom Chips als Krypto-Beschleuniger – Messung und Bewertung

Stand 2026-11-26. Alle Zahlen A500/FS-UAE (accuracy=1), Workbench-1.3-Bildschirm (Hires, 2 Bitplanes), Code und Daten der CPU in Fast RAM, Blitter-Puffer in Chip RAM. Harness: `bench/blitter_bench.c`. README-Vorgabe: Hypothese → Implementierung → Korrektheit → Messung → Vergleich.

## 1. Was der Blitter kann – gemessen

| Operation (1024 Wörter = 2 KiB) | Zeit | je Wort |
|---|---:|---:|
| CPU `d = a ^ b ^ c` (vbcc-C-Schleife, Fast RAM) | 6,70 ms | 46 Takte |
| CPU dito, Chip RAM | 6,80 ms | 47 Takte |
| **Blitter A^B^C→D** inkl. Setup + WaitBlit, Display an | **2,06 ms** | 14,3 Takte |
| Blitter A^B^C→D, Bitplane-DMA aus | 1,40 ms | 9,7 Takte (theoretisch 8: 4 Buszyklen) |
| Blitter Kopie A→D | 1,00 ms / 0,80 ms | 7 / 5,5 Takte |
| Blitter A^B^C, 65536 Wörter in einem Blit (Modulo −128) | 115 ms / 80 ms | 12,4 / 8,7 Takte |

Fixkosten je Blit (16 Wörter: 134 µs, 64: 217 µs, 256: 564 µs): **≈ 900 Takte Setup + WaitBlit** (13 Registerschreibzugriffe aus C plus Bibliotheksaufruf). Kleine Blits lohnen nicht; ab ≈ 256 Wörtern dominiert die Datenphase.

Nebenläufigkeit: `fe16_mul` (Fast RAM) 3,40 ms bei stehendem Blitter, **3,52 ms** bei dauerhaft laufendem Blitter (−3,5 %, davon ein Teil die Abfrage von DMACONR in der Schleife). Mit BLITHOG („blitter nasty“) 108 ms – der Blitter sperrt den Chip-Bus, jede Registerabfrage der CPU wartet bis zum Blit-Ende; BLITHOG ist für dieses Muster unbrauchbar. Bitplane-DMA aus bringt dem Blitter +47 %, der CPU in Fast RAM nichts.

Korrektheit: Blitter-Ergebnis gegen CPU-Ergebnis bitidentisch (PASS).

## 2. Hypothese „bit-sliced AES auf dem Blitter“ – umgesetzt und gemessen (Nacht 26./27.11.)

**Ergebnis: funktioniert, bitgenau, 4,4 KB/s auf dem Blitter allein – 62 % der CPU-T-Tabellen (7,06 KB/s), aber zusätzlich und parallel.** Erste Rechnung weiter unten zum Vergleich.

Konstruktion (`tools/blitaes/gen_blitaes.py`, `crypto/blit/`, `bench/blitaes_bench.c`, `make run-blitaes`):
* 1024 Blöcke (16 KiB) je Batch. Die Daten liegen als 16 „Zeilen“ k à 1 KiB (Blöcke 64k..64k+63) im Chip-RAM. **Der Blitter transponiert selbst**: vier Stufen Bitmatrix-Transposition (16×16 je Block-Chunk), je Stufe 16 Blits à 512 Wörter: aufsteigend mit Barrel-Shift rechts und Maske über den C-Kanal (Minterm C?B:A), absteigend (DESC) für die Linksverschiebung (Minterm C?A:B). Danach ist Zeile k, Chunk q das Lane-Wort für Bit 15−k des Chunks über 16 Blöcke – genau das Layout, das die Runden brauchen. 80 ms hinein, 60 ms heraus (gegen 1,9 + 2,5 s in C auf der CPU).
* SubBytes: Boyar–Peralta-Schaltung mit 113 Gattern (NIST-SLP, exhaustiv geprüft, U0/S0 = MSB) → 226 Blits à 512 zusammenhängende Wörter je Runde (XOR 0x3C, AND 0xC0, XNOR 0xC3), 29 Temporärpuffer durch Lebensdaueranalyse. 180 ms je Runde.
* ShiftRows kostenlos (Spaltenrotation in den MixColumns-Quelladressen). MixColumns + AddRoundKey spaltenweise: je Lane (Bit, Zeile, Spalte) 5–7 Quell-Lanes als Ketten von 3-Quellen-XOR-Blits (64 Ein-Wort-Zeilen, Modulo 14), der Rundenschlüssel als ein Wort je Lane über den C-Kanal mit Modulo −2 (liest dasselbe Wort 64-mal). 432 Blits je Runde, 82 ms. Schlussrunde 128 Blits, 20 ms. Whitening als ein Blit (Schlüsselmuster über B-Modulo −128).
* Verifikation: Software-Blitter-Modell auf dem Host (Shifts, DESC, Modulos, Minterme) → AES-128/256 gegen die Byte-Referenz, dann identisches Programm auf dem echten Blitter (FS-UAE): 1024 Blöcke bitgenau, erster Hardware-Lauf.

| Phase (16 KiB, AES-256, Display an) | Zeit |
|---|---:|
| Schlüssel-Lanes + Masken (CPU) | 140 ms |
| Kopie hinein (CPU, C) | 140 ms |
| Whitening + Transposition (65 Blits) | 80 ms |
| 14 × SubBytes (226 Blits à 512 Wörter) | 14 × 180 ms |
| 13 × MixColumns+Key (432 Blits à 64 Wörter) | 13 × 82 ms |
| Schlussrunde (128 Blits) | 20 ms |
| Transposition heraus (64 Blits) | 60 ms |
| **Blitter gesamt** | **3,76 s = 4,36 KB/s** |
| Kopie heraus (CPU, C) | 160 ms |
| CPU-T-Tabellen zum Vergleich (1024 Blöcke) | 2,32 s = 7,06 KB/s |

Einordnung: Mit C-Setup kostet jeder Blit ≈ 900 Takte Overhead (bei 1024 Blits je Runde ≈ 0,9 M Takte = 130 ms je Runde – fast die Hälfte der MixColumns-Zeit); ein Assembler-Executor (≈ 250 Takte) ist der nächste Schritt, danach Copper-Steuerung (0 % CPU) und Display-DMA-Abschaltung (+40 % Blitter-Durchsatz). CPU und Blitter zusammen: ≈ 11 KB/s AES-256 für Medien statt 7. Nicht umsonst: ≈ 100 KiB Chip-RAM, zwei AES-Implementierungen.

## 2a. Erste Rechnung (vor der Umsetzung)

Anordnung: ein 16-Bit-Wort trägt dasselbe Bit derselben Bytes aus 16 Blöcken; eine S-Box-Gatteroperation über alle 16 Bytepositionen ist ein Blit über 16 Wörter je 16 Blöcke. Für 1024 Blöcke (16 KiB) also 1024-Wort-Blits à 2,06 ms (1,40 ms ohne Display). Boyar-Peralta-S-Box: 113 Gatter; MixColumns + AddRoundKey mit 3-Quellen-XOR ≈ 256 Blits; ShiftRows kostenlos (Adress-Umbenennung).

* je Runde ≈ 370 Blits × 2,06 ms = 0,76 s je 16 KiB; 14 Runden = 10,7 s → **1,5 KB/s** (2,2 KB/s ohne Display).
* CPU-T-Tabellen (gemessen): AES-256-GCM 5,45 KB/s, reines AES-CTR ≈ 7,5 KB/s.

Ergebnis: Der Blitter wäre **2,5–3,5× langsamer** als die CPU, auch mit Setup in Assembler (die Datenphase dominiert bei 1024 Wörtern). Als *zusätzlicher* Rechner neben der CPU brächte er +30–40 % Gesamtdurchsatz für Medien, bei zwei AES-Implementierungen, Bitslice-Transposition und Copper-Steuerung als Komplexitätspreis. Eine Copper-Liste könnte die Blit-Kette ohne CPU treiben (WAIT mit BFD = 0 wartet auf Blitter-Ende, MOVE schreibt Blitter-Register) – das macht den Blitter zum CPU-freien, aber langsamen AES-Koprozessor. **Entscheidung: nicht umsetzen**, solange die CPU-Variante nicht der Engpass eines echten Nutzungsfalls ist. Nachgewiesen ist nur, dass es ginge und was es brächte.

## 3. Hypothese „Blitter für die Kurvenarithmetik“ – verworfen ohne Messung

X25519/Ed25519 bestehen aus 16×16-Bit-Multiplikationen (MULU, 256 je Feldmultiplikation, ≈ 20 k Takte). Der Blitter hat keinen Addierer – nur 3-Quellen-Boolesche Funktionen, Schieber und Füllmodus. Eine Multiplikation wäre Shift-and-Add mit bitseriellem Übertrag (Addition selbst ≈ 16 Durchläufe je Wort). Größenordnung 100× langsamer als MULU. Copper und Paula rechnen gar nicht.

## 4. Wo Custom Chips tatsächlich zählen

1. **WebSocket-Maskierung** (4-Byte-XOR über jeden Client-Frame): Blit mit B-Kanal auf eine 4-Byte-Maske mit Modulo −4 – ein Blit je Frame, 4× schneller als die CPU-Schleife, nebenläufig. Klein, aber kostenlos.
2. **CTR-Keystream-XOR und Pufferkopien** im Medienpfad: 3–5× gegenüber CPU, jedoch nur ≈ 10 % der GCM-Zeit (die AES-Blöcke dominieren).
3. **Anzeige**: Der Blitter macht, wofür er gebaut ist – Text/Bitmaps für die UI, während die CPU rechnet. Entscheidend für ein benutzbares Programm bei 8 s je X25519.
4. **Keine Entropie aus CIA/Strahlposition** (ein Quarz, siehe docs/RNG.md); CIA-Timer dienen als Zeitbasis für Timeouts und Zeitstempel von Eingabe-/Netzereignissen.

## 5. Offene Experimente (bei Bedarf)

* Blit-Setup in Assembler messen (erwartet ≈ 300 statt 900 Takte) – relevant nur für kleine Blits.
* Copper-gesteuerte Blit-Kette als Machbarkeitsnachweis (CPU-Last 0 %).
* Echte Hardware: Blitter-Timing ist in FS-UAE zyklengenau modelliert, Chip-RAM-Konflikte mit Bitplane-DMA ebenfalls; eine Bestätigung auf dem A500 steht aus.

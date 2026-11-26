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

## 2. Hypothese „bit-sliced AES auf dem Blitter“ – Rechnung mit den Messwerten

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

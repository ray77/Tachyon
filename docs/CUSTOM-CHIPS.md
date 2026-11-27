# Custom Chips als Krypto-Beschleuniger – Messung und Bewertung

Stand 2026-11-27. Alle Zahlen A500/FS-UAE (accuracy=1), Workbench-1.3-Bildschirm (Hires, 2 Bitplanes), Code und Daten der CPU in Fast RAM, Blitter-Puffer in Chip RAM. Harness: `bench/blitter_bench.c`. README-Vorgabe: Hypothese → Implementierung → Korrektheit → Messung → Vergleich.

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

Einordnung: Mit C-Setup kostet jeder Blit ≈ 900 Takte Overhead. **Assembler-Executor gemessen** (`crypto/m68k/blitexec.s`, BBUSY-Polling + 14 Registerschreibzugriffe, ≈ 250 Takte): MixColumns 82 → 74 ms je Runde, Transposition heraus 80 → 60 ms, SubBytes unverändert 180 ms; gesamt 3,76 → **3,70 s = 4,43 KB/s**. Die Erklärung steht in den Zahlen: 226 SubBytes-Blits à 512 Wörter mit drei Quellen und einem Ziel sind 463 k Chip-RAM-Zugriffe je Runde; bei 180 ms sind das 2,6 M Zugriffe/s – der Blitter ist durch den Chip-Bus begrenzt (3,55 M Zyklen/s abzüglich Display-DMA), nicht durch das Setup. Der Blitter-Pfad ist also **DMA-bandbreitenbegrenzt**; weniger Blits (Setup) bringen nichts mehr, nur weniger Zugriffe (Gatterzahl, Display-DMA aus) oder Nebenläufigkeit (Copper statt CPU). CPU und Blitter zusammen: ≈ 11 KB/s AES-256 für Medien statt 7. Nicht umsonst: ≈ 100 KiB Chip-RAM, zwei AES-Implementierungen.

## 2b. Copper-gesteuerte Blit-Kette – umgesetzt und gemessen (27.11., früh)

**Ergebnis: Der Copper treibt die gesamte AES-Pipeline ohne CPU-Beteiligung je Blit: 2,28 s je 16 KiB = 7,2 KB/s auf dem Blitter allein, die CPU ist dabei zu 90 % frei. Verschlüsselt die CPU nebenher mit ihren T-Tabellen eigene Blöcke, liefern beide zusammen 14,2 KB/s AES-256 – das Doppelte der CPU allein (7,06 KB/s).** Bitgenau gegen die CPU-Referenz in allen sechs Varianten eines Laufs (4 × fe16-Last, 1 × AES-Last, 1 × GHASH-Last).

Konstruktion (`bench/blitaes_bench.c`, Abschnitt „Copper-driven“):
* Je Blit ein Copper-Block von 88 Bytes: `WAIT 0,0` mit BFD = 0 (wartet nur auf Blitter-Ende), 17 MOVEs für BLTCON0/1, Masken, vier Zeiger, vier Modulos und BLTSIZE, zwei NOOP-MOVEs ($1FE), dann `MOVE COP1LCH/L` auf den Folgeblock. Letzteres macht die Kette **VBL-fest**: der Hardware-Neustart des Coppers am Vertical Blank landet im noch nicht ausgeführten Folgeblock; schlimmstenfalls wird ein Blit wiederholt – alle Ketten-Blits sind idempotent (nur das Whitening arbeitet in place und bleibt CPU-gesteuert).
* Terminator: `WAIT` auf Blitter-Ende, `MOVE INTREQ $8400` (AUD3-Bit als Fertig-Flag), `WAIT $FFFF,$FFFE`. Die CPU pollt INTREQR und rechnet dazwischen (fe16_mul, AES-Blöcke oder GHASH – wählbar).
* Fünf Listen je Batch (TIN 64, SBOX 226, MIX 432, FINAL 128, TOUT 64 Blits = 50 KiB Chip-RAM); die MIX-Liste wird je Runde an 13 × 2 Wörtern (Schlüsselzeiger) gepatcht.
* Betriebssystem-Verträglichkeit: COPCON CDANG; `GfxBase->LOFlist/SHFlist` während des Laufs auf eine Leerliste, weil der VBL-Server der graphics.library COP1LC jeden Frame zurückschreibt (die Kette gewinnt, weil sie COP1LC nach jedem Blit selbst setzt); OwnBlitter; keine Konsolenausgabe im Blitter-Besitz. Alles in docs/TOOLCHAIN.md.

| Variante (16 KiB, AES-256, Lauf 25) | Zeit | Blitter | CPU nebenher | CPU frei |
|---|---:|---:|---|---:|
| CPU-Executor (asm), Display an | 3,70 s | 4,43 KB/s | – | 0 % |
| Copper-Kette, Bitplane-/Sprite-DMA aus, CPU rechnet fe16_mul (3 Wiederholungen) | **2,28 s** | **7,2 KB/s** | 693 fe16_mul | 90 % |
| Copper-Kette, CPU verschlüsselt eigene AES-Blöcke | 2,28 s | 7,2 KB/s | 993 Blöcke = 15,5 KiB | 91 % |
| **→ kombiniert Blitter + CPU** | 2,28 s | | | **14,2 KB/s AES-256** |
| Copper-Kette, CPU rechnet GHASH | 2,28 s | 7,2 KB/s | 3170 GHASH-Blöcke (1390/s = 22 KB/s) | 77 % |

Lesart: Die Copper-Kette ist nicht nur CPU-frei, sie ist auch schneller als der CPU-Executor (kein 250-Takte-Setup zwischen den Blits, der Blitter läuft lückenlos). Die 90 % freie CPU sind real nutzbar: mit AES-Last verschlüsselt sie in derselben Zeit fast so viel wie der Blitter. GHASH nebenher verliert mehr (77 %), weil seine Tabellenzugriffe mit dem Blitter um den Bus konkurrieren (Tabellen im Fast RAM, Daten im Chip-RAM). Damit ist für GCM auf Medien eine Aufteilung sinnvoll: Blitter rechnet den CTR-Keystream eines Batches, die CPU rechnet GHASH über alle Blöcke plus eigene AES-Blöcke – geschätzt ≈ 9–10 KB/s GCM statt 5,45.

**CTR-Batch ohne Transposition (Lauf 26, PASS):** Die CPU schreibt die Lanes der 1024 Zählerblöcke direkt ins transponierte Layout (`ba_ctr_lanes`: 96 Nonce-Lanes konstant, 32 Zähler-Lanes aus zwei 26-Wort-Tabellen, Rundenschlüssel 0 eingefaltet), die Kette startet bei SBOX, am Ende ein XOR-Blit Keystream ⊕ Klartext über 8192 Wörter. Gemessen: Lanes 180 ms (C), Kette ohne TIN 2240 ms, XOR-Blit 20 ms → 2,44 s = 6,7 KB/s, kombiniert mit CPU-Blöcken 13,1 KB/s. Noch kein Gewinn gegenüber der Transposition (TIN kostete nur 40 ms, die Kopie 140 ms; die Lanes in C kosten 180 ms) – der Gewinn kommt erst mit den Lanes in Assembler (8192 Wortschreibzugriffe ≈ 20 ms, erwartet −7 %). Wichtiger ist der strukturelle Effekt: der Klartext muss nicht mehr in das Arena kopiert werden, der Chiffretext entsteht mit einem Blit, und die Pipeline ist genau die für AES-GCM auf dem Medienpfad.

Display-DMA: In Lauf 21/23 lief die Kette mit Display an in 3,40 s (4,8 KB/s) und mit abgeschalteter Bitplane-DMA in 2,38 s; die Einzelliste S-Box maß 8 gegen 6 Ticks (Bitplane-DMA kostet den Blitter ≈ 30 %). In Lauf 25/26 war die Display-an-Variante genauso schnell wie Display aus, obwohl DMACONR BPLEN zeigt (0x03F0) – der Bitplane-Abruf findet offenbar nicht statt, sobald die System-Copperliste (BPLCON0, Zeiger, Fenster je Frame) nicht mehr läuft. Praktisch: Sobald die Kette den Copper hat, ist die Anzeige ohnehin aus; offen bleibt nur die genaue Ursache. Für den Betrieb heißt es ohnehin: während eines Medientransfers kann die Anzeige auf eine Copper-Farbfläche ohne Bitplanes reduziert werden (Fortschritt als Farbbalken per Copper-Liste, kostet keine DMA).

Fehler auf dem Weg (jeder kostete einen FS-UAE-Lauf, zusammen eine Nacht): Konsolen-Write im Blitter-Besitz (Deadlock), COPER-Flag von der Systemliste gesetzt, zweimal falsch gezählte Blockgröße (Blöcke überlappen → kein COP1LC-Update → Endlosschleife ab dem VBL), Diagnose-Blits, die die Schlüssel-Lanes im Arena überschrieben (danach verglichen Copper und Executor denselben Schrott erfolgreich), Rücktransposition mit der falschen Liste. Methode, die am Ende zog: eine Sektion nach der anderen per Copper ausführen, Rest per Executor, Ergebnis vergleichen (Hybridtest).

## 2c. AES-GCM-Bibliothek auf der Copper-Kette – umgesetzt und gemessen (27.11., vormittags)

**Ergebnis: `crypto/blit/blitgcm.c` liefert AES-256-GCM mit 9,1 KB/s gegen 5,56 KB/s auf der CPU allein (+63 %), bitgenau gegen `aes_gcm_encrypt/decrypt` auf dem Host (168 Fälle) und auf FS-UAE (40000 Byte + AAD, 64 KiB in drei Varianten). Ohne CPU-Eigenblöcke 7,0 KB/s.** Erwartung vorab (Abschnitt 2b): 9–10 KB/s; die Messung liegt am unteren Rand.

Konstruktion (`crypto/blit/blitgcm.h/.c`, `crypto/m68k/blitgcm.s`, Harness `bench/blitgcm_bench.c`, `make run-blitgcm`, Host-Test `tests/blitgcm_test.c`):
* API: `blitgcm_init(ctx, aes_gcm_key*, Arena 100 KiB Chip, Copper-Listen 73 KiB Chip)`, `blitgcm_encrypt/decrypt` mit genau der Signatur und Semantik von `aes_gcm_encrypt/decrypt` (IV 12 Byte, AAD, Tag 16 Byte, in/out dürfen aliasen). Einzige Abweichung: `blitgcm_decrypt` schreibt den Klartext schon während der Kette und nullt ihn bei Tag-Fehler (Vergleich constant-time), statt ihn gar nicht zu schreiben.
* Batch = 1024 Blöcke. Die CPU schreibt die 128 Zählerlanes direkt ins transponierte Layout (`bg_ctr_fill_asm`: 96 Nonce-Lanes als 8 Zeilen je Byte, 32 Zähler-Lanes je Wort aus zwei 26-Wort-Tabellen; 8192 Wortschreibzugriffe): **20 ms statt 140 ms in C**, Ergebnis bitgleich mit der C-Variante (im Harness geprüft).
* Copper-Kette ab SBOX: die SBOX-Liste springt mit `MOVE COP1LC`/`MOVE COPJMP1` direkt in die MIX-Liste, erst deren Terminator setzt das AUD3-Flag; FINAL springt ebenso nach TOUT. Je Batch **14 statt 29 CPU-Neustarts** (Rundenschlüssel-Zeiger werden zwischen den Runden an 128 Stellen gepatcht, der SBOX-Terminator für die Schlussrunde auf FINAL umgebogen). Kette je 16 KiB: 2,10 s (Harness mit 29 Neustarts: 2,24 s).
* Timeout ohne DOS: der Poller zählt Rasterdurchläufe über VPOSR/VHPOSR; nach 150 Frames je Abschnitt (normal ≈ 12) parkt er den Copper, zählt `timeouts` hoch und rechnet den Batch auf der CPU nach – das Ergebnis bleibt korrekt, nur langsamer.
* Chiffretext = Keystream ⊕ Klartext: liegen Klartext und Chiffretext im Chip-RAM, ein Blit (A = Keystream, B = Klartext, D = Chiffretext, 8 Wörter je Zeile, 20 ms je 16 KiB); sonst `bg_xor_asm` auf der CPU mit `movem` (≈ 33 ms je 16 KiB). Kopieren-Blit-Zurückkopieren wäre langsamer (≈ 45 ms) und bräuchte 16 KiB Chip-Puffer.
* Während die Kette läuft, pollt die CPU das Flag zwischen Arbeitseinheiten: erst GHASH (AAD, dann Chiffretext von Batch n−1 bzw. beim Entschlüsseln gleich den aktuellen Batch – der Chiffretext ist ja bekannt), dann **eigene Blöcke** hinter dem Batch mit den T-Tabellen, so viele wie die Kette dauert (dynamische Aufteilung, im 64-KiB-Lauf 341 je Batch). Der nächste Batch beginnt hinter den CPU-Blöcken.
* Rest < 1024 Blöcke: lohnt eine Kette noch? Faustregel aus den Zahlen (Kette 2,1 s gegen 2,86 ms je CPU-Block abzüglich unter der Kette versteckbarem GHASH): ab R > 1000 − pending/4 Blöcken (und R ≥ 512) Teil-Batch, der Blitter nimmt R − min(R/2, 400), die CPU den Rest; sonst CPU. J0/Längenblock/Tag immer CPU.
* OwnBlitter, Bitplane-/Sprite-DMA aus, LOFlist/SHFlist geparkt, CDANG – alles innerhalb des Aufrufs, keine Konsolenausgabe dazwischen; die Bibliothek restauriert am Ende (WaitTOF, DisownBlitter).

| 64 KiB AES-256-GCM, Lauf 1 | Zeit | Durchsatz | davon Kette / Lanes / XOR / Schluss |
|---|---:|---:|---|
| CPU `aes_gcm_encrypt` (T-Tabellen + GHASH asm) | 11,78 s | 5,56 KB/s | – |
| Blitter-Kette + GHASH, keine CPU-Blöcke (4 Batches) | 9,36 s | 7,0 KB/s | 8,38 / 0,16 / 0,12 / 0,60 s |
| **Blitter-Kette + GHASH + CPU-Eigenblöcke (3 Batches + 1024 CPU-Blöcke)** | **7,22 s** | **9,1 KB/s** | 6,30 / 0,12 / 0,10 / 0,62 s |
| dito, Puffer im Chip-RAM (XOR-Blit) | 7,18 s | 9,1 KB/s | 6,30 / 0,12 / 0,02 / 0,64 s |
| 40000 B + 20 B AAD, verschlüsseln (1 voller + 1 Teil-Batch, 993 CPU-Blöcke) | 5,14 s | 7,8 KB/s | Schluss 0,74 s |
| 40000 B, entschlüsseln (2 volle Batches, 452 CPU-Blöcke) | 4,38 s | 9,1 KB/s | Schluss 0 s |
| CPU `aes_gcm_encrypt` 40000 B | 7,20 s | 5,56 KB/s | – |

Lesart: Die CPU ist unter der Kette voll beschäftigt (GHASH ≈ 1000 Blöcke + 341 AES-Blöcke in 2,1 s), die Kette selbst ist mit 2,10 s je 16 KiB die Untergrenze dieser Pipeline. Der Schlussteil (GHASH des letzten Batches, 0,6 s = 8 %) ist beim Verschlüsseln unvermeidbar seriell, beim Entschlüsseln entfällt er – deshalb ist Entschlüsseln (Medien-Download!) mit 9,1 KB/s schon bei 40 KB so schnell wie Verschlüsseln bei 64 KB. Der XOR-Blit spart gegenüber der CPU nur 80 ms je 64 KiB; Chip-RAM für Medienpuffer lohnt dafür nicht. Chip-RAM-Bedarf der Bibliothek: 173 KiB.

Was noch ginge (nicht umgesetzt): 96 Nonce-Lanes vom Copper füllen statt von der CPU (−10 ms je Batch), MIX-Liste frei laufen lassen mit Schlüssel-Patch im Schatten der SBOX-Liste (−14 Neustarts, Risiko bei Verdrängung der CPU), Display-DMA-Anteil je Lauf messen. Größerer Hebel bleibt die Gatterzahl der S-Box (Abschnitt 5).

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

* ~~Blit-Setup in Assembler~~ gemessen: 3,76 → 3,70 s, der Blitter ist DMA-begrenzt.
* ~~Copper-gesteuerte Blit-Kette~~ umgesetzt: 6,9 KB/s bei 87 % freier CPU (Abschnitt 2b).
* ~~CTR-Zählerblöcke direkt als Lanes erzeugen~~ umgesetzt (Abschnitt 2b/2c): 20 ms in Assembler statt Kopie + Transposition.
* ~~AES-GCM-Bibliothek auf der Kette~~ umgesetzt: 9,1 KB/s (Abschnitt 2c).
* Weniger Blitter-Zugriffe statt weniger Blits: S-Box-Gatter mit drei Eingängen (A^B^C, Minterm 0x96) statt Zweier-XOR-Ketten, MixColumns-Termteilung.
* Echte Hardware: Blitter-Timing ist in FS-UAE zyklengenau modelliert, Chip-RAM-Konflikte mit Bitplane-DMA ebenfalls; eine Bestätigung auf dem A500 steht aus.

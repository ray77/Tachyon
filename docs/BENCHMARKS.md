# WhatsBench – Messprotokoll

Alle Werte aus FS-UAE 3.2.35 mit `accuracy = 1`, A500/OCS, 68000 @ 7,09 MHz PAL, Kickstart 1.3 rev 34.5, 512 KiB Chip + 1 MiB Fast. Code lief aus Fast-RAM (Loader-Default bei `MEMF_ANY`). Zeitbasis `DateStamp()` (1 Tick = 20 ms), Wiederholungen so gewählt, dass der Quantisierungsfehler < 1 % bleibt. Noch keine Messung auf echter Hardware.

## 2026-11-26 – Baseline: portable C-Referenz (`crypto/ref/x25519_ref.c`, vbcc 0.9h `-O=1023 -speed -cpu=68000`)

| Operation | Zeit/Op | Takte/Op (≈) | n |
|---|---:|---:|---:|
| X25519 (RFC 7748 5.2 #1) | 43,56 s | 309 M | 1 |
| X25519 (RFC 7748 6.1 shared) | 45,72 s | 324 M | 1 |
| `fe16_mul` (16×16 Limbs, Comba in C) | 16,16 ms | 114,6 k | 2000 |
| `fe16_sqr` (= mul) | 15,67 ms | 111,1 k | 2000 |
| `fe16_add` | 0,88 ms | 6,2 k | 20000 |
| `fe16_sub` | 1,31 ms | 9,3 k | 20000 |
| `fe16_mul121665` | 1,38 ms | 9,8 k | 20000 |

Korrektheit auf dem Ziel: RFC 7748 5.2 #1 und 6.1 bestanden (`RESULT: all vectors passed`).

### Einordnung

- Eine X25519-Operation besteht aus ca. 1300 Multiplikationen + 1270 Quadrierungen + 255 × (4 Add/Sub + 1 Mul121665). Mit den gemessenen Einzelwerten: 1300 × 16,2 + 1270 × 15,7 + 255 × 5,8 ≈ 42 s – deckt sich mit der Gesamtmessung; der Overhead liegt fast vollständig in `fe16_mul`.
- 256 MULU.W kosten auf dem 68000 mindestens 256 × 38…70 Takte ≈ 10–18 k Takte. Die C-Variante braucht 115 k Takte, also 6–11× zu viel: Schleifenverwaltung, Indexrechnung und die 64-Bit-Spaltensumme in C (Vergleich statt ADDX) dominieren.
- Realistisches Ziel für Hand-Assembler (`CPU000`): `fe16_mul` ≈ 20–25 k Takte (≈ 3 ms), `fe16_sqr` ≈ 60 % davon → X25519 ≈ 5–7 s. Noise XX braucht clientseitig 2–3 DH-Operationen → 10–20 s Handshake-Anteil. Ob das in WhatsApps Zeitlimits passt, ist offen (README, Risiken).

## 2026-11-26 – Schritt 1: `fe16_mul` in Assembler (`crypto/m68k/fe16_mul.s`, erzeugt von `tools/gen_fe16_mul.py`)

Comba, Radix 2^16, 256 × `move.w (a0)+ / mulu.w -(a1) / add.l / addx.w`, 48-Bit-Akkumulator in d0/d1, Reduktion `r_lo + 38·r_hi` mit `mulu.w #38`, zwei volle Faltungsdurchläufe. Argumente per vbcc `__reg` in a0/a1/a2. Gleiche Konfiguration wie Baseline.

| Operation | Zeit/Op | Takte/Op (≈) | n | Faktor zur Baseline |
|---|---:|---:|---:|---:|
| X25519 (beide Vektoren) | 12,28 s | 87 M | 1 | 3,5× |
| `fe16_mul` (asm) | 3,81 ms | 27,0 k | 5000 | 4,1× |
| `fe16_mul_c` (C, Vergleich) | 15,74 ms | 111,6 k | 2000 | – |
| `fe16_sqr` (= asm mul) | 3,66 ms | 26,0 k | 2000 | 4,3× |
| `fe16_add` (C) | 0,88 ms | 6,2 k | 20000 | – |
| `fe16_sub` (C) | 1,31 ms | 9,3 k | 20000 | – |
| `fe16_mul121665` (C) | 1,38 ms | 9,8 k | 20000 | – |

Korrektheit: asm == C limb-für-limb auf 1000 Inputs (Zufall, 0xFFFF-Limbs, Null/Eins), RFC 7748 5.2 #1 und 6.1 bestanden.

### Aufschlüsselung der 12,3 s

| Anteil | Rechnung | Zeit |
|---|---|---:|
| Mul + Sqr (asm) | ≈ 2570 × 3,7 ms | ≈ 9,5 s |
| Add/Sub/Mul121665 (C) | 255 × (4 × 0,88 + 4 × 1,31 + 1,38) ms | ≈ 2,6 s |
| Rest (cswap, Ladder-Overhead) | | ≈ 0,2 s |

Nächste Hebel in dieser Reihenfolge: dedizierte Quadrierung (136 statt 256 Produkte, ≈ −1,8 s), Add/Sub/Mul121665 in Assembler (≈ −2,2 s), Reduktion/Faltung in `fe16_mul` verschlanken (≈ −0,5 s). Prognose danach ≈ 7–8 s pro X25519.

## 2026-11-26 – Schritt 2: dedizierte Quadrierung `fe16_sqr` (asm, `crypto/m68k/fe16.s`)

120 Kreuzprodukte f[i]·f[j] (i<j) pro Spalte einmal gebildet, Summe verdoppelt (`add.l d0,d0 / addx.w d1,d1`), dann Übertrag der Vorspalte (in d4 geparkt, darf nicht mitverdoppelt werden) und Quadratterm f[k/2]² addiert: 136 statt 256 MULU.W. Reduktion/Faltung wie bei `fe16_mul`.

| Operation | Zeit/Op | Takte/Op (≈) | n | Faktor zur Baseline |
|---|---:|---:|---:|---:|
| X25519 (beide Vektoren) | 10,60 s | 75 M | 1 | 4,1× |
| `fe16_mul` (asm) | 3,72 ms | 26,4 k | 5000 | 4,3× |
| `fe16_sqr` (asm) | 2,39 ms | 17,0 k | 2000 | 6,6× |
| `fe16_add` / `fe16_sub` / `fe16_mul121665` (C) | 0,88 / 1,31 / 1,38 ms | | 20000 | – |

Korrektheit: `fe16_sqr` asm == C limb-für-limb auf 1000 Inputs, RFC 7748 bestanden. Ein erster Generator-Stand verdoppelte den Spaltenübertrag mit (968/1000 Fehler; genau die 32 Ein-Limb-Fälle mit Übertrag 0 bestanden) – vom Vergleichstest sofort gefangen.

Aufschlüsselung der 10,6 s: Mul ≈ 1300 × 3,72 = 4,8 s; Sqr ≈ 1270 × 2,39 = 3,0 s; Add/Sub/Mul121665 in C ≈ 2,6 s. Letztere sind jetzt ein Viertel der Laufzeit.

## 2026-11-26 – Schritt 3: `fe16_add`, `fe16_sub`, `fe16_mul121665` in Assembler

Add: ADDX-Kette über 16 Limbs. Sub: f + (2^256−76) per ADDX-Kette, dann − g per SUBX-Kette, Vielfache von 2^256 = c1 + 1 − b. Mul121665: 16 × `mulu.w #56129`, der 2^16-Anteil wandert als Limb in den Übertrag. Faltungen: wo 38·c ≤ 76 gilt, als billige X-Flag-Kette (`add.w` + 15 × `addx.w`), sonst ein Long-Durchlauf. Semantik identisch zu C.

| Operation | C | asm | Takte asm (≈) | Faktor |
|---|---:|---:|---:|---:|
| X25519 | – | **8,59 s** | 61 M | 5,1× zur Baseline |
| `fe16_add` | 0,88 ms | 0,203 ms | 1,44 k | 4,3× |
| `fe16_sub` | 1,31 ms | 0,258 ms | 1,83 k | 5,1× |
| `fe16_mul121665` | 1,38 ms | 0,432 ms | 3,06 k | 3,2× |
| `fe16_mul` | 15,74 ms | 3,72 ms | 26,4 k | 4,2× |
| `fe16_sqr` | – | 2,38 ms | 16,9 k | – |

Korrektheit: alle fünf Routinen limb-für-limb gleich der C-Version auf je 1000 Inputs (Zufall, 0xFFFF-Limbs, dünn besetzt), RFC 7748 5.2 #1 und 6.1 bestanden.

### Aufschlüsselung der 8,6 s

| Anteil | Rechnung | Zeit |
|---|---|---:|
| `fe16_mul` | 1300 × 3,72 ms | 4,84 s |
| `fe16_sqr` | 1270 × 2,38 ms | 3,02 s |
| Add/Sub/Mul121665 | 255 × (4 × 0,203 + 4 × 0,258 + 0,432) ms | 0,58 s |
| Ladder-Overhead, cswap, Aufrufe (C) | | ≈ 0,16 s |

### Wo die Untergrenze dieses Ansatzes liegt

Ein Produkt kostet `move.w (a0)+ / mulu.w -(a1) / add.l / addx.w` ≈ 8 + (38 + 2·Einsen + 6) + 8 + 4 ≈ 80 Takte bei zufälligen Operanden; 256 Produkte ≈ 21 k der 26,4 k Takte von `fe16_mul`. Der Rest (Spaltenwechsel ≈ 1,2 k, Reduktion ≈ 1,1 k, zwei Faltungen ≈ 1,2 k, Prolog) ist mit ≈ 0,4 k Ersparnis (X-Flag-Faltungen) fast ausgereizt. Karatsuba (eine Ebene, 192 Produkte) spart netto ≈ 3 k Takte pro Multiplikation (≈ −0,5 s), bei der Quadrierung praktisch nichts. Realistische Untergrenze dieser Architektur: **≈ 7,5 s pro X25519** auf 7,09 MHz. Weitere Faktoren gibt es nur noch über weniger Feldoperationen, nicht über schnellere.

Konsequenz für den Verbindungsaufbau: Schlüsselpaare (Basispunkt-Multiplikationen) lassen sich offline im Leerlauf vorberechnen. Online bleiben die DH-Operationen des Noise-Handshakes (XX: 2–3, IK bei Wiederverbindung: 2) → 17–26 s bei 8,6 s/Op. Ob WhatsApp das toleriert, entscheidet die Protokollrecherche (Phase 1), nicht weitere Mikrooptimierung.

## 2026-11-26 – Schritt 4: Karatsuba (eine Ebene) für `fe16_mul`

`_fe16_mul_kara`: f = f0 + 2^128·f1, g analog (je 8 Limbs). z0 = f0·g0, z2 = f1·g1, m = (f0+f1)(g0+g1) mit den beiden 9. Limbs als maskierte Korrekturen (konstante Laufzeit), z1 = m − z0 − z2 (17 Limbs), r[8..] += z1. 192 statt 256 MULU.W, dafür ≈ 110 zusätzliche Wort-Add/Sub mit Carry und ein 132-Byte-Stackrahmen. Beide Varianten bleiben im Generator; `_fe16_mul` ist ein `equ`-Alias auf die gewählte.

| Operation | Comba | Karatsuba | Differenz |
|---|---:|---:|---:|
| `fe16_mul` | 3,728 ms (26,4 k Takte) | **3,472 ms (24,6 k Takte)** | −6,9 % (−1,8 k Takte; Prognose −2,4 k) |
| X25519 | 8,60 s | **8,28 s** | −0,32 s |

Korrektheit: beide Varianten limb-für-limb gleich der C-Version auf 1000 Inputs, RFC 7748 bestanden. Karatsuba ist jetzt Standard. Zweite Ebene (4-Limb-Blöcke) lohnt nicht: 144 Produkte sparen weitere 48 × 80 ≈ 3,8 k, der Verwaltungsaufwand verdoppelt sich aber auf ≈ 5 k.

Aufschlüsselung der 8,28 s: Mul 1300 × 3,47 = 4,51 s; Sqr 1270 × 2,38 = 3,02 s; Add/Sub/Mul121665 0,58 s; Ladder in C ≈ 0,16 s.

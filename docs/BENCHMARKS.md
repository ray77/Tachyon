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

## 2026-11-26 – Schritt 5: SHA-512, Ed25519- und XEdDSA-Verifikation (Baseline, C auf asm-Feldarithmetik)

Neu: `crypto/ref/sha512.c` (32-Bit-Wortpaare, kein 64-Bit-Runtime), `crypto/ref/ed25519.c` (erweiterte Edwards-Koordinaten, ref10-Formeln: Addition 9M, Verdopplung 4M+4S; Dekodierung mit `pow22523`; `sc_reduce` als TweetNaCl-`modL` in int32; Shamir-Doppel-Skalarmultiplikation ohne Fenster; XEdDSA-Konvertierung wie libsignal). Alles variable Laufzeit, da nur öffentliche Daten. Host: RFC 8032 (4 Vektoren + Negativtests), 64 Go-`crypto/ed25519`-Vektoren (48 gültig/16 manipuliert), 64 libsignal-`CalculateSignature`-Vektoren (48/16), 32 SHA-512-Vektoren – alle bestanden.

| Operation | Zeit/Op | Takte (≈) | Anmerkung |
|---|---:|---:|---|
| `ed25519_verify` (RFC 8032 TEST 3) | **14,80 s** | 105 M | 256 Verdopplungen ≈ 6,0 s, ≈ 192 Additionen ≈ 6,0 s, Dekodierung + 1 Inversion ≈ 1,3 s |
| `xeddsa_verify` (libsignal-Vektor) | **15,70 s** | 111 M | + Montgomery→Edwards-Inversion ≈ 0,65 s, Punkt A liegt anders |
| `sha512` (1 Block, C) | 67,4 ms | 478 k | vbcc-C mit 32-Bit-Paaren; 2–3 Blöcke pro Verifikation |
| X25519 (Kontrolle) | 8,26 / 8,28 s | | unverändert |

Korrektheit auf dem Ziel: SHA-512("abc"), RFC 8032 TEST 3, libsignal-Vektor, manipulierte Signatur abgelehnt.

Noise-Handshake online heute: 3 × 8,3 + 2 × 15,7 ≈ **56 s** (mit gepinntem Zwischenzertifikat ≈ 41 s).

Nebenbefund: `fe16_sub` war bei `h == g` nicht alias-sicher (C und asm schrieben h vor dem Subtrahieren). Reihenfolge getauscht (erst f − g, dann + 2^256 − 76), Ergebnisbits unverändert; alle fe16-Operationen sind jetzt für jede Alias-Kombination sicher. X25519 war nicht betroffen (kein `h == g` im Ladder-Code).

### Nächste Hebel für die Verifikation (Erwartung)

| Maßnahme | Ersparnis |
|---|---:|
| Verdopplung 3M+4S statt 4M+4S | 256 × 3,5 ms ≈ 0,9 s |
| Festbasis-Tabelle für B (4-Bit-Fenster, 512 Niels-Punkte ≈ 48 KiB, gemischte Addition 7M) statt Shamir-Anteil | ≈ 2,5 s |
| wNAF (w = 5) für A: 52 statt ≈ 128 Additionen | ≈ 2,3 s |
| Ziel | ≈ 9–10 s pro Verifikation |

## 2026-11-26 – Schritt 6: Verifikation mit Fenstern und Festbasis-Tabelle

`ge_double_scalarmult` nach ref10-Struktur: Verdopplung als p1p1 (4S + 3M, T nur berechnet, wenn eine Addition folgt), A über 8 gecachte ungerade Vielfache (Sliding Window w = 5, 8M je Addition), B über die hostseitig erzeugte Tabelle `crypto/ref/ed25519_btable.h` (B, 3B, …, 63B als affine Niels-Tripel, w = 7, 3 KiB, gemischte Addition 7M). Tabelle unabhängig mit reiner Python-Kurvenarithmetik geprüft.

| Operation | vorher | jetzt |
|---|---:|---:|
| `ed25519_verify` | 14,80 s | **9,34 s** |
| `xeddsa_verify` | 15,70 s | **9,98 s** |

Aufschlüsselung (XEdDSA): ≈ 253 Verdopplungen à 3M+4S ≈ 20 ms → 5,0 s; ≈ 43 A-Additionen à 8M ≈ 28 ms → 1,2 s; ≈ 32 B-Additionen à 7M ≈ 24 ms → 0,8 s; T-Vervollständigungen ≈ 0,3 s; Tabelle für A (1 Verdopplung + 7 Additionen) ≈ 0,25 s; drei Exponentiationen (Montgomery→Edwards-Inversion, Wurzel beim Dekodieren, Inversion beim Kodieren) ≈ 1,9 s; SHA-512 ≈ 0,2 s.

Noise-Handshake online damit: 3 × 8,3 + 2 × 10,0 ≈ **45 s** (mit gepinntem Zwischenzertifikat ≈ 35 s).

Fund dabei: Der KS-1.3-CLI-Stack (4000 Bytes) reichte für `xeddsa_verify` nicht mehr; `startup.s` schaltet jetzt auf einen eigenen 64-KiB-Stack (siehe `docs/TOOLCHAIN.md`).

Verbleibende Hebel bei der Verifikation: Verdopplungen dominieren (50 %) und lassen sich bei variabler Basis nicht reduzieren; die drei Exponentiationen (19 %) ließen sich auf zwei drücken, wenn `ge_tobytes` entfällt und stattdessen R dekodiert und projektiv verglichen wird – gleiche Kosten, kein Gewinn. Realistische Untergrenze ≈ 9 s, solange `fe16_mul` 3,5 ms braucht.

## 2026-11-26 – Schritt 7: Faltungen in mul/sqr als X-Flag-Ketten; symmetrische Primitive in C (Baseline)

Beide Faltungsdurchläufe nach der Reduktion in `fe16_mul`/`fe16_sqr` laufen jetzt als `add.w` + 15 × `addx.w` (38·c < 1482 passt ins Wort). Bitidentisch (Vergleichstest), −2 % je Multiplikation.

| Operation | vorher | jetzt |
|---|---:|---:|
| `fe16_mul` (Karatsuba) | 3,47 ms | **3,40 ms** |
| X25519 | 8,28 s | **8,08 s** |
| `ed25519_verify` | 9,34 s | **9,10 s** |
| `xeddsa_verify` | 9,98 s | **9,72 s** |

Symmetrische Primitive, portable C mit vbcc (`crypto/ref/sha256.c`, `crypto/ref/aes.c`), Korrektheit auf dem Ziel bestätigt (SHA-256("abc"), GCM-Testfall 2):

| Primitive (C) | Durchsatz | Einordnung |
|---|---:|---|
| SHA-256 | 3,5 KB/s (≈ 18 ms/Block, 130 k Takte) | unbrauchbar; Assembler erwartet ≈ 30 k Takte/Block |
| HMAC-SHA256 | 2,95 KB/s | folgt SHA-256 |
| AES-256 Blockverschlüsselung | 15,3 ms/Block (≈ 108 k Takte) | byteweise S-Box/xtime in vbcc-C ist 20–30× zu langsam; Ziel mit T-Tabellen ≈ 4–5 k Takte |
| AES-256-GCM | 250 B/s | GHASH bitweise (128 Schiebeschritte je Block) dominiert; 4-Bit-Tabelle nötig |
| AES-256-CBC Entschlüsselung | 100 B/s | InvMixColumns mit `gmul`-Schleifen; nur Referenz |

Noise-Frames sind klein (wenige hundert Bytes), Medien später groß: AES-GCM und SHA-256 sind damit nach der Kurvenarithmetik die nächsten Assembler-Kandidaten – und die ersten Kandidaten für das Blitter-Experiment (AES-Bitslicing, GHASH-XOR), weil hier der CPU-Baseline-Vergleich jetzt vorliegt.

## 2026-11-26 – Schritt 8: Festbasis-Comb, SHA-256- und AES/GHASH-Assembler

Alle Werte A500/FS-UAE (accuracy=1), DateStamp-Ticks, alle Vektorprüfungen bestanden (`make vamos` und FS-UAE).

| Operation | vorher (C) | jetzt | Faktor |
|---|---:|---:|---:|
| X25519-Schlüsselerzeugung (`x25519_base_comb`, 64×8 Comb-Tabelle 254 KB, constant-time) | 8,08 s (Leiter) | **3,06 s** | 2,6 |
| SHA-256 (`_sha256_block` asm, 1 KiB-Durchsatz) | 3,85 KB/s | **9,9 KB/s** | 2,6 |
| HMAC-SHA256 | 2,95 KB/s | 8,35 KB/s | 2,8 |
| AES-256 Blockverschlüsselung (T-Tabellen, 4 KiB) | 15,6 ms | **2,04 ms** (≈ 14,5 k Takte) | 7,7 |
| AES-256 Blockentschlüsselung (äquivalente inverse Chiffre) | ≈ 150 ms | **2,28 ms** | 66 |
| GHASH-Block (Shoup, 8-Bit-Tabellen, 2 Byte je Schritt) | ≈ 50 ms | **0,56 ms** (≈ 4 k Takte) | 90 |
| AES-256-GCM (1 KiB) | 250 B/s | **5,45 KB/s** | 22 |
| AES-256-CBC Entschlüsselung (1 KiB) | 100 B/s | **6,7 KB/s** | 67 |
| GCM-Schlüsselaufbau (Key-Schedule + 10 KiB GHASH-Tabellen) | – | 100 ms | einmalig je Sitzungsschlüssel |

Einordnung:
* Comb-Keygen 3,06 s statt der erwarteten ≈ 2,3 s: 64 Fenster × (8 Tabelleneinträge laden + maskiert auswählen + 7M-Addition); die Auswahl in C (3 × 8 × fe16_cmov + frombytes) kostet ≈ 0,8 s. Kandidat für Assembler, wenn Schlüsselerzeugung im Vordergrund läuft; die 812 Prekeys beim Pairing brauchen so ≈ 41 min im Hintergrund.
* SHA-256 asm: 6,1 ms je Block ≈ 43 k Takte, erwartet waren ≈ 30 k. Rotationen kosten auf dem 68000 2 Takte je Bit; der Nachrichtenfahrplan allein (48 × σ0/σ1) liegt bei ≈ 12 k Takten. Tuning zurückgestellt (HMAC/HKDF im Handshake sind klein; Medien-Hashing ist später relevant).
* AES: 16 Tabellenzugriffe je Runde à ≈ 50 Takte (clr, move.b aus dem Zustand, 2 × add.w, move.l (An,Dn.w), eor.l) ≈ 900 Takte/Runde, wie gerechnet. Ein-/Ausgabe byteweise (Nutzpuffer dürfen ungerade liegen – vamos verschleiert Address-Errors, echte Hardware nicht).
* GHASH: 8 Schritte × (16-Bit-Shift 32 Takte + 2 Reduktions-Lookups + 2 × 16-Byte-Tabellen-XOR) ≈ 4 k Takte. Die Blockoperation wird damit vom AES-Anteil dominiert (14,5 k).
* Noise-Transport: ein typischer Frame (≤ 1 KiB) kostet jetzt ≈ 0,2 s; Medien (MB) bleiben mit ≈ 5 KB/s ein Problem → Kandidat für Blitter-Bitslicing (siehe nächster Schritt) oder Akzeptanz (1 MB ≈ 3 min).

Fehler auf dem Weg (dokumentiert in docs/TOOLCHAIN.md): vbcc-Fehlkompilierung von `int8_t`-Byte-Casts in `comb_select` (nur auf dem Ziel sichtbar, Host korrekt); S-Box-Generator mit Shifts statt Rotationen; GHASH-16-Bit-Shift mit vertauschter `move.w`/`swap`-Reihenfolge. Alle drei durch die asm-gegen-C-Vergleiche im Harness gefunden, zwei davon in Sekunden mit `make vamos`.

## 2026-11-26 – Schritt 9: Blitter vs CPU (Custom-Chip-Hypothese)

Details und Bewertung in docs/CUSTOM-CHIPS.md. Kurz: 3-Quellen-XOR über 2 KiB CPU 6,70 ms, Blitter 2,06 ms (1,40 ms ohne Bitplane-DMA); Fixkosten ≈ 900 Takte je Blit; CPU in Fast RAM verliert bei laufendem Blitter 3,5 %, mit BLITHOG wird sie blockiert. Bit-sliced AES auf dem Blitter rechnet sich zu 1,5–2,2 KB/s gegen 5,45 KB/s auf der CPU → nicht umgesetzt. Blitter bleibt für WebSocket-Maskierung, Keystream-XOR und die Anzeige vorgesehen.

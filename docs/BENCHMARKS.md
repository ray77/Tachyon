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

## 2026-11-27 – Schritt 10: Bit-sliced AES auf dem Blitter, Copper-gesteuert

Details in docs/CUSTOM-CHIPS.md Abschnitte 2 und 2b. A500/FS-UAE, 16 KiB AES-256 je Batch (1024 Blöcke), bitgenau gegen die CPU-Referenz.

| Variante | Zeit je 16 KiB | Durchsatz | CPU dabei |
|---|---:|---:|---:|
| CPU T-Tabellen (asm), Referenz | 2,32 s | 7,06 KB/s | 100 % belegt |
| Blitter, CPU-Executor in C (900 Takte je Blit) | 3,76 s | 4,36 KB/s | 100 % belegt |
| Blitter, CPU-Executor in asm (250 Takte je Blit) | 3,70 s | 4,43 KB/s | 100 % belegt |
| Blitter, Copper-Kette (0 CPU je Blit), Bitplane-DMA aus | **2,28 s** | **7,2 KB/s** | **90 % frei** |
| Blitter + CPU gleichzeitig (Copper-Kette + T-Tabellen) | 2,28 s für 31,5 KiB | **14,2 KB/s** | – |
| CTR-Batch: Zählerlanes von der CPU (C, 180 ms), Kette ab SBOX, XOR-Blit (20 ms) | 2,44 s | 6,7 KB/s (13,1 mit CPU) | 86 % frei |

Hypothese bestätigt und übertroffen: Die erste Rechnung (Abschnitt 2a in CUSTOM-CHIPS.md) sagte 1,5–2,2 KB/s für den Blitter voraus und riet ab; mit Blitter-seitiger Transposition, 113-Gatter-S-Box und Copper-Steuerung liefert der Blitter so viel wie die CPU, und beide zusammen das Doppelte. Preis: ≈ 100 KiB Chip-RAM (Arena) + 50 KiB Copper-Listen, Display-DMA aus während des Batches, zwei AES-Implementierungen.

Fehler auf dem Weg (docs/TOOLCHAIN.md, Abschnitt Stolperfallen): Konsolenausgabe im Blitter-Besitz (Deadlock), COPER als Fertig-Flag (Systemliste setzt es), VBL-Server schreibt COP1LC, zweimal falsch gezählte Copper-Blockgröße, Diagnose-Blits zerstörten die Schlüssel-Lanes, Rücktransposition mit der TIN- statt TOUT-Liste. 25 FS-UAE-Läufe à 2–5 Minuten.

## 2026-11-27 – Schritt 11: RSA-2048, X.509-Kette, TLS-1.2-Handshake (Montgomery in Assembler)

A500/FS-UAE, DateStamp-Ticks, alle Vektoren gegen Go (`tools/genvectors/rsa.go`, `tools/tlsserver`) bestanden.

| Operation | vorher | jetzt |
|---|---:|---:|
| `rsa_mont_mul` 2048 Bit (Comba, 16-Bit-Limbs, 48-Bit-Akkumulator) | 1,86 s (C) | **0,448 s** |
| `rsa_mont_sqr` 2048 Bit (Paarsymmetrie) | – | **0,340 s** |
| `rsa_pub_set` (n0inv, R² mod n: Verdoppeln + 5 Quadrierungen statt 2048 Verdoppelungen) | 6,94 s | **1,94 s** |
| RSA-2048 öffentliche Operation x^65537 (16 sqr + 1 mul + Konvertierungen) | 9,38 s | **7,68 s** |
| X.509-Kette web.whatsapp.com (Parsen + 2 RSA-2048-Verifikationen) | 32,7 s | **19,5 s** |
| TLS-1.2-Client-Handshake (1 Zertifikatsprüfung + RSA-Verschlüsselung + PRF + GCM-Schlüssel) | 34,3 s | **21,1 s** |
| Noise-XX-Client-Handshake (3 X25519 + HKDF + 6 GCM-Schlüsselaufbauten) | – | 25,3 s |

Einordnung: Verbindungsaufbau (TLS 21 s + Noise 25 s + Pairing-Signaturen) liegt jetzt bei ≈ 50 s. Größter Einzelposten bleibt X25519 (8,1 s je Operation, 3 im Noise-Handshake). Für RSA bliebe Karatsuba über den 128 Limbs (≈ −25 %) und das Entrollen der Comba-Innenschleife; beides zurückgestellt, weil der Zertifikatsweg nur einmal je Verbindung läuft und das Serverzertifikat zwischengespeichert werden kann (Fingerabdruck-Vergleich statt erneuter Verifikation: 19,5 s → Millisekunden bei unverändertem Zertifikat).

## 2026-11-27 – Schritt 12: AES-GCM-Bibliothek mit Keystream auf dem Blitter (`crypto/blit/blitgcm.c`)

Details in docs/CUSTOM-CHIPS.md Abschnitt 2c. A500/FS-UAE, AES-256-GCM, Puffer in Fast RAM, bitgenau gegen `aes_gcm_encrypt/decrypt` (Host: 168 Fälle inkl. Längen 0/15/16/16383/16384/16385/40000, mit/ohne AAD, in place, AES-128; FS-UAE: 40000 B + AAD, 64 KiB in drei Varianten, 192 KiB in place; Tag-Manipulation abgewiesen). Drei Läufe, alle PASS.

| Variante | Zeit | Durchsatz |
|---|---:|---:|
| CPU `aes_gcm_encrypt` (T-Tabellen + GHASH asm), Referenz | 192 KiB: 35,4 s | 5,56 KB/s |
| 64 KiB: Blitter-Kette + GHASH auf der CPU, keine CPU-Blöcke | 9,36 s | 7,0 KB/s |
| 64 KiB: Kette + GHASH + CPU-Eigenblöcke (dynamische Aufteilung) | 7,08 s | 9,3 KB/s |
| 64 KiB dito, Puffer im Chip-RAM (Chiffretext per XOR-Blit) | 7,06 s | 9,3 KB/s |
| **192 KiB verschlüsseln, in place (8 Ketten + 3807 CPU-Blöcke)** | **19,1 s** | **10,3 KB/s** |
| **192 KiB entschlüsseln, in place** | **18,8 s** | **10,4 KB/s** |
| Zählerlanes je Batch: C 120–140 ms → Assembler | | **20 ms** |
| CTR-Block auf der CPU: vbcc-Schleifen 2,8 ms → `bg_ctr_blocks` asm | | **2,12 ms** (AES-Block allein 2,04) |
| Copper-Kette je 16 KiB: 29 → 14 CPU-Neustarts (SBOX springt per COPJMP1 nach MIX) | 2,24 → **2,10 s** | |

Hypothese war 9–10 KB/s (Abschnitt 2b): bestätigt und im Dauerbetrieb leicht übertroffen. Die Kette (2,1 s je 16 KiB) ist die Untergrenze, die CPU ist darunter voll ausgelastet (GHASH ≈ 1460 Blöcke + ≈ 435 eigene AES-Blöcke je Kette, keine Leerläufe). Unter laufender Kette läuft CPU-Code aus Fast RAM ≈ 20 % langsamer als im Leerlauf (AES 2,04 → 2,42 ms, GHASH 0,58 → 0,72 ms) – in FS-UAE gemessen, auf Hardware offen. Kurze Nachrichten verlieren am Datenende (64 KiB: 9,3 KB/s; beim Verschlüsseln bleibt der GHASH des letzten Batches seriell). Preis: 173 KiB Chip-RAM (Arena + Copper-Listen), Anzeige während eines Aufrufs aus.

Fehler auf dem Weg: Tabellen-Shift der Zählerbits 6..31 um n statt n−6 (Host-Test mit simulierter Kettenlatenz `ctx.soft_polls`, sichtbar ab Block 62, vor dem ersten FS-UAE-Lauf gefunden); CTR-Block in C kostete 0,7 ms Overhead je Block (vbcc-Byte-Schleifen, Stack-Frames) – erst der Harness-Vergleich AES-Block gegen CTR-Block zeigte es, danach Assembler.

## 2026-11-27 – Schritt 13: S-Box-Gatter in 3-Eingangs-Blits gefaltet

Details in docs/CUSTOM-CHIPS.md Abschnitt 2d. 31 Fanout-1-Gatter des 113-Gatter-Netzes in ihre Verbraucher gefaltet (Minterm mit drei Quellen, 4 statt 2 × 3 Buszyklen je Wort): 226 → 164 Blits je S-Box-Runde, Zyklen −18 %. Host-Tests (blitaes, blitgcm) und FS-UAE Lauf 4 bitgenau.

| Variante | vorher | jetzt |
|---|---:|---:|
| Copper-Kette je 16 KiB AES-256 | 2,10 s | **1,83 s** |
| 64 KiB GCM, Blitter + GHASH (CPU nur GHASH) | 7,0 KB/s | 8,0 KB/s |
| 64 KiB GCM, Blitter + GHASH + CPU-Eigenblöcke | 9,3 KB/s | 10,2 KB/s |
| 192 KiB GCM verschlüsseln, in place | 10,3 KB/s | **11,0 KB/s** |
| 192 KiB GCM entschlüsseln, in place | 10,4 KB/s | **11,4 KB/s** |
| CPU `aes_gcm_encrypt` (Referenz) | 5,56 KB/s | 5,55 KB/s |

Einordnung: AES-256-GCM auf dem Medienpfad liegt jetzt beim Doppelten der CPU (1 MB ≈ 90 s statt 3 min). Für den Verbindungsaufbau ist das ohne Belang – der wird von X25519 (8,1 s) und XEdDSA-Verifikation (9,7 s) bestimmt, nicht von AES.

## 2026-11-27 – Schritt 14: TLS-1.3-Handshake auf dem 68000 (`crypto/ref/tls13.c`)

A500/FS-UAE, DateStamp-Ticks, Wiederabspielen der aufgezeichneten Go-Loopback-Session (`bench/tls13_vector.h`, ein selbstsigniertes RSA-2048-Zertifikat, deterministischer DRBG-Seed); Host-Vektoren und Live-Lauf siehe docs/PROTOCOL.md Abschnitt 7.

| Operation | Zeit |
|---|---:|
| X25519-Schlüsselpaar für `key_share` (Comb, vor der Verbindung berechenbar) | 3,16 s |
| **TLS-1.3-Client-Handshake online** (X25519-Shared-Secret + 1 Zertifikatsprüfung + `rsa_pub_set` Blattschlüssel + RSA-PSS-CertificateVerify + HKDF + 4 GCM-Schlüsselaufbauten) | **29,4 s** |
| davon X25519 (`x25519_ref`) | ≈ 8,1 s |
| davon RSA: 2 × `rsa_pub_set` (je 1,9 s) + 2 × öffentliche Operation (je 7,7 s) | ≈ 19,3 s |
| davon HKDF-SHA256, AES-GCM-Schlüsselaufbau, Record-Layer, Transkript | ≈ 2 s |
| TLS-1.2-Handshake (Vergleich, Schritt 11) | 21,1 s |
| X.509-Kette web.whatsapp.com (2 RSA-2048-Prüfungen), nach Korrektur der Kettenprüfung | 19,5 s (zwischenzeitlich 29,5 s, s. u.) |

Hochrechnung auf die Live-Kette (`*.whatsapp.net` ← DigiCert G2 TLS RSA CA1 ← gepinnter G2-Schlüssel): X25519 8,1 s + Kette 19,5 s + Blattschlüssel 1,9 s + RSA-PSS 7,7 s ≈ **37 s** ohne Cache; mit gepinntem Zwischenzertifikat (eine Prüfung weniger) ≈ 27 s; mit Zertifikatscache (Fingerabdruck statt Kettenprüfung) ≈ 18 s. Das Zeitlimit von 60 s ab Verbindungsbeginn gilt auch für den TLS-1.3-Flight (PROTOCOL.md Abschnitt 8, nachgemessen mit `TLS_HOLD`: 60,0 s → `close_notify`, 50 s angenommen); der Pong-Herzschlag greift erst nach dem WebSocket-Upgrade, innerhalb des TLS-Handshakes hilft nur Rechenzeit sparen – 37 s passen, ohne Zertifikatscache bleiben 23 s Reserve.

Nebenbefund und Korrektur: `x509_verify_chain` prüfte seit der Vertrauensanker-Änderung jedes Zertifikat zuerst unter dem gepinnten Wurzelschlüssel – für das Blatt eine vergeblich verbrauchte RSA-Operation (Kette 19,5 s → 29,5 s im ersten Lauf dieses Schritts). Jetzt eine Prüfung je Zertifikat (Aussteller als Nächstes in der Kette → dessen Schlüssel; letztes Zertifikat → gepinnter Schlüssel). Außerdem war `bench/tls_vector.h` nach der Neuaufzeichnung der TLS-1.2-Session (Extended Master Secret) veraltet, das Wiederabspielen scheiterte auf dem Ziel mit `finished mismatch`; der Header wird jetzt per Make-Regel aus `tests/vectors/tls_session.bin` erzeugt (`tools/gen_tls_vector.py`). Beide TLS-Replays erreichen CONNECTED (vamos und FS-UAE, Lauf 3: `RESULT: all vectors passed`).

Einordnung: Der A500-Verbindungsaufbau liegt mit TLS 1.3 bei ≈ 37 s TLS + 25 s Noise + Pairing-Signaturen, also ≈ 60–65 s ohne Caches. Die großen Hebel bleiben unverändert: Zertifikatscache (−19,5 s), gepinntes Zwischenzertifikat, Karatsuba/Entrollen in `rsa_mont_mul` (−25 % auf alle vier RSA-Schritte), und ein in Ruhe vorberechnetes X25519-Schlüsselpaar (bereits so gebaut: `tls13_client_start_kp`).

## 2026-11-27 – Schritt 15: Zertifikatscache im TLS-1.3-Handshake

A500/FS-UAE, dieselbe aufgezeichnete Session wie in Schritt 14, zweimal abgespielt: einmal mit leerem Cache (volle Kettenprüfung), einmal mit dem Fingerabdruck des Blatts im Cache (`x509_cache`, PROTOCOL.md Abschnitt 7). Alle Vektoren bestanden.

| Operation | Zeit |
|---|---:|
| TLS-1.3-Handshake online, Kette geprüft (Schritt 14) | 29,4 s |
| TLS-1.3-Handshake online, Zertifikat im Cache (X25519 + `rsa_pub_set` Blatt + RSA-PSS-CertificateVerify + HKDF + GCM) | 19,8 s |
| Ersparnis = eine Zertifikatsprüfung (`rsa_pub_set` 1,9 s + öffentliche Operation 7,7 s) | −9,6 s |
| **dito, zusätzlich der vorbereitete Blattschlüssel (`rsa_pub`, R² mod n) im Cache**, auf Treffer mit `rsa_pub_check` geprüft (ein Montgomery-Produkt statt `rsa_pub_set`) | **18,3 s** |
| Ersparnis `rsa_pub_set` 1,9 s − `rsa_pub_check` 0,45 s | −1,5 s |

Hochrechnung Live-Kette (2 Prüfungen und der Blattschlüssel gespart): 37 s → **≈ 16,5 s** (X25519 8,1 s + Schlüsselprüfung 0,45 s + RSA-PSS 7,7 s + ≈ 0,3 s Rest); mit dem 60-s-Fenster (Abschnitt 8) bleiben 43 s Reserve. Übrig als RSA-Posten nur noch die eine PSS-Prüfung (7,7 s, Karatsuba/Entrollen ≈ −25 %). Der Verbindungsaufbau mit warmem Cache liegt damit bei ≈ 16,5 s TLS + 25 s Noise. Der Cache ist ≈ 1,1 KiB (Fingerabdruck 32 Byte + `rsa_pub`); ein beschädigter Eintrag (`rsa_pub_check` schlägt fehl) zählt als Fehltreffer und wird nach der vollen Prüfung überschrieben – Hosttest mit verfälschtem R², kein Aussperren.

## 2026-11-27 – Schritt 16: Zwischenzertifikat mitgepinnt (`x509_verify_chain_pins`)

A500/FS-UAE, die echte zweistufige Kette von web.whatsapp.com (`tests/certs/`), einmal gegen den G2-Wurzelschlüssel allein, einmal gegen die Pin-Menge {CA1-Zwischenzertifikat, G2-Wurzel} (PROTOCOL.md Abschnitt 7). Alle Vektoren bestanden.

| Operation | Zeit |
|---|---:|
| Kette Blatt → CA1 → gepinnte G2-Wurzel (2 RSA-2048-Prüfungen) | 19,5 s |
| **Kette gegen Pin-Menge {CA1, G2}: vollständig am Zwischenzertifikat (1 Prüfung)** | **9,8 s** |

Hochrechnung TLS-1.3-Handshake auf der Live-Kette, kalt (kein Zertifikatscache): 37 s → **≈ 27,5 s** (X25519 8,1 s + Kette 9,8 s + Blattschlüssel 1,9 s + RSA-PSS 7,7 s); mit warmem Cache bleibt es bei ≈ 16,5 s (Schritt 15), der Pin greift nur beim ersten Kontakt und nach einer Blattrotation. Fällt DigiCert auf ein anderes Zwischenzertifikat zurück, läuft die Prüfung über die Wurzel (19,5 s) weiter, ohne Codeänderung.

Stand der TLS-Zeiten damit: kalt 27,5 s, warm 16,5 s, Fenster des Servers 60 s. Verbindungsaufbau gesamt (TLS + Noise mit ≈ 35–45 s) ≈ 50–70 s; größter Posten bleibt X25519 (8,1 s je Operation, 1 in TLS, 3 in Noise).

## 2026-11-27 – Schritt 17: Netzwerk live – TLS 1.3, WebSocket und Noise gegen web.whatsapp.com aus dem emulierten A500

Erster vollständiger Verbindungsaufbau vom Amiga-Binary aus (`make run-probe GAP=0`, docs/NETWORK.md): A500/FS-UAE wie oben, dazu die emulierte A2065 auf slirp (`network_card = a2065`), TheWire13 1.9.1 als Stack über `a2065fix.device` und unsere `utility.library` 37 für Kickstart 1.3, Programm `build/amiga/wa_probe` (407 KiB, vor dem Stack gestartet). Zeitbasis `DateStamp()` ab Programmstart; Zufall aus `SYS:seed.bin`, Uhrzeit aus `SYS:now.txt` (die Amiga-Uhr stand auf 1978).

| Phase | Dauer | Zeitpunkt |
|---|---:|---:|
| Warten, bis `bsdsocket.library` öffnet und `socket()` antwortet (Stack startet parallel) | 3,2 s | 3,26 s |
| DNS `web.whatsapp.com` → 57.144.245.32 (Resolver des Stacks, slirp-DNS 10.0.2.3) | 0,90 s | 4,18 s |
| TCP-Verbindung Port 443 (SYN → SYN/ACK über slirp-NAT) | 0,82 s | 5,02 s |
| X25519-Schlüsselpaar (Festbasis-Comb) | 3,42 s | 8,44 s |
| TLS-1.3-Handshake: ClientHello → Server-Flight → Kette am Pin CA1 (1 RSA) → RSA-PSS → Finished | 31,8 s | 40,28 s |
| WebSocket-Upgrade `/ws/chat` | 0,50 s | 40,78 s |
| Noise-ClientHello (statisches + ephemeres Schlüsselpaar, 2 Comb-Multiplikationen) | 6,8 s | 47,60 s |
| ServerHello (Netz, 350 Bytes) | 1,4 s | 48,98 s |
| `noise_client_finish` (3 DH, HKDF, AES-GCM) + XEdDSA-Prüfung des Zwischenzertifikats | 40,4 s | 89,40 s |
| XEdDSA-Prüfung des Blattzertifikats, Schlüsselvergleich | 11,1 s | 100,52 s |
| ClientFinish gesendet – **51,8 s nach ServerHello, 12 Pongs vom Herzschlag** | 0,3 s | 100,80 s |
| erster verschlüsselter Server-Frame (695 → 679 Bytes, Pair-Device-IQ) empfangen und entschlüsselt | 4,7 s | 105,48 s |

`RESULT: handshake ACCEPTED by web.whatsapp.com with our TLS 1.3/WS/Noise stack, 0.00 s hold, 12 pongs` – auf dem 68000 mit 7,09 MHz, Kickstart 1.3, über einen echten TCP/IP-Stack und einen SANA-II-Treiber.

### Einordnung

- **TLS 1.3: 31,8 s** gegen 27,5 s Hochrechnung (Schritt 16, kalt). Die Differenz sind Netz und Transport: zwei Umläufe über slirp (je ≈ 0,8–1,4 s), der Server-Flight kommt in 1460-Byte-Segmenten und wird Record für Record entschlüsselt, dazu WaitSelect/recv im Stack. Der Rechenanteil ist wie gemessen. Vom TCP-Connect bis zum eigenen Finished vergehen 35,3 s – innerhalb des 60-s-Fensters des Servers (PROTOCOL.md Abschnitt 8), aber ohne viel Luft für langsamere Netze; der Zertifikatscache (−11 s, Schritt 15) ist deshalb nicht optional.
- **Noise: 51,8 s** zwischen ServerHello und ClientFinish gegen die frühere Schätzung 35–45 s. Aufschlüsselung: 3 × X25519 (≈ 24 s) + 2 × XEdDSA (≈ 22 s) + HKDF/AES; die Schätzung hatte die zweite XEdDSA-Prüfung nicht enthalten. Die 12 Pongs (alle 4 s aus `CRYPTO_YIELD()`) haben die 10-s-Leerlaufgrenze überbrückt; der Server nahm den ClientFinish an und antwortete 4,7 s später (Entschlüsseln und Parsen auf dem 68000 inklusive).
- **Gesamt ≈ 100 s** vom Programmstart bis zum ersten entschlüsselten Server-Frame, ≈ 97 s ab TCP. Mit warmem Zertifikatscache ≈ 86 s. Nächste Hebel: XEdDSA-Verifikation (22 s für zwei Zertifikate; das Zwischenzertifikat ist stabil und ließe sich wie die TLS-Kette cachen → −11 s), die 6,8 s für die zwei Comb-Schlüsselpaare vor dem ClientHello (vorab berechnen, wie das TLS-Schlüsselpaar), und die 3,4 s TLS-Schlüsselpaar (ebenfalls vorab).
- **Speicher:** `Avail` nach dem Start beider Programme: Fast 872 Bytes frei, Chip 69 KiB frei. TheWire13 belegt Code 114 KiB + BSS 126 KiB + TCP-Pool (12 PCBs × 40 KiB = 480 KiB, ohne Konfigurationsschlüssel; fällt bei Knappheit auf 4 PCBs = 240 KiB zurück) + RX-Puffer; die Probe 407 KiB (Code 147 KiB, BSS 260 KiB inkl. 64 KiB Stack). Startet der Stack zuerst, bleibt kein Fast-RAM für die Probe (Loader-Fehler, kein `result.txt`). Für den Client heißt das: Stack und Client teilen sich 1 MiB Fast + 512 KiB Chip; der TCP-Pool des Stacks muss klein bleiben, der Client unter ≈ 400 KiB. **Nachtrag 2 MiB Fast** (`make run-probe FAST=2048`, NETWORK.md Abschnitt 6): Stack allein 1 369 712 Bytes Fast belegt, 727 KiB Fast und 447 KiB Chip frei; mit laufender Probe 190 KiB Fast und 447 KiB Chip frei. Der Stack nimmt mit 2 MiB ≈ 440 KiB mehr (12 statt 4 PCBs), die Startreihenfolge wird egal, die Zeiten ändern sich nicht. Der Netz-Client setzt deshalb 2 MiB Fast voraus; 1 MiB bleibt die Benchmark-Maschine.

## 2026-11-27 – Schritt 18: Schlüsselpaare vor dem Connect, Cache für das Noise-Zwischenzertifikat

Dieselbe Maschine und derselbe Ablauf wie Schritt 17 (`make run-probe GAP=0`, FS-UAE, A2065/slirp, TheWire13 über `a2065fix.device`), Programm `build/amiga/wa_probe` aus Commit b91672c. Zwei Änderungen in `tests/wa_probe_core.c`: `wa_probe_prepare` berechnet die drei X25519-Schlüsselpaare (TLS, Noise-Static, Noise-Ephemeral; Festbasis-Comb) **vor** dem TCP-Connect – auf dem Amiga sogar vor dem Warten auf den Stack, der parallel startet –, und das Zwischenzertifikat der Noise-Kette wird nach einmaliger XEdDSA-Prüfung als Fingerabdruck gecacht (`noise_cert_cache`, PROTOCOL.md Abschnitt 6; hier vorgewärmt aus dem Host-Lauf `make wa-probe GAP=6` über `build/wa_noise_cache.bin` → `SYS:noisecache.bin`, wie es im Client aus `ENVARC:` käme).

| Phase | Schritt 17 | Schritt 18 | Zeitpunkt (18) |
|---|---:|---:|---:|
| TLS-X25519-Schlüsselpaar | 3,42 s (nach Connect) | 4,62 s **vor** Connect, parallel zum Stackstart | 4,98 s |
| Noise-Static + -Ephemeral (2 Comb-Multiplikationen) | 6,8 s (nach WebSocket) | 7,32 s **vor** Connect, parallel zum Stackstart | 12,32 s |
| Warten auf `bsdsocket.library` | 3,2 s | 0,1 s (Stack war längst fertig) | 12,42 s |
| DNS + TCP-Verbindung | 1,7 s | 1,5 s | 13,90 s |
| TLS-1.3-Handshake (Kette am Pin CA1, 1 RSA, RSA-PSS, Finished) | 31,8 s | 31,5 s | 45,38 s |
| WebSocket-Upgrade | 0,5 s | 0,5 s | 45,84 s |
| Noise-ClientHello | 6,8 s | **0,3 s** | 46,10 s |
| ServerHello (Netz) | 1,4 s | 1,3 s | 47,44 s |
| `noise_client_finish` (3 DH, HKDF, AES-GCM) | ≈ 29,3 s | 28,8 s | 76,30 s |
| XEdDSA Zwischenzertifikat | 11,1 s | **0,0 s (Cache-Treffer)** | 76,30 s |
| XEdDSA Blattzertifikat, Schlüsselvergleich | 11,1 s | 11,0 s | 87,30 s |
| ClientFinish gesendet – nach ServerHello | 51,8 s (12 Pongs) | **40,1 s (9 Pongs)** | 87,56 s |
| erster verschlüsselter Server-Frame entschlüsselt | 4,7 s | 4,5 s | 92,08 s |
| **Verbindungsfenster TCP-Connect → erster Frame** | **100,5 s** | **78,2 s** | |
| Programmstart → erster Frame | 105,5 s | 92,1 s | |

`RESULT: handshake ACCEPTED by web.whatsapp.com with our TLS 1.3/WS/Noise stack, 0.00 s hold, 9 pongs, Noise cert cache hit` (`TIMING: keys 12180 ms (tls 4620 + noise 7320, before connect), dns 980 ms, tcp connect 480 ms, tls 31460 ms, ws 31900 ms, server hello 33520 ms, client finish 73620 ms, accepted 78180 ms`).

### Einordnung

- **−22,3 s im Verbindungsfenster**, gerechnet waren 21,3 s (3,4 + 6,8 + 11,1); der Rest ist Streuung im Netz. Alle drei Posten sind aus dem Fenster verschwunden: der ClientHello folgt 0,3 s nach dem WebSocket-Upgrade, die Prüfung des Zwischenzertifikats kostet nichts mehr.
- **Die Schlüsselpaare brauchen offline länger** (12,2 s statt 10,2 s), weil TheWire13 in derselben Zeit startet und den 68000 mitbenutzt – genau das ist der Gewinn: die Wartezeit auf den Stack (3,2 s) ist in den Schlüsselpaaren aufgegangen, der Programmstart bis zum ersten Frame fällt um 13,4 s. Im Client gehören die Schlüsselpaare in den Programmstart (Bildschirmaufbau, Konfiguration), noch vor jedem Connect.
- **Noise jetzt 40,1 s zwischen ServerHello und ClientFinish:** 3 × X25519-Leiter (≈ 24 s) + HKDF/AES-GCM (≈ 5 s) + 1 × XEdDSA (11 s). Der Herzschlag deckte es mit 9 Pongs ab. Nächster Hebel hier: die XEdDSA-Prüfung des Blatts (11 s; das Blatt wechselt mit dem Serverschlüssel, Seriennummer 366 seit mehreren Läufen – auch cachebar, mit Fehltreffer bei Wechsel) und die Leitern selbst (X25519-PLAN.md).
- **TLS bleibt 31,5 s**, davon ≈ 10 s RSA (eine Prüfung + `rsa_pub_set`), die der Zertifikatscache aus Schritt 15 spart, sobald der Amiga ihn aus einer Datei lädt wie jetzt den Noise-Fingerabdruck (`io.use_cache` ist in der Amiga-Probe noch 0). Damit läge das Fenster bei ≈ 68 s.
- **Speicher:** `Avail` nach beiden Programmen Fast 696 Bytes frei, Chip 133 KiB frei – die Probe ist mit den vorgezogenen Schlüsselpaaren nicht gewachsen (gleiche statischen Puffer, nur umgehängt). Live-Verbindungen für diesen Schritt: Host 2 (Cache leer → gefüllt, Treffer), vamos 1, FS-UAE 1.

## 2026-11-27 – Schritt 19: Pairing als verknüpftes Gerät aus dem emulierten A500

Dieselbe Maschine wie Schritt 18 mit 2 MiB Fast-RAM (`make run-pair FAST=2048`), Programm `build/amiga/wa_probe` im Modus `WA_MODE_PAIR` (PROTOCOL.md Abschnitt 11), Noise-Cache vorgewärmt, keine gespeicherten Zugangsdaten → QR-Pairing, 515-Neustart, Login-Verbindung. Das Telefon las den Code vom FS-UAE-Fenster ab (61 × 61 Module, 6 × 3 Pixel je Modul) und bestätigte das Pairing; `RESULT: PAIRED and LOGGED IN as <JID>:8 (scan -> sign 19.60 s, login connection 76.00 s)`.

| Phase | Dauer | Zeitpunkt |
|---|---:|---:|
| Companion-Identität (Noise-Static, Signal-Identität, signierter Prekey mit XEdDSA, Registrierungs-ID; vor dem Connect) | 18,28 s | 18,88 s |
| TLS-Schlüsselpaar + Noise-Ephemeral (vor dem Connect) | 6,52 s | 25,40 s |
| DNS + TCP-Connect | 1,3 s | 26,78 s |
| TLS-1.3-Handshake | 32,1 s | 58,96 s |
| WebSocket + Noise-ClientHello (300-Byte-Registrierungs-Payload) | 0,6 s | 59,60 s |
| ServerHello → ClientFinish (3 DH, HKDF, AES-GCM, XEdDSA Blatt; Zwischenzertifikat aus dem Cache) | 40,64 s (10 Pongs) | 101,48 s |
| erster Server-Frame (`pair-device` mit 6 Refs), Ack | 4,7 s | 106,22 s |
| QR V11 L kodieren (Maske 2 fest) + zeichnen (414 × 207 Pixel) | 0,78 s + 0,92 s | 107,98 s |
| Telefon scannt → `pair-success` | 18,26 s | 125,42 s |
| HMAC-SHA256 + Account-Signatur prüfen (XEdDSA) | **11,30 s** | 136,76 s |
| Geräte-Signatur (XEdDSA-Sign, `sc_muladd`) | **7,84 s** | 144,66 s |
| `SYS:tachyon.creds` schreiben, `pair-device-sign` senden | 0,4 s | 145,10 s |
| Server: `stream:error 515` + `xmlstreamend` (eine WebSocket-Nachricht) | 0,66 s | 145,58 s |
| neue TLS- und Noise-Ephemeral-Schlüsselpaare | 6,60 s | 152,40 s |
| Login-Verbindung: TCP, TLS (32,1 s), WebSocket, Noise (41,3 s, 87-Byte-Login-Payload) | 76,0 s | 228,70 s |
| `<success>` → eingeloggt | | 228,74 s |
| **Scan → `pair-device-sign`** | **19,60 s** | |
| **Programmstart → `<success>`** | **228,7 s**, 26 Pongs | |

### Einordnung

- **Der Server wartet.** 19,6 s zwischen Scan und Geräte-Signatur störten nicht; die 20-s-Gültigkeit der Codes zählt nur bis zum Scan. Die Pongs alle 4 s hielten die Verbindung.
- **XEdDSA dominiert:** Prüfung 11,3 s (wie beim Noise-Blattzertifikat) und Signatur 7,8 s – zusammen 19 s, davon 3 Festbasis-/Doppelbasis-Multiplikationen. Die Prüfung ist dieselbe `xeddsa_verify` wie in Noise; jeder Gewinn dort (X25519-PLAN.md) zählt hier doppelt.
- **Zwei volle Verbindungen** kosten 2 × (32 s TLS + 41 s Noise) = 146 s der 229 s. Der 515-Neustart ist vom Protokoll vorgegeben; die Login-Verbindung kommt bei jedem Programmstart wieder (76 s), das Pairing nur einmal. Hebel wie in Schritt 18: Zertifikatscache für TLS (−10 s), Blattzertifikat cachen (−11 s), schnellere Leitern.
- **Identität 18,3 s** vor dem Connect: drei Festbasis-Multiplikationen plus XEdDSA-Sign des Prekeys. Einmalig; bei gespeicherten Zugangsdaten entfällt sie, und der Lauf beginnt beim Login (76 s).
- **Speicher:** mit 2 MiB Fast nach Stack und Probe 177 KiB Fast + 437 KiB Chip frei (`avail.txt`); der QR-Schirm (4 Planes 640 × 256, 80 KiB Chip) und die Decoder-Arenen (2 × 6 KiB) passen.
- **Plattformtyp:** dieses Binary war 37 s vor der Umstellung auf `WA_PLATFORM_TYPE` FIREFOX gebaut (Header fehlte in den Make-Abhängigkeiten, behoben), das Pairing lief daher wie das Host-Pairing mit UNKNOWN; das Telefon zeigt „Anderes Gerät". Ein dritter Lauf mit FIREFOX (Gerät :9) brachte dieselben Zahlen plus ≈ 5 % für die Fortschrittspunkte (Prüfung 12,04 s, Signatur 8,14 s, Login-Verbindung 79,9 s, gesamt 234 s; PROTOCOL.md 11). Ein vierter Lauf (Login mit den Zugangsdaten von Gerät :9, PROTOCOL.md 11 „Nach `<success>`“): 10 Einmal-Prekeys in **32,9 s** vor dem Connect (3,3 s je X25519-Paar), Login-Verbindung 76,0 s, Prekey-Zählung 1,0 s, Upload von 10 Prekeys angenommen nach 1,3 s, `<active/>` angenommen 3,6 s nach `<success>`; Programmstart → aktiv 122 s. Live-Verbindungen für diesen Schritt: Host 2 (Pairing, Login), FS-UAE 3 (Pairing UNKNOWN, Pairing FIREFOX, Login mit Prekey-Upload).

## 2026-11-27 – Schritt 20: zweite Faltung auf Limb 0, Leitertausch als Index-Flip

Zwei Mikro-Schritte an der Feldarithmetik, beide bitidentisch zur C-Referenz (Vergleichstests auf je 1000 Inputs, RFC 7748, 256 Go-Zufallsvektoren auf dem Host, alle Vektoren unter vamos und in FS-UAE).

1. **Zweiter Faltungsdurchlauf nur noch auf Limb 0** (`tools/gen_fe16_asm.py`, `fold_last`). Nach der Reduktion gilt h < 2^256 und der Übertrag c < 39; Durchlauf 1 addiert 38·c ≤ 1444. Trägt er aus 2^256 hinaus, bleibt h < 1444 zurück, und die +38 des zweiten Durchlaufs kann Limb 0 nicht mehr verlassen. Dieselbe Schranke gilt für Add (h < 38), Sub (h < 76) und mit zwei Limbs für Mul121665 (h < 2^23). Aus 376 Takten (`mulu` + 15 × `addx`-Kette) werden 24 (`neg.w`, `and.w #38`, `add.w`), ohne Verzweigung, in allen fünf Routinen. Die C-Referenz behält ihre volle Kette (sie addiert dort Nullen).
2. **Konditionaler Tausch in der Montgomery-Leiter als Index-Flip** (`crypto/ref/x25519_ref.c`): (x2,z2) und (x3,z3) liegen in `pt[4]`, der Tausch kippt einen Index zwischen 0 und 2 per Maske statt zweimal 16 Limbs zu XOR-tauschen (≈ 1,6 k Takte je Schritt). Verzweigungsfrei; die Adresse hängt vom geheimen Bit ab, was auf dem 68000 ohne Cache keinen messbaren Unterschied macht.

| Operation | vorher | jetzt | Δ |
|---|---:|---:|---:|
| `fe16_mul` (Karatsuba) | 3,40 ms | **3,34 ms** | −2 % |
| `fe16_sqr` | 2,38 ms | **2,26 ms** | −5 % |
| `fe16_add` | 0,203 ms | **0,151 ms** | −26 % |
| `fe16_sub` | 0,258 ms | **0,206 ms** | −20 % |
| `fe16_mul121665` | 0,432 ms | **0,383 ms** | −11 % |
| X25519, nur Faltung | 8,08 s | 7,82 s | −3,2 % |
| **X25519, beides** | 8,08 s | **7,71 s** | **−4,6 %** |
| `ed25519_verify` | 9,10 s | **8,84 s** | −3 % |
| `xeddsa_verify` | 9,72 s | **9,44 s** | −3 % |
| Noise-XX-Client (3 X25519 + HKDF + GCM) | 25,3 s | **24,3 s** | −4 % |
| TLS-1.3-Handshake, Zertifikat im Cache | 18,1 s | 18,0 s | – |

### Einordnung

Die Leiter steht damit bei 7,7 s gegen die in Schritt 3 genannte Untergrenze von ≈ 7,5 s. Was übrig ist: 192 Produkte à ≈ 84 Takte (`move.w (a0)+` 8, `mulu.w -(a1)` 48 + 2·Einsen, `add.l` 8, `addx.w` 4) sind 16 k der 23,7 k Takte einer Multiplikation; Spaltenwechsel, Karatsuba-Buchhaltung, Reduktion und erste Faltung teilen sich den Rest, jeder Posten für sich schon knapp. Karatsuba für die Quadrierung (136 → 108 Produkte) kostet in der Buchhaltung, was es an Produkten spart; eine zweite Karatsuba-Ebene ebenso. Die vier Online-Leitern der Login-Verbindung kosten jetzt 30,8 s statt 32,3 s. Deutlich mehr bringt nur, Leitern aus dem Fenster zu nehmen: Noise `es` = DH(e_c, s_s) mit dem gecachten Server-Static vor dem Connect rechnen (−7,7 s, Gleichheitsprüfung nach dem ServerHello) und, falls der Server Tickets schickt und `psk_ke` erlaubt, TLS-Resumption ohne DH (−7,7 s).

## 2026-11-27 – Schritt 21: Login-Verbindung des A500 mit TLS- und Noise-Cache aus der Datei

Zwei Logins mit den Zugangsdaten von Gerät :9 (`make run-pair FAST=2048`, FS-UAE, 2 MiB Fast, Binary aus 426499e + Ticket-Log), fünf Minuten Abstand. Lauf 1 füllt `SYS:tlscache.bin` (585 Byte, `x509_cache_write`) und die zweite Hälfte von `SYS:noisecache.bin` (Blattzertifikat), Lauf 2 trifft beide. Zeiten ab TCP-Connect.

| Phase | Lauf 4 (Schritt 19, 16:30) | Lauf 1 (19:11, Caches füllen) | **Lauf 2 (19:19, Treffer)** |
|---|---:|---:|---:|
| Prekeys vor dem Connect | 32,9 s (10 neu) | 32,4 s (10 neu) | **0 s** (Batch lag vor) |
| drei X25519-Schlüsselpaare vor dem Connect | 6,6 s | 6,4 s | 6,6 s |
| TLS 1.3 | 32,0 s | 31,7 s | **20,3 s** (Cache HIT: Kette + `rsa_pub_set` gespart) |
| WebSocket-Upgrade + ClientHello → ServerHello | 1,7 s | 1,7 s | 1,6 s |
| Noise ServerHello → ClientFinish | 41,3 s | 39,4 s (Leiter 7,7 s) | **28,5 s** (Blatt-XEdDSA gespart) |
| **Login-Verbindung bis `<success>`** | **76,0 s** | **74,4 s** | **52,0 s** |
| Programmstart → `<success>` | 122 s | 117 s | **62 s** |
| Pongs in Noise | 9 | 9 | 6 |

Dazu: `<active/>` angenommen 2,0 s (Lauf 1) bzw. 5,7 s (Lauf 2) nach `<success>`; die 170-KB-Nachricht des Servers wird verworfen, die Verbindung bleibt; `tls: 0 NewSessionTicket(s)`.

### Einordnung

Von 76,0 s auf 52,0 s: −10,4 s TLS-Cache (eine RSA-2048-Prüfung + Schlüsselvorbereitung), −10,9 s Noise-Blatt-Cache (eine XEdDSA-Prüfung), −1,6 s schnellere Leiter. Der Startweg bis zum Login ist mit 62 s halbiert, weil der Prekey-Batch jetzt zwischen den Läufen gespeichert wird. Was bleibt (52 s): vier X25519-Leitern 30,8 s, RSA-PSS CertificateVerify ≈ 5 s, HKDF und zehn AES-GCM-Schlüsselaufbauten ≈ 5 s, Entschlüsseln/Parsen und Netz der Rest. Da der Server keine Tickets schickt, gibt es keine TLS-Resumption; der nächste Hebel ist die Vorausrechnung von Noise `es` mit dem gecachten Server-Static (−7,7 s → ≈ 44 s), danach bliebe nur noch Arithmetik an der Untergrenze. Live-Verbindungen für diesen Schritt: 2 (beide Logins, keine Fehlversuche).

## 2026-11-27 – Schritt 22: Noise `es` vor der Verbindung gerechnet

`noise_es_pre` (PROTOCOL.md Abschnitt 6): der Server-Static aus dem 96-Byte-Noise-Cache, `es` = DH(e_c, s_s) mit den Schlüsselpaaren vor dem Connect, im Handshake nur bei byteweiser Gleichheit mit dem entschlüsselten Static verwendet. Zwei Logins mit Gerät :9 (`make run-pair FAST=2048`, FS-UAE, 2 MiB Fast), Lauf A speichert den Static, Lauf B nutzt ihn.

| Phase | Schritt 21 (Caches) | Lauf A (19:31) | **Lauf B (19:38, `es` vorab)** |
|---|---:|---:|---:|
| `es` vor dem Connect | – | – | 8,0 s |
| drei X25519-Schlüsselpaare vor dem Connect | 6,6 s | 6,6 s | 6,6 s |
| TLS 1.3 (Cache HIT) | 20,3 s | 20,3 s | 20,3 s |
| Noise ServerHello → ClientFinish | 28,5 s | 28,9 s | **19,7 s** |
| **Login-Verbindung bis `<success>`** | **52,0 s** | **52,5 s** | **43,1 s** |
| Programmstart → `<success>` | 62 s | 62 s | 61 s |
| Pongs in Noise | 6 | 6 | 4 |

### Einordnung

Tagesbilanz der Login-Verbindung des A500: **76,0 s → 43,1 s** (−10,4 s TLS-Zertifikatscache, −10,9 s Noise-Blatt-Cache, −1,6 s schnellere Leiter, −8,8 s `es` vorab). Online stehen noch drei Leitern (TLS, `ee`, `se`; 23 s), beide mit frischem Server-Ephemeral und darum nicht vorab rechenbar, RSA-PSS CertificateVerify ≈ 5 s, HKDF und AES-GCM-Schlüsselaufbauten ≈ 5 s, Entschlüsseln/Parsen und Netz. Der Server schickt keine Tickets (keine TLS-Resumption), die Leiter liegt 3 % über der Untergrenze: ohne Protokollwechsel (Noise IK spart keinen DH) bleibt die Login-Verbindung bei etwa 40–43 s. Was den Start bis zum Login noch verkürzt, läuft außerhalb der Server-Uhr: Schlüsselpaare und `es` im Leerlauf des Clients, nicht erst beim Start. Live-Verbindungen für diesen Schritt: 2.

## 2026-11-27 – Schritt 23: Schlüsselpaare und `es` im Leerlauf, Start ohne Vorrechnen

`proto/nextkeys.c` (PROTOCOL.md Abschnitt 6): nach `<active/>` rechnet der Client, solange er online ist, TLS-Schlüsselpaar, Noise-Ephemeral und `es` für den nächsten Start und speichert sie (226 Byte); der nächste Start verbraucht den Datensatz vor dem ersten Byte auf der Leitung. Zwei Logins mit Gerät :9 (`make run-pair FAST=2048`, FS-UAE, 2 MiB Fast), Lauf C schreibt, Lauf D verbraucht.

| Phase | Schritt 22 (Lauf B) | Lauf C (19:50, schreibt) | **Lauf D (19:57, verbraucht)** |
|---|---:|---:|---:|
| Schlüssel vor dem Connect | 14,6 s (6,6 + `es` 8,0) | 14,6 s | **0,06 s** (aus dem Datensatz) |
| Programmstart → TCP-Connect | 17,5 s | 17,6 s | **4,2 s** |
| TLS 1.3 (Cache HIT) | 20,3 s | 20,3 s | 20,4 s |
| Noise ServerHello → ClientFinish | 19,7 s | 19,7 s | 19,7 s |
| Login-Verbindung bis `<success>` | 43,1 s | 43,3 s | 43,2 s |
| **Programmstart → `<success>`** | **61 s** | **61 s** | **47,4 s** |
| nächste Schlüssel, online gerechnet | – | 15,9 s (3 Pongs) | 18,0 s (4 Pongs) |

### Einordnung

Der Startweg des A500 bis zum Login: mittags 122 s (Prekeys 33 s + Schlüssel 7 s + Verbindung 76 s), jetzt **47 s**, davon 43 s die Verbindung selbst. Vor dem Connect rechnet der 68000 nichts mehr; alles Vorab-Rechenbare läuft in der vorigen Sitzung, während der Server ohnehin Ereignisse schickt (Herzschlag hält den WebSocket). Die 43 s der Verbindung bestehen aus drei Leitern mit frischem Server-Ephemeral (23 s), RSA-PSS CertificateVerify (≈ 5 s), HKDF/AES-GCM (≈ 5 s), Netz und Parsen; ohne Protokollwechsel bleibt das so. Die Prekey-Erzeugung (3,3 s je Schlüssel) gehört in dieselbe Leerlaufphase, sobald der Client länger online bleibt. Live-Verbindungen für diesen Schritt: 2.

Nachtrag (20:05): die Prekey-Erzeugung liegt jetzt ebenfalls in der Leerlaufphase nach `<active/>` (PROTOCOL.md Abschnitt 6, „Prekeys ebenfalls im Leerlauf“): vor dem Connect rechnet `wa_probe_prepare` gar nichts mehr. Offline im Simulator geprüft (136 Prüfungen); live nicht eigens gemessen, weil Server (6) und Charge (10 anstehend) an diesem Abend nichts zu erzeugen ließen – 3,3 s je Schlüssel, online mit Herzschlag wie die Schlüssel für den nächsten Start.

## 2026-11-27 – Schritt 24: Signal live – X3DH, erste Nachricht vom A500, Server-Ack

Vierter Live-Chat-Versuch (SIGNAL.md 6, `make run-chat … FAST=2048`, FS-UAE zyklengenau, A500 mit 2 MiB Fast): der Text des Nutzers an die eigene Nummer, gesendet vor `<active/>` (passiver Zustand), bestätigt vom Server. Zeiten seit dem TCP-Connect.

| Phase | Versuch 4 |
|---|---:|
| Programmstart → `<success>` | 60,4 s (Verbindung 42,5 s) |
| Bundle-Anfrage → Bundle des Telefons | 0,9 s |
| **X3DH als Initiator** (XEdDSA der Prekey-Signatur, 4 Leitern, 2 Schlüsselpaare, Ratchet-Leiter) | **64,16 s** (15 Pongs) |
| Sitzungsdatensatz schreiben (2×, SYS:) | 0,6 s + 0,6 s |
| Nachricht verschlüsseln (118 Byte Klartext → 265 Byte PreKeySignalMessage) | 0,28 s |
| `<message>` gesendet → `<ack class=message>` | **0,52 s** |
| Programmstart → Server-Ack | 129,3 s |
| Schlüssel für den nächsten Start (online) | 17,1 s (3 Pongs) |

### Einordnung

Der erste Text eines Amiga 500 an WhatsApp, auf dem Telefon angekommen (Selbst-Chat, vom Nutzer bestätigt): 129 s nach dem Programmstart liegt die Server-Bestätigung vor, davon 64 s X3DH auf dem 68000 (Erwartung aus dem Vektor-Runner war ~54 s; live kommt die XEdDSA-Prüfung der Prekey-Signatur dazu, 9,4 s). Beim zweiten Text an dasselbe Gerät entfällt X3DH (Sitzung im Datensatz): Verschlüsseln 0,3 s, Ack ~0,5 s. Die Antwort des Telefons kam nicht mehr an – nach `<active/>` gab die Stapel-Schleife mitten im 166-KB-History-Frame auf (SIGNAL.md 6, Versuche 4 und 5; Versuch 5 misst den Empfang auf dem 68000 mit **~3,2 KB/s**: TLS-Entschlüsselung, 166 KB ≈ 52 s); Schritt 25 ist der Empfang. Signal-Zeiten des Vektor-Runners unter FS-UAE (`make run`) stehen noch aus; unter vamos (nicht zyklengenau) laufen alle Vektoren durch.

## 2026-11-28 – Schritt 25: Chat-Oberfläche in der Probe, Live-Lauf 6 (Empfangspfad)

Sechster Live-Chat-Versuch, der erste mit der eingebauten Oberfläche (`ui/gui.c` in `bench/wa_probe_amiga.c`, UI.md „Einbindung in die Probe“; `make run-chat … CHAT_SEND='' CHAT_LINGER=300 FAST=2048`, Empfangslauf ohne Skripttext). Log `build/chat6.log`.

| Phase | Lauf 6 |
|---|---:|
| Programmstart → Schirm + GUI gemalt (1 Chat, Arena im Chip-RAM) | 1,48 s (bei 3,1 s) |
| Programmstart → `<success>` / `<active/>` | 50,9 s / 54,7 s (TLS 21,0 s, Noise-Handshake 22,6 s mit gespeichertem `es`) |
| `offline_preview`: 33 Stanzas (3 Nachrichten, 1 Quittung, 6 Benachrichtigungen, 23 Status) | 56,7 s |
| 166 587-Byte-Frame: Beginn → 164,5 KB | 58,0 s → 116,8 s (**2,8 KB/s**, wie Lauf 5) |
| die letzten 2 025 Byte des Frames | **39 s** (116,8 → 155,9 s; kein Byte dazwischen, Stall wie in Lauf 4) |
| Frame dekodieren (166 487-Byte-`pkmsg` des eigenen Telefons, zu lang: **bestätigt**, verworfen) | 17,8 s (173,7 s) |
| zweite Offline-Nachricht (613-Byte-`pkmsg`, `@lid`): X3DH als Responder + Entschlüsseln | **53,6 s** → `[protocol message, type 5]`, 454 Byte Klartext |
| Quittung senden | **fehlgeschlagen** (Verbindung weg), WebSocket geschlossen bei 234,5 s |
| GUI: Ticks / Mittel / Maximum / über 100 ms | 143 / 19 ms / 300 ms / 2 |
| Speicher nach Start beider Programme (SYS:avail.txt) | Fast 62 KB frei, Chip 255 KB frei |

Was zu sehen war: Kopfzeile mit grünem Punkt „online“, Uhr nach der Serverzeit, der Selbst-Chat „Du“; die vom Nutzer getippte Zeile als ausstehende Blase (Uhr-Symbol) mit Listeneintrag und Nachrichtenzahl in der Kopfzeile. Die Zeile wurde **nicht** gesendet: die Linger-Schleife, in der der Core getippte Zeilen abholt, wurde nie erreicht, weil die Verbindung im Offline-Stapel endete. Zwei Mängel der Oberfläche aus dem Lauf, beide behoben: das Tippen kroch (ein Zeichen je 200-ms-Tick, während der 68000 rechnet; jetzt holt ein Tick alle wartenden Tasten), und die Uhr sprang auf 16:03 des Vortags (das `t=` einer Offline-Nachricht wurde als Serveruhr genommen; jetzt zählen nur Stanzas ohne `offline` und nur vorwärts).

### Einordnung

Der Empfangspfad ist zwei Schritte weiter als in Lauf 5: die 166-KB-History-Stanza des Telefons ist zum ersten Mal **bestätigt** (sie sollte beim nächsten Login nicht mehr kommen), und eine echte Offline-Nachricht des Telefons wurde mit X3DH als Responder **entschlüsselt** (eine Protokollnachricht, Typ 5 – App-State-Schlüssel, kein Text). Dann wiederholt sich das Muster der Läufe 4 und 5: nach einer langen Rechenphase, in der der Socket kaum gelesen wird (17 s Decode ohne Lesen, 53 s X3DH mit 8-KB-Staging-Puffer), ist die Verbindung weg; dazu der 39-s-Stall am Frame-Ende. Verdacht: Nullfenster über eine Minute (8-KiB-Fenster + 8 KB Staging) gegen slirp/Server. Nächster Hebel liegt im Core (Signal-Sitzung): Staging-Puffer im Chip-RAM auf ~128 KB (frei: 255 KB) und ein Lesen auch in der Decode-Schleife. Die Oberfläche selbst war unauffällig: 19 ms je Tick, 300 ms Maximum, kein verlorenes Zeichen, Haken/Uhr/Zähler wie vorgesehen.


## 2026-11-28 – Schritt 25: Offline-Stapel empfangen – 166-KB-Frame, X3DH als Responder (Live-Versuch 6)

Empfangslauf mit der Chat-GUI auf dem Schirm (SIGNAL.md 6, Versuch 6). Zeiten seit Programmstart.

| Phase | Versuch 6 |
|---|---:|
| Programmstart → `<success>` | 50,9 s (Verbindung 44,8 s) |
| 166 587-Byte-Frame: erstes bis letztes Byte | ~59 s (**~1,7 KB/s**; Versuch 5 ohne Schirm 3,2 KB/s) |
| Noise-Entschlüsselung des Frames an Ort und Stelle (AES-GCM, 166 KB) | **37 s** (4,5 KB/s) |
| Decodieren + 40 Hex-Logzeilen + Ack | 17 s (Logzeile 0,4 s) |
| **X3DH als Responder + erste Entschlüsselung** (613-Byte-PreKeySignalMessage) | **53,6 s** |

### Einordnung

Der Weg herein ist langsamer als der hinaus: 166 KB kosten eine Minute Empfang (TLS-Entschlüsselung, Chip-Bus mit dem Schirm geteilt) und 37 s Noise-Entschlüsselung – zusammen mehr als der ganze Login. Der History-Frame ist jetzt bestätigt und kommt nicht wieder; die laufenden Kosten sind die Offline-Nachrichten (je ~54 s für ein neues Gerät, danach ~1 s je Nachricht). Die GCM-Zeiten sind Software (`crypto/ref/aes.c`); der Blitter-AES/GCM (`crypto/blit`, Schritt 12) ist in der Probe noch nicht eingehängt – dort liegt der nächste Faktor 2–3.

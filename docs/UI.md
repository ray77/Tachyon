# Oberfläche

## QR-Code zum Verknüpfen (`ui/qr.c`, `ui/qr.h`)

Der A500 wird als verknüpftes Gerät angemeldet, indem das Telefon einen QR-Code vom Bildschirm liest. Der Text ist `ref,noisePub,identityPub,advSecret` (die drei Schlüssel Base64 mit Auffüllzeichen, je 44 Zeichen), insgesamt etwa 140–170 ASCII-Zeichen. `ui/qr.c` erzeugt daraus die Modul-Bitmap; gezeichnet wird sie vom Bildschirmcode.

Umfang: Byte-Modus, Fehlerkorrektur L oder M, Versionen 1–15 (die kleinste passende), alle acht Masken nach den vier Strafregeln bewertet, Format- und Versionsinformation, Reed-Solomon über GF(256) mit Primitivpolynom `0x11d`. Eingabe höchstens 300 Byte; die passen immer in Version ≤ 11 (L) bzw. ≤ 13 (M), die Versionen darüber erreicht man nur mit `min_version`.

### API

```c
static qr      code;    /* Ergebnis, 774 Byte */
static qr_work work;    /* Arbeitsspeicher, 1485 Byte, danach frei */

if (qr_encode(&code, &work, text, len, QR_ECC_L) == 0) {
    /* code.size Module je Seite; qr_module(&code, x, y) == 1: dunkel */
}
```

| Funktion | Zweck |
|---|---|
| `qr_encode(q, w, data, len, ecc)` | kleinste Version, beste Maske; `0` oder `-1` (Länge > 300, unbekannte Stufe) |
| `qr_encode_ex(..., min_version, mask)` | zusätzlich Mindestversion und feste Maske (0–7, `QR_MASK_AUTO`) |
| `qr_module(q, x, y)` | ein Modul lesen |
| `qr_render_pbm(q, out, cap, scale)` | PBM (P4) mit Ruhezone für den Host-Test; Länge oder `0` |

Bitmap: `q->modules`, 10 Byte je Zeile (`QR_STRIDE`, wortausgerichtet), Bit 7 des ersten Bytes ist x = 0 wie in einer Bitplane, 1 = dunkel, Bits rechts vom letzten Modul sind 0. Die Ruhezone (4 helle Module ringsum) gehört **nicht** zur Bitmap.

Zielcode: keine libc, kein `malloc`, keine Rekursion, keine variable Multiplikation oder Division (kein Laufzeithelfer nötig), Stackrahmen höchstens 60 Byte plus gesicherte Register, Tabellen `const` (GF-Logarithmen 766 Byte).

### Größe für den Pairing-Text

Der Testtext (161 Byte) ergibt auf Stufe L **Version 8, 49 × 49 Module**, auf Stufe M Version 9, 53 × 53.

| Version | Module je Seite | max. Byte L | max. Byte M |
|---|---|---|---|
| 7 | 45 | 154 | 122 |
| 8 | 49 | 192 | 152 |
| 9 | 53 | 230 | 180 |
| 10 | 57 | 271 | 213 |
| 11 | 61 | 321 | 251 |

Empfehlung: Stufe **L** (kleinere Module-Zahl; ein Bildschirm hat keine Schmutz- oder Knickschäden). Die Version hängt von der Länge der `ref` ab, die der Server liefert; der Zeichencode muss deshalb `code.size` auswerten und darf 49 nicht fest annehmen.

### Darstellung auf dem Hires-Schirm (640 × 256, 16 Farben)

**Ein Modul = 8 × 4 Pixel, nicht 4 × 4.** Ein PAL-Pixel in Hires ohne Interlace ist etwa halb so breit wie hoch (Verhältnis ≈ 0,52 : 1). Mit 4 × 4 Pixeln wäre der Code auf dem Bildschirm 1 : 1,9 gestreckt, womit Kamera-Decoder nicht zuverlässig zurechtkommen; mit 8 × 4 ist ein Modul praktisch quadratisch (1,04 : 1). Nebenbei ist ein Modul dann genau ein Byte breit: je Modul `0x00` oder `0xFF` in vier Zeilen schreiben, x auf ein Vielfaches von 8 legen, kein Schieben.

| Version | Module | Code in Pixeln | mit Ruhezone | passt in 640 × 256 |
|---|---|---|---|---|
| 7 | 45 | 360 × 180 | 424 × 212 | ja |
| 8 | 49 | 392 × 196 | 456 × 228 | ja |
| 9 | 53 | 424 × 212 | 488 × 244 | ja |
| 10 | 57 | 456 × 228 | 520 × 260 | nur mit 14 statt 16 Zeilen Ruhezone oben und unten |
| 11–13 | 61–69 | mit Ruhezone höher als 256 | – | 6 × 3 Pixel je Modul (Seitenverhältnis wie 8 × 4) |

Farben: dunkle Module in der dunkelsten Palettenfarbe, Hintergrund und Ruhezone in der hellsten, nicht invertiert. Die Darstellung auf echtem Schirm mit Telefonkamera ist noch nicht erprobt.

### Rechenzeit

FS-UAE, A500 mit 7 MHz (`tools/fsuae/a500-1mb-fast.fs-uae`), vbcc, gemessen mit `DateStamp` (1/50 s), 2026-11-27:

| Fall | Zeit |
|---|---|
| 161 Byte, L (V8), Maskenwahl | 2,5 s |
| 161 Byte, L (V8), feste Maske | 0,54 s |
| 161 Byte, M (V9), Maskenwahl | 2,9 s |
| 300 Byte, L (V11), Maskenwahl | 3,9 s |

Rund 2 s entfallen auf die Bewertung der acht Masken. Da der Pairing-Code regelmäßig mit neuer `ref` erneuert wird, kann der Client mit `qr_encode_ex(..., 1, 2)` eine feste Maske wählen; jede Maske ergibt einen gültigen Code, nur die Lesbarkeit ist nicht optimiert.

### Test

```sh
make qr-test      # braucht zbarimg (brew install zbar); python-qrcode landet in build/qr-venv
```

`tests/qr_test.c` schreibt jeden Code als PBM nach `build/qr/`, lässt ihn von `zbarimg` lesen (Ergebnis = Eingabe, byteweise) und vergleicht Version, Formatbits und alle Module mit **python-qrcode 8.2**: Pairing-Text in L und M (alle acht Masken), kurze Texte, jede Version 1–15 randvoll und mit einem Byte mehr, 300 Byte. Die Maskenwahl prüft der Test gegen eine eigene, schlichte Umsetzung der Strafregeln; python-qrcode bewertet etwas anders und wählt oft eine andere Maske, dann vergleicht der Test mit dessen Maske erzwungen. Zwei Eigenheiten der Referenzen: `segno` taugt nicht (es fügt vor den Füllbytes ein überzähliges `0x00` ein, sobald der Bitstrom schon auf einer Bytegrenze endet – im Byte-Modus immer), und python-qrcode stürzt bei Blöcken aus lauter Nullbytes ab (`glog(0)`); diesen Fall prüft nur `zbarimg`.

Einmalig von Hand geprüft (nicht Teil von `make`): die 68000-Übersetzung mit vbcc liefert unter vamos dieselben Bytes wie der Host für 1, 40, 161, 271 und 300 Byte in L und M sowie Version 15.

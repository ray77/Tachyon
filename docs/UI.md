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

## Bildschirm (ui/screen.c, Stand 2026-11-27)

Der Client läuft auf einem eigenen Intuition-Screen: 640×256 (PAL Hires, nicht interlaced), 4 Bitplanes = 16 Farben, ohne Titelzeile, mit einem randlosen Backdrop-Fenster in Bildschirmgröße, das die Tastatur per IDCMP liefert. Gezeichnet wird mit graphics.library in das RastPort dieses Fensters. Quellen: `ui/screen.h` (API), `ui/screen.c`, `ui/amiga13.h` (eigene Bindings für Kickstart 1.3); Demo und Test: `bench/amiga/screen_demo.c` (`make amiga-screen`, `make run-screen`).

### Warum Intuition-Screen und keine eigene Copperliste

- **Das Betriebssystem muss weiterlaufen.** TheWire13, der SANA-II-Treiber, DOS und die CLI arbeiten unter dem Client weiter (docs/NETWORK.md). Eine eigene Copperliste hält nur, wenn man COP1LC jeden Frame selbst setzt und `GfxBase->LOFlist` auf eine Leerliste zeigt (docs/TOOLCHAIN.md, „Stolperfallen“) – das ist ein Eingriff in den View, den Intuition sich teilt, und VERTB darf nicht abgeschaltet werden (DOS-Zeit, `WaitTOF`).
- **OpenScreen liefert alles, was wir brauchen:** die vier Bitplanes (80 KiB Chip), Copperliste, ColorMap (`LoadRGB4`), den Mauszeiger-Sprite und über das Fenster die Eingabekette input.device → Intuition → IDCMP. Kein Interrupt-Handler, kein Blitter-Besitz, keine Hardware-Register.
- **Preis:** jeder graphics.library-Aufruf geht durch Layer-Lock und ClipRects, etwa 1,5 ms Grundkosten pro Aufruf (Messung unten). Für einen Chat-Client reicht das; wo es eng wird, zeichnet man Bereiche statt des ganzen Bildschirms neu oder blittet vorbereitete Templates (siehe QR).

### Bindings für 1.3 (`ui/amiga13.h`)

Wie `net/bsdsocket13.h`: vbcc-`__reg`-Inline-Stubs mit den LVO-Offsets aus den NDK-3.2-FD-Dateien (`intuition_lib.fd`, `graphics_lib.fd`, `console_lib.fd`), Basis explizit in a6. Nur V33-Funktionen: `OpenScreen`/`CloseScreen`, `OpenWindow`/`CloseWindow`, `ModifyIDCMP`, `ShowTitle`, `SetAPen`/`SetBPen`/`SetDrMd`, `RectFill`, `SetRast`, `Move`/`Draw`, `Text`/`TextLength`, `OpenFont`/`CloseFont`/`SetFont`, `LoadRGB4`/`SetRGB4`, `BltTemplate`, `WaitTOF`, `RawKeyConvert` (console.device). Die Strukturen (`NewScreen`, `Screen`-Präfix bis `BitMap`, `NewWindow`, `Window`-Präfix bis `UserPort`, `RastPort`, `ViewPort`, `TextAttr`, `TextFont`, `IntuiMessage`, `InputEvent`) sind aus NDK 3.2 R4 (Include_H) kopiert, auf die seit V33 vorhandenen Felder beschränkt; die Offsets wurden mit vbcc gegen die NDK-Header geprüft (Screen.ViewPort 44, Screen.RastPort 84, Screen.BitMap 184, Window.RPort 50, Window.UserPort 86, RastPort 100 Bytes, ViewPort 40 Bytes) und entsprechen den 1.3-Includes.

### API (`ui/screen.h`)

| Funktion | Zweck |
|---|---|
| `scr_open()` / `scr_close()` | intuition.library 33, graphics.library 33, Screen, Fenster, Topaz 8, Palette, console.device; Fehlercodes `SCR_ERR_*`. `scr_close` räumt auch nach fehlgeschlagenem `scr_open` auf und streift vor `CloseWindow` die offenen IDCMP-Nachrichten ab (1.3-Regel). |
| `scr_set_palette(rgb4, n)` | bis 16 Einträge `0x0RGB` per `LoadRGB4`; Standardpalette: 0 Schwarz, 1 Hintergrund (dunkelblau), 2 Weiß, 3 WhatsApp-Grün, 4 Dunkelgrün, 5 Türkis, 6–8 Grau, 9 Rot, 10 Gelb, 11/12 Blau, 13 Orange, 14 Beige, 15 Hellgrün (`SCR_PAL_*`). |
| `scr_clear(pen)` | `SetRast` über den ganzen Schirm |
| `scr_fill(x, y, w, h, pen)`, `scr_hline`, `scr_vline` | `RectFill`, am Bildschirmrand geclippt |
| `scr_text(x, y, pen, s)` | Topaz 8 in JAM1 (nur Glyphenpixel), `(x, y)` = linke obere Ecke der Zelle, Rückgabe Breite in Pixeln; `scr_text_bg(x, y, pen, bg, s)` in JAM2; `scr_text_width(s)` |
| `scr_bitmap_1bpp(x, y, wm, hm, bits, scale, pen_on, pen_off)` | QR-Modulmatrix: `wm × hm` Module, zeilenweise, Zeilen auf ganze Bytes aufgefüllt, MSB zuerst, 1 = dunkel; jedes Modul wird `scale × scale` Pixel. Expandiert die Matrix zeilenweise (Fast-RAM-Puffer, Tabellen für Breite 1/2/4/8) in ein Chip-RAM-Template und zeichnet es mit einem `BltTemplate` (JAM2). `scr_bitmap_1bpp_rects` ist der `RectFill`-Fallback (Läufe gleichfarbiger Module), auch wenn kein Chip-RAM frei ist. |
| `scr_bitmap_1bpp_ex(x, y, wm, hm, bits, stride, sx, sy, pen_on, pen_off)` | allgemeine Form für den Encoder oben: `stride` Bytes je Quellzeile (`QR_STRIDE` 10), `sx × sy` Pixel je Modul – für den Bildschirm **8 × 4** (ein Byte je Modul, siehe QR-Abschnitt zum Seitenverhältnis), 6 × 3 für große Versionen. `scr_bitmap_1bpp_rects_ex` entsprechend. Aufruf für einen Code `q`: `scr_bitmap_1bpp_ex(x, y, q->size, q->size, q->modules, QR_STRIDE, 8, 4, 0, 2)` nach einem `scr_fill` der Ruhezone (4 Module = 32 × 16 Pixel) in Pen 2. |
| `scr_wait_key(ticks)` | wartet bis `ticks` Frames (1/50 s; `SCR_FOREVER`, 0 = nur abfragen) auf eine Taste: ASCII (8 Backspace, 9 Tab, 13 Return, 27 Escape, 127 Del, 32–126, ISO-8859-1 für Umlaute unter deutscher Keymap), `SCR_KEY_RAW \| Rawcode` für Tasten ohne Zeichen (Cursor `$4C–$4F`, F1–F10 `$50–$59`, Help `$5F`), `SCR_KEY_TIMEOUT`. Tastenloslassen und reine Qualifier werden übersprungen. Wartet mit `WaitTOF` (Task schläft) statt zu pollen; ohne Timeout mit `Wait` auf das Port-Signal. |
| `scr_translate_raw(code, qual)` | dieselbe Übersetzung für einen Rawcode (Selbsttest, Replay); `scr_last_key_source()` sagt, woher die letzte Taste kam |
| `scr_screen()`, `scr_window()`, `scr_rastport()`, `scr_font_height()`, `scr_font_width()`, `scr_console_ok()` | Zugriff für spätere Module |

Nicht reentrant: ein Screen pro Programm, Zustände statisch. Kein DOS-Bezug in `ui/screen.c` (nur exec, intuition, graphics, console.device); `SysBase` wird aus Adresse 4 gelesen.

### Tastatur

Das Fenster ist mit `IDCMP_RAWKEY | IDCMP_VANILLAKEY` geöffnet. Drei Wege liefern Zeichen:

1. **VANILLAKEY** (`'V'`): Intuition hat die Taste selbst über die Systemkeymap in ein Zeichen übersetzt. Kommt auf 1.3 für Tasten, die genau ein Zeichen ergeben.
2. **RAWKEY → `RawKeyConvert`** (`'C'`): console.device wird mit Unit `CONU_LIBRARY` (−1) geöffnet und als Library benutzt (LVO −48, V33). Keymap `NULL` = die Systemkeymap (Preferences bzw. `SetMap`), also funktionieren deutsche Belegungen (y/z, Umlaute) ohne eigene Tabelle. Dead-Key-Informationen (`IAddress`) werden durchgereicht. Mehrzeichen-Ergebnisse (CSI-Sequenzen der Cursor- und F-Tasten) werden zu `SCR_KEY_RAW | Code`.
3. **Eingebaute US-Tabelle** (`'T'`): nur wenn console.device nicht öffnet. Rawcodes `$00–$5F` (Reihe `` `1234567890-=\ ``, `qwertyuiop[]`, `asdfghjkl;'`, `zxcvbnm,./`, Ziffernblock, `$40` Space, `$41` Backspace, `$42` Tab, `$43` Enter, `$44` Return, `$45` Esc, `$46` Del), Shift und Caps Lock für Buchstaben, Ctrl bildet auf `$00–$1F` ab. Kein Deutsch.

keymap.library gibt es auf 1.3 nicht (ihre Funktionen sind laut `keymap_lib.fd` V36+), deshalb console.device. Der Selbsttest der Demo schickt Rawcodes durch denselben Pfad: `$20`→`a`, `$20`+Shift→`A`, `$01`→`1`, `$40`→Space, `$44`→13, `$41`→8, `$45`→27, `$4C`→`SCR_KEY_RAW|$4C`, `$A0` (Loslassen)→ignoriert – alle korrekt über `'C'` (FS-UAE, Standardkeymap usa0). Der VANILLAKEY-Weg und eine deutsche Keymap sind nur mit echtem Tastendruck prüfbar (FS-UAE-Lauf ohne Bildschirmzugriff).

### Messungen (FS-UAE, A500 zyklengenau, 512 KiB Chip + 1 MiB Fast, `make run-screen`, 2026-11-27)

Zeiten aus `DateStamp`-Ticks (20 ms), daher jede Operation mehrfach wiederholt und gemittelt.

| Schritt | Messung |
|---|---|
| `scr_open` (Libraries, OpenScreen, OpenWindow, OpenFont, LoadRGB4, console.device) | 220–260 ms |
| `scr_close` | 160 ms |
| Chip-RAM durch den Screen | **82 120 Bytes** = 81 920 (4 Planes × 80 × 256) + 200 (Copperliste, ColorMap, Sprite); Fast 2 016 Bytes (Screen-, Window-, Layer-Strukturen). Nach `scr_close` sind Chip und Fast exakt wieder auf dem Stand vor dem Öffnen. |
| `scr_clear` (SetRast 640×256×4 durch den Layer) | 88 ms |
| Titelzeile (`scr_fill` 640×12 + zwei `scr_text`) | 32 ms |
| `scr_fill` 36×14 | 1,7 ms |
| `scr_hline` 300 px / `scr_vline` 4 px | 1,5 ms (reine Aufruf-Grundkosten: Layer-Lock, ClipRect, Blitter-Setup) |
| `scr_fill` 228×228 | 30 ms |
| Textblock: 10 Zeilen à ≈45 Zeichen Topaz 8 + 1 JAM2-Zeile | 200 ms, also ≈ 18 ms pro Zeile, ≈ 0,4 ms pro Zeichen (`Text()` blittet in 1.3 Zeichen für Zeichen). Ein voller Schirm mit 80×32 Zeichen wäre ≈ 1 s. |
| QR 49 Module, 4 × 4 Pixel (196 × 196): Ruhezone + `scr_bitmap_1bpp` | **120 ms** (30 ms Ruhezone-Fill + ≈55 ms CPU-Expansion/AllocMem + 30 ms `BltTemplate` 196×196 in 4 Planes). Erste Fassung mit bitweiser Expansion direkt ins Chip-RAM: 456 ms; Expansion in Fast-RAM-Zeilenpuffer mit Wortkopien: 240 ms; tabellengetrieben (Nibble→Wort für Breite 4, Byte→Wort für 2, Byte je Modul für 8): 116–120 ms. |
| QR 49 Module, **8 × 4 Pixel** (392 × 196, das Format des Clients), `scr_bitmap_1bpp_ex`, Stride 10 | **188 ms** ohne Ruhezone |
| QR 49 Module, 6 × 3 Pixel (generischer Bitpfad) | 280 ms |
| dieselbe 4 × 4-Matrix per `scr_bitmap_1bpp_rects` | 1 830 ms (≈1 200 `RectFill`-Aufrufe à 1,5 ms) – nur Fallback |
| `scr_wait_key(500)` ohne Taste | 10 000 ms, Timeout tickgenau |
| Demo gesamt | ≈ 35 s inklusive 10 s Warten (FS-UAE-Lauf mit Boot ≈ 50 s, `make run-screen` wartet bis 60 s) |

Folgerungen für den Client: Bereiche statt des ganzen Schirms neu zeichnen (ein `scr_clear` kostet 4–5 Frames); Text zeilenweise und nur geänderte Zeilen; große Grafiken als Template vorbereiten und blitten. Ein eigener 8×8-Textrenderer direkt in die Planes (CPU, am Layer vorbei – im randlosen Backdrop-Fenster ohne Überlappung erlaubt) wäre die nächste Stufe, falls 0,4 ms/Zeichen stören.

### Grenzen von Kickstart 1.3

- **Keine Tags:** `OpenScreenTagList`/`OpenWindowTagList`, `SA_*`/`WA_*` sind V36. Es gibt nur `struct NewScreen`/`struct NewWindow`; Auflösung über `ViewModes` (`HIRES`, optional `LACE`), Typ `CUSTOMSCREEN`. Keine Display-IDs, kein Overscan-Prefs-Zugriff, keine `SA_Quiet`-Variante außer `SCREENQUIET`.
- **Titelzeile:** ein Custom-Screen hat immer die Titelzeilen-Layer; verbergen lässt sie sich nur hinter Backdrop-Fenstern (`ShowTitle(screen, FALSE)`), deshalb das randlose Backdrop-Fenster in voller Größe. `ScreenToFront` ist nach `OpenScreen` unnötig (der neue Screen liegt vorn); es sind keine Depth-Gadgets vorhanden, der Nutzer kann den Screen nicht per Maus nach hinten legen – Umschalten zur Workbench ginge nur per Amiga-N/M (Intuition-Tastenkürzel, funktioniert).
- **Fonts:** `NewScreen.Font` auf Topaz 8 (`FPF_ROMFONT`), zusätzlich `OpenFont` + `SetFont` auf das Fenster-RastPort, damit die Preferences-Schrift (Topaz 9 bei 60 Hz) nicht hineinspielt. Diskfonts bräuchten diskfont.library und Disk-Zugriff; nicht vorgesehen. `Text()` auf 1.3 ist langsam (siehe oben), `TextLength` wird genutzt, um Strings am rechten Rand zu kürzen (Text() rendert sonst den vollen String in den Clip).
- **Tastatur:** keine keymap.library; console.device als Library, siehe oben. `IDCMP_VANILLAKEY` ist vorhanden.
- **Speicher:** Backdrop-Fenster mit `WFLG_SIMPLE_REFRESH | WFLG_NOCAREREFRESH`, damit kein Smart-Refresh-Puffer angelegt wird; `WFLG_RMBTRAP` unterdrückt die Menüleiste bei rechter Maustaste.
- **Zeichnen im Fenster-RastPort statt im Screen-RastPort:** geht durch den Layer (Clipping, Lock) und kostet die genannten 1,5 ms pro Aufruf, bleibt aber mit Intuitions eigener Darstellung konsistent. Direktes Zeichnen in `Screen.RastPort` (ohne Layer) wäre schneller, würde aber die (verborgene) Titelzeile übermalen und bei Requestern/Alerts kollidieren.

### Offen

- Mausunterstützung (IDCMP_MOUSEBUTTONS/`MOUSEMOVE`) bei Bedarf; Qualifier-Rückgabe für Shift/Ctrl-Kombinationen.
- Prüfung des VANILLAKEY-Pfades und einer deutschen Keymap mit echtem Tastendruck (manuell in FS-UAE).
- Eigener Textrenderer, falls die Chat-Ansicht mehr als ein paar Zeilen pro Sekunde schreiben muss.

# Toolchain (Stand 2026-11-26, macOS arm64)

Alles läuft als Cross-Build auf dem Mac; Ziel ist eine Kickstart-1.3-Hunk-Executable, die in FS-UAE auf einem A500 (512 KiB Chip + 1 MiB Fast) getestet wird.

| Werkzeug | Version | Ort | Herkunft |
|---|---|---|---|
| vbcc (`vbccm68k`, `vc`, `vprof`) | 0.9h (Quelle vom 2025) | `~/opt/vbcc/bin` | aus `http://www.ibaug.de/vbcc/vbcc.tar.gz` nativ mit clang gebaut (`make TARGET=m68k`) |
| vbcc-Targets `m68k-kick13`, `m68k-amigaos` + `config/` | gleiche Release | `~/opt/vbcc/targets`, `~/opt/vbcc/config` | aus `vbcc_linux_x64.tar.gz` entnommen (m68k-Objekte, hostunabhängig) |
| vasm `vasmm68k_mot` | 1.8e | `/opt/homebrew/bin` | brew tap `prebuilt-amiga-dev-tools` |
| vlink | **nicht verfügbar** | – | siehe unten |
| NDK 3.2 R4 (Include_H, Include_I, FD, SFD, lib) | 3.2 | `~/opt/ndk32` | Aminet `dev/misc/NDK3.2.lha` |
| amitools (`xdftool`, `hunktool`, `vamos`) | aktuell | `~/opt/amitools-venv`, Links in `~/opt/bin` | pip in eigenem venv |
| FS-UAE | 3.2.35 | `/Applications/FS-UAE.app` | brew cask |
| vAmiga | 5.1 | `/Applications/vAmiga.app` | brew cask (manuelle Gegenprobe, zyklusgenau) |
| Go | 1.27.4 | brew | Testvektor-Orakel (`crypto/ecdh`), später Whatsmeow-Referenz |
| Kickstart 1.3 rev 34.5 (A500) | 256 KiB, MD5 `82a21c1890cae844b3df741f2762d48d` | `~/Documents/FS-UAE/Kickstarts/kick13-34.5-a500.rom` | eigene ROM-Kopie des Nutzers |
| Workbench 1.3.3 Boot-ADF | | `~/Documents/FS-UAE/Floppies/wb133-boot.adf` | eigene Kopie, derzeit nicht benötigt |

## Kein vlink: Build-Weg ohne Linker

Frank Wille bietet den vlink-Quelltext seit 2026 nicht mehr zum Download an (nur per E-Mail-Anfrage an menschliche Entwickler), und Binaries gibt es nur für Amiga/MorphOS/OS4/TOS/MiNT/Win64. Daher:

```text
C-Quellen ──(Unity-Build: bench/amiga/unity.c)──► vbccm68k ──► eine .s-Datei
bench/amiga/startup.s  INCLUDE  dieser .s-Datei ──► vasmm68k_mot -Fhunkexe -kick1hunks ──► Executable
```

- Freestanding: keine `vc.lib`, kein `startup.o`; Betriebssystemaufrufe über die Inline-Header der vbcc-Targets (`proto/*.h`) direkt an die Library-Basen.
- Unity-Build, weil vbcc lokale Labels (`l66`) pro Übersetzungseinheit vergibt und vasm sie sonst doppelt sieht.
- vbcc erwartet einige Laufzeitroutinen aus `vc.lib`: `__divu` (unsigned 32/32), `__divs`/`__mods` (signed), bei `long long` auch `__divuint64` u. a. Nur `__divu` liegt in `bench/amiga/startup.s`. Regel für Zielcode: keine Signed-Division/-Modulo (Zähler oder Shifts verwenden), keine 64-Bit-Arithmetik. Verstöße fallen beim Assemblieren als `undefined symbol <__divs>` auf.
- Unity-Build heißt: `static`-Namen müssen über alle eingebundenen C-Dateien eindeutig sein (`K` in sha256.c/sha512.c → `K256`).
- Vorteil für dieses Projekt: vollständige Kontrolle über Speicherlayout und Sektionen (Chip/Fast), keine libc-Abhängigkeit im Krypto-Kern.
- Optionen, falls später doch ein Linker nötig wird: vlink-Quelltext beim Autor anfragen; GitHub-Spiegel `8l/vlink` (ältere Version, 2023); oder `m68k-elf-gcc` aus brew plus `elf2hunk`.

## Befehle

```bash
make host-test     # Referenz auf dem Mac gegen RFC 7748 + 256 Go-Vektoren
make amiga         # build/amiga/x25519bench
make run           # FS-UAE starten, auf SYS:done warten, SYS:result.txt ausgeben
make vectors       # Zufallsvektoren mit Go neu erzeugen
```

`tools/run-fsuae.sh <exe>` legt `build/fsuae-run/dh0` als Verzeichnis-Festplatte (Bootpriorität 6) an, mit `S/Startup-Sequence` = Programm + `EndCLI`. Unter 1.3 gibt es keine residenten C:-Kommandos, deshalb muss das Programm selbst `SYS:result.txt` und zum Schluss `SYS:done` schreiben.

Konfiguration: `tools/fsuae/a500-1mb-fast.fs-uae` (A500, `accuracy = 1`, `chip_memory = 512`, `slow_memory = 0`, `fast_memory = 1024`).

## Stack

Der CLI-Stack unter Kickstart 1.3 ist 4000 Bytes. `bench/amiga/startup.s` schaltet deshalb vor `main()` auf einen eigenen 64-KiB-Stack in der BSS-Sektion um und zurück vor dem `rts`. Symptom ohne Umschaltung: `xeddsa_verify` (≈ 3,5 KiB Stackbedarf durch Fenstertabellen und gecachte Punkte) kam nie zurück, während `ed25519_verify` knapp durchlief. Für den späteren Client gilt: alle Krypto-Pfade auf Stackbedarf messen, großer eigener Stack oder statische Arbeitsbereiche.

## Offene Punkte

- Zeitmessung derzeit über `DateStamp()` (1/50 s); CIA-Timer (E-Clock 709 379 Hz) für Mikrobenchmarks nachrüsten.
- Hunk-Speicherflags: `section text,code_f` setzt das Fast-Flag, geht aber verloren, sobald vbccs eigene `section text,code`-Zeilen dieselbe Sektion erneut öffnen (geprüft mit `hunktool info`). Für Blitter-Puffer später eigene `data_c`/`bss_c`-Sektionen in startup.s; AmigaOS bevorzugt ohnehin Fast-RAM bei `MEMF_ANY`.
- FS-UAE automatisch beenden statt per `kill`; alternativ vAmiga-Headless prüfen.
- Echte Hardware-Messung steht aus.

## vamos als schnelle Korrektheitsschleife (2026-11-26)

`make vamos` führt das fertige Amiga-Binary mit amitools' **vamos** aus (Musashi-68000 in C, exec/dos.library in Python emuliert, kein Kickstart nötig). Der komplette WhatsBench-Lauf, der in FS-UAE (zyklengenau) 6–7 Minuten dauert, ist dort in Sekunden fertig. Einsatz: asm-gegen-C-Vergleiche, Vektorprüfungen, Debug-Ausgaben. Nicht brauchbar für: Zeiten (DateStamp-Ticks sind bedeutungslos), Custom-Chip-Code (Blitter/Copper/CIA gibt es nicht), Address-Error-Prüfung (vamos toleriert ungerade Long-Zugriffe, die echte 68000 nicht tolerieren – deshalb lesen/schreiben die Assembler-Blockfunktionen Nutzdaten byteweise).

Installation: in das amitools-venv zusätzlich `pip install greenlet machine68k` (beides fehlte nach der Grundinstallation; ohne machine68k meldet vamos „can't create raw machine“). Aufruf: `vamos -q -V sys:<dir> -s 64 test` – `-s 64` setzt 64 KiB Stack, `SYS:` zeigt auf das Arbeitsverzeichnis mit `result.txt`.

## vbcc-Fehlkompilierung (2026-11-26)

vbcc 0.9h mit `-O=1023 -speed -cpu=68000` übersetzt in `comb_select` den Ausdruck `(digit ^ (int8_t)neg) - (int8_t)neg` mit `int8_t digit` falsch: Es verwendet den vorher für `(uint8_t)digit >> 7` nullerweiterten Wert auch dort, wo C die vorzeichenerweiterte Promotion verlangt. Ergebnis: `|digit|` ist für negative Ziffern falsch, die Comb-Tabellenauswahl liefert die Identität, `x25519_base_comb` ist falsch – nur auf dem Ziel, der Host-Compiler macht es richtig. Workaround: Parameter als `int` übergeben und das Vorzeichen ohne Byte-Casts aus dem `uint32_t`-Shift ableiten. Regel für dieses Projekt: keine Byte-Casts in signed/unsigned-gemischten Ausdrücken; jede neue Funktion zuerst mit `make vamos` gegen die Host-Vektoren prüfen.

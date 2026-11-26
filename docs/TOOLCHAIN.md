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
- vbcc erwartet einige Laufzeitroutinen aus `vc.lib` (`__divu` für 32/32-Division, bei `long long` auch `__divuint64`). `__divu` liegt in `bench/amiga/startup.s`; 64-Bit-Arithmetik wird im Zielcode vermieden.
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

## Offene Punkte

- Zeitmessung derzeit über `DateStamp()` (1/50 s); CIA-Timer (E-Clock 709 379 Hz) für Mikrobenchmarks nachrüsten.
- Hunk-Speicherflags: `section text,code_f` setzt das Fast-Flag, geht aber verloren, sobald vbccs eigene `section text,code`-Zeilen dieselbe Sektion erneut öffnen (geprüft mit `hunktool info`). Für Blitter-Puffer später eigene `data_c`/`bss_c`-Sektionen in startup.s; AmigaOS bevorzugt ohnehin Fast-RAM bei `MEMF_ANY`.
- FS-UAE automatisch beenden statt per `kill`; alternativ vAmiga-Headless prüfen.
- Echte Hardware-Messung steht aus.

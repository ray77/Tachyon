# Netzwerkschicht: TCP/IP unter Kickstart 1.3 (Stand 2026-11-27)

Der Krypto- und Transportpfad (`crypto/ref/tls13.c`, `ws.c`, `noise.c`, `heartbeat.c`) ist E/A-agnostisch: der Aufrufer schiebt Bytes zwischen Socket und `tls13_input` / `t->out`. Was fehlte, war der Socket selbst. Kickstart 1.3 bringt kein TCP/IP mit; die Wahl fiel auf **TheWire13** (Aminet `comm/tcp/TheWire13.lha`, v1.9.1 vom 2026-11-02, Marcel Jähne, Freeware ohne Quelltext, OS 1.3+, 68000): ein eigener Stack-Task plus eine `bsdsocket.library` im AmiTCP-Stil, SANA-II-Treiber darunter. Damit bleibt die Netzwerkkarte austauschbar – jeder SANA-II-Treiber (plipbox, A2065, Zorro-LAN-IDE, a314eth, …) wird nur in der Konfiguration eingetragen.

## 1. TheWire13 – was der Stack braucht

Archiv (152 860 Bytes gepackt, 288 024 entpackt, 19 Dateien):

| Datei im Archiv | Ziel auf dem Amiga | Zweck |
|---|---|---|
| `c/TheWire13` | `C:` | der Stack (eigener Task, läuft aus der Shell: `run >NIL: C:TheWire13`) |
| `libs/bsdsocket.library` | `LIBS:` | API für Anwendungen, Version 4.4.0 („TheWire13 bsdsocket.library 4.4.0“); öffnet nur, wenn der Stack-Task läuft (öffentlicher Port `amitcp13.stack`) |
| `libs/amitls13.library` | `LIBS:` | TLS für `mini_wget` – **nicht** verwendet, Tachyon bringt eigenes TLS 1.3 mit |
| `s/thewire13.conf` | `S:` | Konfiguration, s. u. |
| `s/mini_ntp.conf` | `S:` | Zeitserver für `mini_ntp` (`server = ptbtime1.ptb.de`, `timezone = 1`, `dst = eu`) |
| `c/mini_ping`, `mini_nslookup`, `mini_ntp`, `mini_wget` | `C:` | Diagnose; `mini_ntp` stellt die Uhr – der A500 hat keine RTC und bootet 1978 (Zertifikatsgültigkeit!) |
| `devs/networks/plipbox.device`, `enc62413.device` | `DEVS:Networks/` | mitgelieferte SANA-II-Treiber (Parallelport-Ethernet plipbox; Zorro-LAN-IDE-CP) |

Die Readme nennt zusätzlich `S:amitcp13.hosts` (lokale Hosts-Datei, optional, nicht im Archiv).

`S:thewire13.conf` (so wie ausgeliefert, Schlüssel = Wert):

```text
device=devs:networks/a314eth.device
unit=0
dhcp=1
ip=192.168.7.11
netmask=255.255.255.0
gateway=192.168.7.1
dns=192.168.25.1
dns2=8.8.8.8
hostname=amiga13
domain=lan
mtu=1500
log_enabled=0
```

Weitere dokumentierte Schlüssel (History 1.7): `streaming_mode=1`, `socket_rx_buffer=65535`, `sana_rx_requests=64`, `tcp_window=65535`. Schlägt DHCP fehl, nimmt der Stack die statischen Werte derselben Datei. Beim Start druckt er IP, Netzmaske, Gateway und DNS; bei Fehlern „SANA open failed“, „RX init failed“, „DHCP failed“ (Strings im Binary).

### bsdsocket.library: was dokumentiert ist

Die Readme führt keine vollständige Funktionsliste („bsdsocket.library support is still incomplete and evolving“); aus den History-Einträgen 1.6–1.9.1 sind belegt: `socket`, `connect` (blockierend und nicht blockierend: EINPROGRESS/EALREADY/EISCONN), `bind`, `listen`, `accept`, `send`, `recv` (mit `MSG_DONTWAIT`, Teilsendungen erhalten, unbekannte Flags abgelehnt), `sendto`, `recvfrom`, `select`/`WaitSelect` (Deskriptoren und Timeouts validiert, Schreibbereitschaft meldet den Erfolg eines nicht blockierenden Connects, EOF/Fehler über Lese-/Schreibbereitschaft statt `exceptfds`, Exec-Signale), `setsockopt` (SO_REUSEADDR, SO_KEEPALIVE, SO_DONTROUTE, SO_BROADCAST, SO_OOBINLINE, TCP_NODELAY; sonst ENOPROTOOPT), `getsockopt(SO_ERROR)`, `getsockname`, `gethostbyname` (eigener Resolver mit TTL-Cache, mehrere DNS-Server, `localhost` intern), `gethostname`, `SetSocketSignals` (Interrupt-/IO-/Urgent-Masken; Ctrl-C-Default), `Errno` und Errno-Zeiger (`SetErrnoPtr`), `SocketBaseTagList`. EAGAIN/EWOULDBLOCK = 35 (Amiga-kompatibel).

Tachyon benutzt davon: `socket`, `connect`, `send`, `recv`, `WaitSelect`, `CloseSocket`, `setsockopt(TCP_NODELAY)`, `gethostbyname`, `SetSocketSignals(0,0,0)`, `Errno`.

## 2. Emulation: FS-UAE mit A2065 auf slirp

FS-UAE 3.2.35 (WinUAE-Kern 3300b2) emuliert die **A2065** (Commodore Zorro-II-Ethernet, Am7990 LANCE) und verbindet sie über **slirp** (User-Mode-NAT, nur ausgehende Verbindungen) mit dem Netz des Hosts. Option in `tools/fsuae/a500-1mb-fast-net.fs-uae`:

```text
network_card = a2065
```

Im Log: `set option "a2065" to "slirp"`, `A2065: 'slirp' 00:00:00:32:33:34`, `Card 2: Z2 0x00e90000 64K IO A2065 Z2 Ethernet`. Adressen von slirp: Gast 10.0.2.15/24, Gateway 10.0.2.2, DNS 10.0.2.3 (DHCP/BOOTP vorhanden). Ein realer A500 hat keinen Zorro-Slot; in der Emulation ist die Karte eine Autoconfig-Erweiterung wie das Fast-RAM – für den Test des Stacks ausreichend, die Hardwarefrage löst später der SANA-II-Treiber der echten Karte.

Treiber: TheWire13 liefert keinen `a2065.device`. Aminet `driver/net/a2065v216a.lha` (Steve Lemieux, 1998, 5 182 Bytes, „a2065 2.16a (4.3.98)“, Commodore-Treiber v2.16 mit Ethernet-Framing-Fix) kommt nach `DEVS:Networks/a2065.device`. Beide Archive liegen entpackt unter `build/thewire13/` und `build/a2065dev/` (nicht im Repository; Freeware-Binaries Dritter, von aminet.net geladen).

Nicht gangbar: FS-UAEs eingebautes `uaenet.device` (im Binary vorhanden, bräuchte pcap; unter macOS/slirp nicht nutzbar), plipbox (Parallelport-Hardware, nicht emuliert), NE2000/PCMCIA (nur A600/A1200). vamos (amitools) emuliert eine `bsdsocket.library` v4 auf dem Host-Netz – kein Stack, kein SANA-II, aber ein schneller Funktionstest des Amiga-Binaries (`make vamos-probe`).

Boot ohne Workbench: Kickstart 1.3 hat keine residenten `C:`-Kommandos; `tools/run-fsuae-net.sh` holt `Run` und `Wait` mit `xdftool` von der Workbench-1.3-Diskette des Nutzers und baut DH0:

```text
DH0:C/TheWire13, Run, Wait, mini_*      DH0:Libs/bsdsocket.library
DH0:Devs/Networks/a2065.device          DH0:S/thewire13.conf (device=devs:networks/a2065.device, slirp-Adressen)
DH0:S/Startup-Sequence:  run >SYS:stack.log C:TheWire13 / wait 8 / test / endcli
DH0:seed.bin (64 Byte /dev/urandom)  now.txt (UTC)  waip.txt (dig)  gap.txt (GAP)
```

## 3. Entwurf: `net/bsdsock_io.c`

`net/bsdsocket13.h` deklariert die bsdsocket-ABI ohne SDK: Library-Vektoren (`-30 socket`, `-54 connect`, `-66 send`, `-78 recv`, `-90 setsockopt`, `-120 CloseSocket`, `-126 WaitSelect`, `-132 SetSocketSignals`, `-162 Errno`, `-210 gethostbyname`, …) mit den AmiTCP-Registerkonventionen als vbcc-Inline-Stubs, 4.4BSD-Strukturen (`sockaddr_in` mit `sin_len`, `fd_set` mit 64 Deskriptoren, `timeval`). Diese ABI teilen alle Amiga-Stacks (AmiTCP, Miami, Roadshow, UAE), TheWire13 ebenso – daher ist der Adapter die gesamte Netzabhängigkeit des Clients.

`net/bsdsock_io.c` (≈ 150 Zeilen):

| Funktion | Verhalten |
|---|---|
| `bsdsock_open` | `OpenLibrary("bsdsocket.library")`, `SetSocketSignals(0,0,0)` – keine Break-Signale in blockierende Aufrufe; der Client pollt mit Timeouts |
| `bsdsock_stack_ready` | `socket()` + `CloseSocket()` – meldet, ob der Stack-Task antwortet (die Probe wartet so bis 60 s auf den Start von TheWire13) |
| `bsdsock_resolve` | `gethostbyname`, sonst Dotted-Quad aus der Konfiguration (`SYS:waip.txt`) |
| `bsdsock_connect` | `socket`, `connect` (blockierend), `TCP_NODELAY` (TLS-Records und WS-Frames gehen als Ganzes) |
| `bsdsock_send` | Schleife über `send`, bis alles übergeben ist |
| `bsdsock_recv` | `WaitSelect` mit Timeout, dann ein `recv`: > 0 Bytes, 0 Timeout, −1 geschlossen/Fehler (`io->err`, `io->fail`) |

Kooperativ und einfädig: nichts läuft im Interrupt oder in einem zweiten Task. Der Herzschlag (`heartbeat.c`) feuert aus `CRYPTO_YIELD()` zwischen Feldoperationen und sendet über `tls13_send` + `bsdsock_send`; `tls13_input` wird nur aus `bsdsock_recv`-Ergebnissen gefüttert. Deshalb kann die TLS-Zustandsmaschine nie reentrant laufen.

### Die Probe

`tests/wa_probe_core.c` ist die plattformneutrale Protokolllogik (TLS 1.3 mit Pin-Menge {G2-Wurzel, CA1}, optionaler Zertifikatscache, WebSocket-Upgrade, Noise-XX-ClientHello/ServerHello/ClientFinish mit XEdDSA-Prüfung der WhatsApp-Zertifikatskette, Herzschlag, Entschlüsselung des ersten Server-Frames) über einer Schnittstelle aus `send`, `recv(timeout)`, `reconnect`, `now_ms`, `log`. Freestanding wie `crypto/ref`: eigene Kopier-/Vergleichs-/Formatfunktionen (`wa_fmt`), Protobuf-Werte 32-bittig (vbcc bräuchte für 64-Bit-Division `vc.lib`). `tests/wa_probe.c` ist die POSIX-Seite (unverändert alle Schalter: `GAP`, `WAIP`, `tunnel`, `TLS_CACHE`, `TLS_HOLD`, `WA_PROBE_DEBUG/DUMP`), `bench/wa_probe_amiga.c` die Kickstart-1.3-Seite:

- Zeit: `DateStamp()` → Millisekunden; die Kalenderumrechnung (Tage seit 1978 → `YYYYMMDDHHMMSSZ`) liefert den Zeitstring für die Zertifikatsprüfung, wenn die Amiga-Uhr plausibel ist (Jahr ≥ 2025), sonst `SYS:now.txt` vom Host, sonst keine Gültigkeitsprüfung (geloggt). Auf echter Hardware übernimmt das `mini_ntp` oder ein eigener SNTP-Aufruf über denselben Adapter.
- Zufall: `SYS:seed.bin` (64 Byte `/dev/urandom` des Hosts) seedet den HMAC-DRBG – der emulierte A500 hat keine Entropiequelle (docs/RNG.md); der spätere Client sammelt sie aus Eingabe- und Paket-Timing.
- Ausgabe: Konsole und `SYS:result.txt` mit Zeitstempeln, `TIMING:`-Zeile (DNS, TCP, TLS, WS, ServerHello, ClientFinish, angenommen), `RESULT:`-Zeile, zuletzt `SYS:done`.

Ziele: `make amiga-probe` (Binary 178 KiB), `make run-probe GAP=0` (FS-UAE, Minuten), `make vamos-probe` (Sekunden, Host-Netz).

## 4. Ergebnisse

Siehe docs/BENCHMARKS.md Schritt 17.

### vamos (Musashi-68000, vamos' eigene bsdsocket.library v4 auf dem Host-Netz)

Das unveränderte Amiga-Binary erreicht gegen web.whatsapp.com: DNS 60 ms, TCP 40 ms, TLS 1.3 bei 0,18 s, WebSocket offen bei 0,38 s, ServerHello 0,62 s, ClientFinish 0,84 s, erster verschlüsselter Server-Frame (695 → 679 Bytes, pair-device IQ) bei 1,24 s – `RESULT: handshake ACCEPTED`. Damit sind Registerkonventionen und Strukturen in `bsdsocket13.h` bestätigt (vamos implementiert dieselbe AmiTCP-ABI); Zeiten sind dort bedeutungslos (keine Zyklen).

## 5. Offen

- Entropiesammler und Seed-Datei (docs/RNG.md) statt `SYS:seed.bin`.
- Zeit per SNTP über den Adapter (ein UDP-Datagramm; braucht `sendto`/`recvfrom` im Adapter) oder `mini_ntp` in der Startup-Sequence.
- Zertifikatscache persistent in `ENVARC:` (heute nur im Speicher der Probe).
- Nicht blockierender `connect` mit Timeout (heute blockierend; TheWire13 meldet EINPROGRESS, `WaitSelect` auf Schreibbereitschaft).
- Echte Hardware: SANA-II-Treiber der tatsächlichen Karte in `S:thewire13.conf` eintragen, sonst keine Codeänderung.

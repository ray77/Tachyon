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

**utility.library für 1.3.** Der a2065.device öffnet beim Init `utility.library` (ab Kickstart 2.0 im ROM, unter 1.3 nicht vorhanden): `OpenDevice` scheiterte mit rc −1, TheWire13 meldete „SANA open failed“. `tools/amiga/utility13.c` + `utility13.s` bauen deshalb `LIBS:utility.library` 37.0 (RTF_AUTOINIT-Romtag, Open/Close/Expunge; alle öffentlichen V36/V37/V39-Funktionen: Tag-Listen, `CallHookPkt`, `Amiga2Date`/`Date2Amiga`/`CheckDate`, `SMult32`/`UMult32`/`SDivMod32`/`UDivMod32`, `Stricmp`/`Strnicmp`/`ToUpper`/`ToLower`, `ApplyTagChanges`, `SMult64`/`UMult64`, `GetUniqueID`; `PackStructureTags` und die Named-Object-Funktionen liefern 0). `make utility13-test` prüft 32 Ergebnisse unter vamos (`-O utility.library=mode:amiga`, sonst nimmt vamos seine eigene Nachbildung, deren `NextTagItem` und `UMult64` falsch rechnen). Mit der Bibliothek öffnet der Treiber (rc 0) und `S2_DEVICEQUERY` antwortet; dasselbe hilft jedem anderen 2.0-Treiber, den ein Nutzer einbinden will.

Werkzeuge daneben: `tools/amiga/sana2_probe.c` (`make run-sana2`) spricht den SANA-II-Treiber ohne Stack an – `S2_DEVICEQUERY`, `S2_GETSTATIONADDRESS`, `S2_CONFIGINTERFACE` mit drei Kandidatenadressen, `S2_ONLINE`, eine ARP-Anfrage an das slirp-Gateway 10.0.2.2 und die Antwort über `CMD_READ` –, `tools/amiga/sana2_hold.c` (`NET_HOLD=1`) konfiguriert die Schnittstelle mit ihrer ROM-Adresse und hält das Gerät offen.

Nicht gangbar: FS-UAEs eingebautes `uaenet.device` (im Binary vorhanden, bräuchte pcap; unter macOS/slirp nicht nutzbar), plipbox (Parallelport-Hardware, nicht emuliert), NE2000/PCMCIA (nur A600/A1200). vamos (amitools) emuliert eine `bsdsocket.library` v4 auf dem Host-Netz – kein Stack, kein SANA-II, aber ein schneller Funktionstest des Amiga-Binaries (`make vamos-probe`).

Boot ohne Workbench: Kickstart 1.3 hat keine residenten `C:`-Kommandos; `tools/run-fsuae-net.sh` holt `Run` und `Wait` mit `xdftool` von der Workbench-1.3-Diskette des Nutzers und baut DH0:

```text
DH0:C/TheWire13, Run, Wait, mini_*      DH0:Libs/bsdsocket.library
DH0:Devs/Networks/a2065.device          DH0:S/thewire13.conf (device=devs:networks/a2065.device, slirp-Adressen)
DH0:S/Startup-Sequence:  run >SYS:stack.log C:TheWire13 / wait 8 / test / endcli
DH0:seed.bin (64 Byte /dev/urandom)  now.txt (UTC)  waip.txt (dig)  gap.txt (GAP)
DH0:C/SetMap (Boot-Disk System/) + DH0:Devs/Keymaps/d (Extras-Disk)   Startup-Sequence: setmap d  (KEYMAP=d, WBEXTRAS=...)
```

Tastaturbelegung: FS-UAE schickt die physischen Tastenpositionen des Mac-Keyboards, die ROM-Keymap ist `usa0`. Ohne `SetMap` sieht die GUI deshalb y/z vertauscht und keine Umlaute (Live-Lauf 8, 2026-11-28). `tools/run-fsuae-net.sh` kopiert `System/SetMap` von der Boot-Disk und `Devs/Keymaps/$KEYMAP` von der Extras-Disk (`WBEXTRAS`, Standard `~/Documents/FS-UAE/Floppies/wb133-extras.adf`) und setzt `setmap d` vor den Probe-Start; `KEYMAP=` schaltet es ab, fehlt die Extras-Disk, bleibt es bei der US-Belegung (Meldung im Log). Beide Dateien sind Commodore-Material und liegen nur unter `build/`. Pfeiltasten: ohne angeschlossenen Joystick legt FS-UAE die Cursortasten (und rechte Ctrl/Alt) als Tastatur-Joystick auf Port 1, der Amiga sieht sie dann nicht (Lauf 14: kein Chatwechsel in der GUI); `tools/fsuae/a500-1mb-fast-net.fs-uae` setzt deshalb `joystick_port_1 = none`.

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

**2026-11-27, FS-UAE, `make run-probe GAP=0`: `RESULT: handshake ACCEPTED by web.whatsapp.com with our TLS 1.3/WS/Noise stack, 0.00 s hold, 12 pongs`.** DNS 0,9 s, TCP 0,8 s, TLS 1.3 31,8 s, WebSocket 0,5 s, Noise 51,8 s (12 Pongs), erster entschlüsselter Server-Frame nach 105 s. Zeiten und Einordnung: docs/BENCHMARKS.md Schritt 17. **Abends derselbe Lauf mit den drei X25519-Schlüsselpaaren vor dem Connect (parallel zum Stackstart) und dem Cache für das Noise-Zwischenzertifikat (`SYS:noisecache.bin`, vorgewärmt vom Host-Lauf): Noise 40,1 s (9 Pongs), Verbindungsfenster 78,2 s statt 100,5 s, erster Frame nach 92 s – BENCHMARKS.md Schritt 18.**

Vier Hindernisse lagen zwischen „Stack startet“ und diesem Ergebnis, alle ohne Quelltext von TheWire13 oder dem Treiber gelöst:

| Symptom | Ursache | Lösung |
|---|---|---|
| `OpenDevice` a2065.device rc −1, „SANA open failed“ | der Treiber öffnet `utility.library` (erst ab Kickstart 2.0) | eigene `LIBS:utility.library` 37 (`tools/amiga/utility13.*`) |
| `S2_CONFIGINTERFACE` io_Error 5 (`S2ERR_BAD_ADDRESS`) | TheWire13 konfiguriert mit der *aktuellen* Adresse der unkonfigurierten Einheit (ff:ff:ff:ff:ff:ff), der Treiber nimmt nur seine ROM-Adresse; vorkonfigurieren (`sana2hold`) endet in `S2ERR_BAD_STATE`, auch fatal | `a2065fix.device` (`tools/amiga/sanafix.*`): Wrapper, konfiguriert immer die ROM-Adresse, gibt sie in `ios2_SrcAddr` zurück, meldet „schon konfiguriert“ als Erfolg |
| Programm startet nicht (kein `result.txt`), `Avail`: Fast 464 Bytes frei | TheWire13 reserviert beim Start 12 × 40 KiB TCP-Pool (kein Konfigurationsschlüssel) | Programm vor dem Stack starten; der Pool fällt auf 4 PCBs (240 KiB) zurück |
| ARP-Antworten kommen nie an (DNS scheitert, `connect` ETIMEDOUT) | der Wrapper gab den privaten `ios2_BufferManagement`-Zeiger des Treibers nicht an den Stack weiter (SANA-II: muss in jedem Request stehen) | Zeiger nach `OpenDevice` in den Request des Stacks kopieren |

Daneben: `run >file cmd` leitet nur Runs eigene Ausgabe um, `run >NIL: cmd >file` die des Programms; der CLI-Stack von 4000 Bytes wird vor dem Stack auf 50000 gesetzt (`stack`); `echo` braucht Anführungszeichen; ein Fehler eines Kommandos bricht die Startup-Sequence ab (Failat 10).

### Ablauf einer Verbindung (Auszug `SYS:result.txt`, FS-UAE)

```text
+   3.26s  net: bsdsocket.library v4 open, stack answers (socket() ok) after 6 tries
+   4.18s  dns: web.whatsapp.com -> 57.144.245.32 in 900 ms
+   5.02s  tcp: connected to 57.144.245.32:443 in 820 ms
+   8.44s  tls: X25519 key pair ready (3.42 s)
+  40.18s  tls: chain completed at pin 1 (CA1 intermediate), 1 RSA verification
+  40.28s  tls: TLS 1.3 TLS_AES_128_GCM_SHA256 / X25519 connected, 2 certificates verified against the pin set {G2 root, CA1 intermediate}, RSA-PSS CertificateVerify and Finished verified
+  40.78s  ws: wss://web.whatsapp.com/ws/chat open
+  47.60s  noise: ClientHello sent
+  48.98s  noise: ServerHello received (350 bytes)
+  89.40s  noise: intermediate certificate serial 3 signed by WhatsApp's root key: VERIFIED
+ 100.52s  noise: leaf certificate serial 366 signed by the intermediate, key == server static: VERIFIED
+ 100.52s  noise: 0 X25519 ladders during the hold, 12 pongs sent, heartbeat error 0
+ 100.80s  noise: ClientFinish sent 51.80 s after ServerHello
+ 105.48s  noise: first encrypted server frame: 695 bytes ciphertext -> 679 bytes plaintext, first bytes 00 f8 0a 19 (binary node, pair-device IQ)
TIMING: dns 900 ms, tcp connect 820 ms, tls 35240 ms, ws 35760 ms, server hello 43940 ms, client finish 95780 ms, accepted 100460 ms (ms since probe start, 12 pongs)
RESULT: handshake ACCEPTED by web.whatsapp.com with our TLS 1.3/WS/Noise stack, 0.00 s hold, 12 pongs
```

Stackseitig (`SYS:stack.log`, `log_enabled=1`): ARP 10.0.2.3 → 52:55:0a:00:02:03, DNS-Antwort 115 Bytes, `tcp_connect_prepare local_port=51463 remote=57.144.245.32:443`, `SYNACK ack validated`, `TCP state -> ESTABLISHED ... rx_mss=1460 peer_mss=1460 tx_mss=512`. Speicher danach: Fast 872 Bytes frei, Chip 69 KiB frei (`SYS:avail.txt`).

### SANA-II-Treiber allein (FS-UAE, `make run-sana2`, 2026-11-27)

```text
sana: OpenDevice -> 0, device a2065.device version 2.16
sana: S2_DEVICEQUERY -> 0: AddrFieldSize 48 bits, MTU 1500, BPS 10000000, HardwareType 1 (Ethernet)
sana: S2_GETSTATIONADDRESS: current ff:ff:ff:ff:ff:ff, default (ROM) 00:80:10:32:33:34
sana: S2_CONFIGINTERFACE (default address) -> 0; danach current 00:80:10:32:33:34
sana: S2_ONLINE -> io_Error 3, WireError 12 (S2WERR_UNIT_ONLINE: CONFIGINTERFACE hat die Einheit schon online gebracht)
sana: CMD_WRITE ARP request (broadcast) -> 0
sana: CMD_READ ARP reply nach 0 ms: 50 Bytes von 52:55:0a:00:02:02 = 10.0.2.2 (slirp-Gateway)
```

Damit ist der Weg Kickstart 1.3 → a2065.device (mit unserer utility.library) → emulierte LANCE → slirp → Host-Netz bewiesen. TheWire13 scheitert an `S2_CONFIGINTERFACE` mit `S2ERR_BAD_ADDRESS`, weil es die *aktuelle* Adresse der noch unkonfigurierten Einheit (ff:ff:ff:ff:ff:ff, Broadcast) statt der Default-Adresse aus `ios2_DstAddr` einträgt; AmiTCP und Roadshow nehmen die Default-Adresse. Umgehung ohne Quelltext: `sana2hold` konfiguriert die Einheit vorher mit der ROM-Adresse und hält das Gerät offen (`NET_HOLD=1`).

### vamos (Musashi-68000, vamos' eigene bsdsocket.library v4 auf dem Host-Netz)

Das unveränderte Amiga-Binary erreicht gegen web.whatsapp.com: DNS 60 ms, TCP 40 ms, TLS 1.3 bei 0,18 s, WebSocket offen bei 0,38 s, ServerHello 0,62 s, ClientFinish 0,84 s, erster verschlüsselter Server-Frame (695 → 679 Bytes, pair-device IQ) bei 1,24 s – `RESULT: handshake ACCEPTED`. Damit sind Registerkonventionen und Strukturen in `bsdsocket13.h` bestätigt (vamos implementiert dieselbe AmiTCP-ABI); Zeiten sind dort bedeutungslos (keine Zyklen).

### DHCP (FS-UAE, `NET_DHCP=1`, 2026-11-27)

TheWire13 holt seine Adresse von slirps DHCP-Server, wenn `dhcp=1` in `S:thewire13.conf` steht. Damit ein stiller Rückfall auf die statischen Einträge nicht wie Erfolg aussieht (TheWire13 nimmt sie bei DHCP-Fehlschlag, Readme 1.6), schreibt `tools/run-fsuae-net.sh` bei `NET_DHCP=1` eine unerreichbare statische Adresse (192.168.77.5) in die Konfiguration. Ergebnis mit `NET_LOG=1` (Auszug `SYS:stack.log`, Pfad `-> UDP 68/67`):

```text
INFO: UDP BIND port=68
INFO: UDP send dst=255.255.255.255 src_port=68 dst_port=67 payload_len=300    (DISCOVER)
INFO: IP RX src=10.0.2.2 dst=255.255.255.255 proto=17 total_len=309          (OFFER)
INFO: UDP send dst=255.255.255.255 src_port=68 dst_port=67 payload_len=300    (REQUEST)
INFO: IP RX src=10.0.2.2 dst=255.255.255.255 proto=17 total_len=309          (ACK)
INFO: UDP UNBIND port=68 queue=0
IP: 10.0.2.15 (DHCP)
Mask: 255.255.255.0
Gateway: 10.0.2.2
DNS: 10.0.2.3
```

Zwei Umläufe, dann ARP, DNS (1,58 s), TCP-Connect (0,84 s) und `handshake ACCEPTED` wie mit statischen Adressen; der Stack war fertig, bevor die Probe ihre Schlüsselpaare (12,7 s, parallel zum Stackstart) berechnet hatte. Mit DHCP fallen auf echter Hardware die vier Adresszeilen der Konfiguration weg. Derselbe Lauf bestätigt die Pool-Größe aus dem Log: `tcp_init: max_tcp=12 active_tcp=12 pool_bytes=720072`, also 60 KiB je PCB (nicht 40 KiB wie in Schritt 17 geschätzt).

## 5. Offen

- Speicher: mit 1 MiB Fast müssen sich TheWire13 und Client 1 MiB Fast + 512 KiB Chip teilen, der Client bleibt unter ≈ 400 KiB und muss vor dem Stack starten. Deshalb setzt der Netz-Client 2 MiB Fast voraus (Abschnitt 6); ein Pool-Schlüssel beim Autor bliebe wünschenswert.
- Rückmeldung an den TheWire13-Autor (aminet@jaehne.tk): `S2_CONFIGINTERFACE` sollte die Default-Adresse aus `S2_GETSTATIONADDRESS`/`ios2_DstAddr` verwenden (wie AmiTCP), dann entfällt `a2065fix.device`.
- `tx_mss=512` (TheWire13-Default `tx_buffer=512`): TLS-Records von 16 KiB gehen in 32 Segmenten – für den Handshake egal, für Medien später relevant.
- Entropiesammler und Seed-Datei (docs/RNG.md) statt `SYS:seed.bin`.
- Zeit per SNTP über den Adapter (ein UDP-Datagramm; braucht `sendto`/`recvfrom` im Adapter) oder `mini_ntp` in der Startup-Sequence.
- Zertifikatscache persistent in `ENVARC:` (heute nur im Speicher der Probe).
- Nicht blockierender `connect` mit Timeout (heute blockierend; TheWire13 meldet EINPROGRESS, `WaitSelect` auf Schreibbereitschaft).
- Echte Hardware: SANA-II-Treiber der tatsächlichen Karte in `S:thewire13.conf` eintragen, sonst keine Codeänderung.

## 6. Speicherausbau: 1 MiB gegen 2 MiB Fast (2026-11-27)

Mit 1 MiB Fast bleiben nach Stack und Probe 872 Bytes Fast und 69 KiB Chip frei (Schritt 17 in BENCHMARKS.md); die Probe ist nur Krypto und Netz, der Client braucht zusätzlich Bildschirm, Kontakte, Signal-Sessions und Nachrichtenpuffer. Deshalb wurde die Maschine mit 2 MiB Fast vermessen (`tools/fsuae/a500-2mb-fast-net.fs-uae`, `make run-probe FAST=2048`; `tools/run-fsuae-net.sh` übergibt `NET_FAST` als `--fast_memory`). `Avail` in Bytes:

| Zustand (2 MiB Fast) | Fast belegt | Fast frei | größter Fast-Block | Chip frei |
|---|---:|---:|---:|---:|
| System + TheWire13 (Stack zuerst, vor der Probe) | 1 369 712 | 727 408 | 727 032 | 447 472 |
| System + TheWire13 + Probe (beide laufen) | 1 906 584 | 190 536 | 190 152 | 447 472 |
| nach Ende der Probe | 1 435 248 | 661 872 | 433 544 | 447 472 |

Was sich gegenüber 1 MiB ändert:

- **Der Stack wächst mit dem Angebot.** Mit 1 MiB belegen Stack und Probe zusammen ≈ 1,45 MiB (1 MiB Fast voll plus 447 KiB Chip), mit 2 MiB ≈ 1,89 MiB. Die Differenz von ≈ 440 KiB ist der TCP-Pool mit 12 statt 4 PCBs (`pool_bytes=720072` im Stack-Log, 60 KiB je PCB); der Stack allein liegt bei 2 MiB bei ≈ 1,3 MiB Fast (einschließlich System und CLI, ≈ 60 KiB). Die Probe selbst nahm 537 KiB (Binary von Commit b91672c mit vorgezogenen Schlüsselpaaren und Zertifikatscache).
- **Chip-RAM bleibt frei.** Der Loader legt alles in Fast ab, 447 KiB Chip stehen für Bildschirm (Hires 640×256, 16 Farben: 80 KiB), Fonts und Blitter-Puffer zur Verfügung. Mit 1 MiB lagen ≈ 380 KiB des Stacks im Chip-RAM.
- **Startreihenfolge ist egal.** Stack zuerst und Client zuerst funktionieren beide (`NET_ORDER=stack-first` getestet); mit 1 MiB lud die Probe nach dem Stack nicht mehr.
- **Keine Zeitänderung.** TLS 1.3 31,5 s, Noise 40,5 s (mit Cache-Treffer und vorberechneten Schlüsseln, Commit b91672c), `handshake ACCEPTED` – die Rechenzeit hängt nicht am RAM-Ausbau.

Budget für den Client bei 2 MiB: ≈ 700 KiB Fast neben dem voll ausgebauten Stack, dazu ≈ 440 KiB Chip. Die Krypto- und Netzschicht der Probe braucht davon ≈ 540 KiB (davon 64 KiB eigener Stack, TLS-Record-Puffer, Zertifikatskette); für Oberfläche, Kontakte, Sessions und Nachrichten bleiben ≈ 150 KiB Fast plus das Chip-RAM. Das ist eng, aber machbar; mit 1 MiB ist es nicht machbar, solange der Stack keinen Pool-Schlüssel hat. Für echte Hardware passt die Vorgabe: ein A500 mit Ethernet hat praktisch immer eine Seitenerweiterung mit 2 MiB oder mehr (A590, GVP, Supra; ACA500plus mit X-Surf-500 bringt 8 MiB), reine 1-MiB-Fast-Erweiterungen sind selten, die A501 im Trapdoor ist Slow-RAM. Die 1-MiB-Maschine bleibt die Benchmark-Maschine für die Kryptografie (`tools/fsuae/a500-1mb-fast.fs-uae`).

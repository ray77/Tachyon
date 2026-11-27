#!/bin/sh
# Run the Amiga WhatsApp probe (or any program needing TCP/IP) inside FS-UAE on the Tachyon reference
# machine with network: A500, Kickstart 1.3, 512 KiB Chip + 1 MiB Fast, NET_FAST=2048 for 2 MiB, emulated A2065 Ethernet on
# FS-UAE's slirp NAT (tools/fsuae/a500-1mb-fast-net.fs-uae), TheWire13 as the TCP/IP stack.
#
#   tools/run-fsuae-net.sh <amiga-executable> [timeout-seconds]
#
# DH0 is assembled from: the WB 1.3 disk's Run/Wait commands (extracted with amitools' xdftool from the
# user's own ADF), TheWire13's C:/LIBS: files, the Aminet a2065.device in DEVS:Networks (both unpacked
# under build/ by hand, see docs/NETWORK.md), a generated S:thewire13.conf for slirp and a Startup-Sequence
# that starts the stack in the background, waits, runs the program and ends the CLI. Inputs for the probe:
# SYS:seed.bin (64 bytes from /dev/urandom), SYS:now.txt (UTC time), SYS:waip.txt (dig), SYS:gap.txt (GAP).
# The program must create SYS:result.txt and finally SYS:done. The stack's console output lands in
# SYS:stack.log.
set -eu
EXE=${1:?usage: run-fsuae-net.sh <executable> [timeout]}
TIMEOUT=${2:-600}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
FSUAE=/Applications/FS-UAE.app/Contents/MacOS/fs-uae
XDFTOOL=${XDFTOOL:-$HOME/opt/amitools-venv/bin/xdftool}
WBADF=${WBADF:-$HOME/Documents/FS-UAE/Floppies/wb133-boot.adf}
WIRE=${WIRE:-$ROOT/build/thewire13/TheWire13}
A2065DEV=${A2065DEV:-$ROOT/build/a2065dev/a2065.device}
WORK=${TACHYON_NET_WORK:-"$ROOT/build/fsuae-net"}
DH0="$WORK/dh0"
NET_DHCP=${NET_DHCP:-0}
NET_FAST=${NET_FAST:-1024}    # Fast RAM in KiB: 1024 = benchmark machine, 2048 = the client's minimum (docs/NETWORK.md 6)
NET_RXBUF=${NET_RXBUF:-16384}  # socket_rx_buffer: TheWire13's TCP pool is max_tcp (12) x this; the default 40000 costs 480 KiB
NET_LOG=${NET_LOG:-0}          # log_enabled in thewire13.conf
NET_WAIT=${NET_WAIT:-8}        # seconds between starting the stack and the program
NET_STACK=${NET_STACK:-50000}  # CLI stack for the stack task (Kickstart 1.3 default is 4000 bytes)
GAP=${GAP:-0}

for f in "$WIRE/c/TheWire13" "$WIRE/libs/bsdsocket.library" "$A2065DEV" "$WBADF"; do
  [ -f "$f" ] || { echo "missing: $f (see docs/NETWORK.md for the downloads)"; exit 2; }
done

rm -rf "$WORK"; mkdir -p "$DH0/S" "$DH0/C" "$DH0/Libs" "$DH0/Devs/Networks"
cp "$EXE" "$DH0/test"
# C: commands from the user's Workbench 1.3 disk (Kickstart 1.3 has none in ROM)
for c in Run Wait Stack Echo ChangeTaskPri Avail; do "$XDFTOOL" "$WBADF" read "c/$c" "$DH0/C/$c" >/dev/null; done
cp "$WIRE/c/TheWire13" "$WIRE/c/mini_ping" "$WIRE/c/mini_ntp" "$WIRE/c/mini_nslookup" "$DH0/C/" 2>/dev/null || cp "$WIRE/c/TheWire13" "$DH0/C/"
cp "$WIRE/libs/bsdsocket.library" "$DH0/Libs/"
# utility.library V37 for 1.3 (make utility13): the a2065.device opens it at init time
[ -f "$ROOT/build/amiga/utility.library" ] && cp "$ROOT/build/amiga/utility.library" "$DH0/Libs/"
[ -f "$ROOT/build/amiga/sana2_hold" ] && cp "$ROOT/build/amiga/sana2_hold" "$DH0/C/sana2hold"
NET_HOLD=${NET_HOLD:-0}        # 1: configure the interface with its ROM address first and keep it open (sana2hold)
HOLD_LINE=""; [ "$NET_HOLD" = 1 ] && HOLD_LINE='run >NIL: C:sana2hold\nwait 3\n'
cp "$A2065DEV" "$DH0/Devs/Networks/a2065.device"
# a2065fix.device (make sanafix) wraps the driver for TheWire13's S2_CONFIGINTERFACE; NET_FIX=0 talks to a2065.device directly
NET_FIX=${NET_FIX:-1}
SANADEV=devs:networks/a2065.device
if [ "$NET_FIX" = 1 ] && [ -f "$ROOT/build/amiga/a2065fix.device" ]; then cp "$ROOT/build/amiga/a2065fix.device" "$DH0/Devs/Networks/"; SANADEV=devs:networks/a2065fix.device; fi
# slirp: guest 10.0.2.15/24, gateway 10.0.2.2, DNS 10.0.2.3. With NET_DHCP=1 the same addresses must come from slirp's DHCP
# server; TheWire13 falls back to the static entries when DHCP fails (readme 1.6), so the static fallback is then an
# unroutable address and a failed DHCP shows up as "IP: 192.168.77.5 (static)" in SYS:stack.log and a connect timeout.
if [ "$NET_DHCP" = 1 ]; then S_IP=192.168.77.5; S_GW=192.168.77.1; S_DNS=192.168.77.1; else S_IP=10.0.2.15; S_GW=10.0.2.2; S_DNS=10.0.2.3; fi
cat > "$DH0/S/thewire13.conf" <<EOF
device=$SANADEV
unit=0

dhcp=$NET_DHCP

ip=$S_IP
netmask=255.255.255.0
gateway=$S_GW

dns=$S_DNS
dns2=$S_DNS

hostname=tachyon
domain=lan
mtu=1500

socket_rx_buffer=$NET_RXBUF
tcp_window=$NET_RXBUF

log_enabled=$NET_LOG
EOF
head -c 64 /dev/urandom > "$DH0/seed.bin"
date -u +%Y%m%d%H%M%SZ | tr -d '\n' > "$DH0/now.txt"
dig +short web.whatsapp.com 2>/dev/null | grep -E '^[0-9.]+$' | head -1 | tr -d '\n' > "$DH0/waip.txt" || true
printf '%s' "$GAP" > "$DH0/gap.txt"
# fingerprint of WhatsApp's verified intermediate Noise certificate (32 bytes, written by make wa-probe or an earlier
# Amiga run): with it the probe skips the ~11 s XEdDSA verification of the intermediate; copied back after the run
NCACHE=${NOISE_CACHE:-$ROOT/build/wa_noise_cache.bin}
[ -f "$NCACHE" ] && cp "$NCACHE" "$DH0/noisecache.bin"
# the redirection after the command name belongs to the started program (its banner, DHCP and SANA messages),
# the one after Run only to Run's own "[CLI 2]" line
# Order: the program first (it waits up to 60 s for the stack), then TheWire13, which sizes its TCP PCB pool
# (12 x 40 KiB by default, no config key) from the memory that is left: with the stack first, Fast RAM is gone
# (Avail: 464 bytes) and a 400 KiB program cannot load. NET_ORDER=stack-first restores the old order.
NET_ORDER=${NET_ORDER:-probe-first}
if [ "${NET_NOSTACK:-0}" = 1 ]; then printf 'stack %s\ntest\nendcli\n' "$NET_STACK" > "$DH0/S/Startup-Sequence"   # driver tests without the stack
elif [ "$NET_ORDER" = probe-first ]; then
  printf "stack %s\n${HOLD_LINE}run >NIL: test\nwait 2\nrun >NIL: C:TheWire13 >SYS:stack.log\nwait %s\navail >SYS:avail.txt\nendcli\n" "$NET_STACK" "$NET_WAIT" > "$DH0/S/Startup-Sequence"
else printf "stack %s\n${HOLD_LINE}run >NIL: C:TheWire13 >SYS:stack.log\nwait %s\navail >SYS:avail.txt\ntest\navail >SYS:avail2.txt\nendcli\n" "$NET_STACK" "$NET_WAIT" > "$DH0/S/Startup-Sequence"; fi

"$FSUAE" "$HERE/fsuae/a500-1mb-fast-net.fs-uae" \
    --floppy_drive_0= \
    --hard_drive_0="$DH0" --hard_drive_0_label=DH0 --hard_drive_0_priority=6 \
    --fast_memory="$NET_FAST" --log_file="$WORK/fs-uae.log" >"$WORK/stdout.log" 2>&1 &
PID=$!
i=0
while [ $i -lt "$TIMEOUT" ]; do
  if [ -f "$DH0/done" ]; then sleep 1; break; fi
  if ! kill -0 $PID 2>/dev/null; then echo "fs-uae exited early (see $WORK/stdout.log)"; break; fi
  sleep 1; i=$((i+1))
done
kill $PID 2>/dev/null || true
[ -f "$DH0/sana2hold.log" ] && { echo "--- SYS:sana2hold.log ---"; cat "$DH0/sana2hold.log"; }
[ -f "$DH0/avail.txt" ] && { echo "--- SYS:avail.txt (after both started) ---"; cat "$DH0/avail.txt"; }
echo "--- SYS:stack.log ---"
cat "$DH0/stack.log" 2>/dev/null || echo "(no stack.log)"
[ -f "$DH0/amitcp13.log" ] && { echo "--- SYS:amitcp13.log (NET_LOG=1) ---"; cat "$DH0/amitcp13.log"; }
echo "--- SYS:result.txt after ${i}s ---"
cat "$DH0/result.txt" 2>/dev/null || echo "(no result.txt)"
if [ -f "$DH0/noisecache.bin" ] && [ -f "$DH0/done" ]; then cp "$DH0/noisecache.bin" "$NCACHE" && echo "(noise certificate cache saved to $NCACHE)"; fi

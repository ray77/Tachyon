#!/bin/sh
# Run the Amiga WhatsApp probe (or any program needing TCP/IP) inside FS-UAE on the Tachyon reference
# machine with network: A500, Kickstart 1.3, 512 KiB Chip + 1 MiB Fast, emulated A2065 Ethernet on
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
GAP=${GAP:-0}

for f in "$WIRE/c/TheWire13" "$WIRE/libs/bsdsocket.library" "$A2065DEV" "$WBADF"; do
  [ -f "$f" ] || { echo "missing: $f (see docs/NETWORK.md for the downloads)"; exit 2; }
done

rm -rf "$WORK"; mkdir -p "$DH0/S" "$DH0/C" "$DH0/Libs" "$DH0/Devs/Networks"
cp "$EXE" "$DH0/test"
# C: commands from the user's Workbench 1.3 disk (Kickstart 1.3 has none in ROM)
for c in Run Wait; do "$XDFTOOL" "$WBADF" read "c/$c" "$DH0/C/$c" >/dev/null; done
cp "$WIRE/c/TheWire13" "$WIRE/c/mini_ping" "$WIRE/c/mini_ntp" "$WIRE/c/mini_nslookup" "$DH0/C/" 2>/dev/null || cp "$WIRE/c/TheWire13" "$DH0/C/"
cp "$WIRE/libs/bsdsocket.library" "$DH0/Libs/"
cp "$A2065DEV" "$DH0/Devs/Networks/a2065.device"
# slirp: guest 10.0.2.15/24, gateway 10.0.2.2, DNS 10.0.2.3 (static; the same addresses come via DHCP with NET_DHCP=1)
cat > "$DH0/S/thewire13.conf" <<EOF
device=devs:networks/a2065.device
unit=0

dhcp=$NET_DHCP

ip=10.0.2.15
netmask=255.255.255.0
gateway=10.0.2.2

dns=10.0.2.3
dns2=10.0.2.3

hostname=tachyon
domain=lan
mtu=1500

log_enabled=0
EOF
head -c 64 /dev/urandom > "$DH0/seed.bin"
date -u +%Y%m%d%H%M%SZ | tr -d '\n' > "$DH0/now.txt"
dig +short web.whatsapp.com 2>/dev/null | grep -E '^[0-9.]+$' | head -1 | tr -d '\n' > "$DH0/waip.txt" || true
printf '%s' "$GAP" > "$DH0/gap.txt"
# Run >file: the new CLI inherits the redirected output, so the stack's banner and DHCP/SANA messages are kept
printf 'run >SYS:stack.log C:TheWire13\nwait 8\ntest\nendcli\n' > "$DH0/S/Startup-Sequence"

"$FSUAE" "$HERE/fsuae/a500-1mb-fast-net.fs-uae" \
    --floppy_drive_0= \
    --hard_drive_0="$DH0" --hard_drive_0_label=DH0 --hard_drive_0_priority=6 \
    --log_file="$WORK/fs-uae.log" >"$WORK/stdout.log" 2>&1 &
PID=$!
i=0
while [ $i -lt "$TIMEOUT" ]; do
  if [ -f "$DH0/done" ]; then sleep 1; break; fi
  if ! kill -0 $PID 2>/dev/null; then echo "fs-uae exited early (see $WORK/stdout.log)"; break; fi
  sleep 1; i=$((i+1))
done
kill $PID 2>/dev/null || true
echo "--- SYS:stack.log ---"
cat "$DH0/stack.log" 2>/dev/null || echo "(no stack.log)"
echo "--- SYS:result.txt after ${i}s ---"
cat "$DH0/result.txt" 2>/dev/null || echo "(no result.txt)"

#!/bin/sh
# Run one Amiga executable inside FS-UAE on the WhatsA500 reference machine
# (A500, Kickstart 1.3, 512 KiB Chip + 1 MiB Fast) and print what the program
# wrote to SYS:result.txt.
#
#   tools/run-fsuae.sh <amiga-executable> [timeout-seconds]
#
# The executable is copied into a fresh DH0 directory as "test" together with a
# Startup-Sequence that runs it. Kickstart 1.3 has no resident C: commands, so the
# sequence contains only the program itself and the CLI built-in EndCLI; the
# program must create SYS:result.txt and finally SYS:done (the completion marker).
set -eu
EXE=${1:?usage: run-fsuae.sh <executable> [timeout]}
TIMEOUT=${2:-120}
HERE=$(cd "$(dirname "$0")" && pwd)
FSUAE=/Applications/FS-UAE.app/Contents/MacOS/fs-uae
WORK=${WHATSA500_WORK:-"$HERE/../build/fsuae-run"}
DH0="$WORK/dh0"
rm -rf "$WORK"; mkdir -p "$DH0/S"
cp "$EXE" "$DH0/test"
printf 'test\nendcli\n' > "$DH0/S/Startup-Sequence"
"$FSUAE" "$HERE/fsuae/a500-1mb-fast.fs-uae" \
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
echo "--- SYS:result.txt after ${i}s ---"
cat "$DH0/result.txt" 2>/dev/null || echo "(no result.txt)"

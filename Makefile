# WhatsA500 - build on macOS/Linux, run on an emulated A500 (see docs/TOOLCHAIN.md)
#
#   make host-test      portable X25519 reference + RFC/Go vectors on the host
#   make amiga          build/amiga/x25519bench (Kickstart 1.3 hunk executable)
#   make run            run the benchmark in FS-UAE and print SYS:result.txt
#   make vectors        regenerate tests/vectors/x25519_random.txt with Go
#
VBCC    ?= $(HOME)/opt/vbcc
NDK     ?= $(HOME)/opt/ndk32
VC      := $(VBCC)/bin/vbccm68k
VASM    ?= vasmm68k_mot
HOSTCC  ?= cc

# -O=1023 is vc's -O2; -speed trades size for speed; 68000 only, no FPU.
# FE16_ASM: fe16_mul/fe16_sqr come from crypto/m68k/fe16.s (included by startup.s)
VCFLAGS := -quiet -O=1023 -speed -cpu=68000 -c99 -no-cpp-warn -DFE16_ASM \
           -I$(VBCC)/targets/m68k-kick13/include -I$(NDK)/Include_H -Icrypto/ref
VASMFLAGS := -quiet -Fhunkexe -kick1hunks -nowarn=62 -m68000

HOST_CFLAGS := -O2 -Wall -Wextra -std=c99 -Icrypto/ref

CRYPTO_SRC := crypto/ref/x25519_ref.c
BENCH_SRC  := bench/x25519_bench.c
# no linker available on macOS: one unity translation unit -> one .s -> vasm -Fhunkexe
UNITY_SRC  := bench/amiga/unity.c
AMIGA_ASM  := build/amiga/x25519bench.s

.PHONY: all host-test amiga run vectors clean

all: host-test amiga

# ---- host ------------------------------------------------------------------
build/x25519_test: tests/x25519_test.c $(CRYPTO_SRC) crypto/ref/x25519.h
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/x25519_test.c $(CRYPTO_SRC) -o $@

host-test: build/x25519_test
	./build/x25519_test tests/vectors/x25519_random.txt

vectors:
	go run ./tools/genvectors -n 256 > tests/vectors/x25519_random.txt

# ---- amiga -----------------------------------------------------------------
$(AMIGA_ASM): $(UNITY_SRC) $(CRYPTO_SRC) $(BENCH_SRC) crypto/ref/x25519.h
	@mkdir -p build/amiga
	$(VC) $(VCFLAGS) $(UNITY_SRC) -o=$@

crypto/m68k/fe16.s: tools/gen_fe16_asm.py
	python3 $< > $@

build/amiga/x25519bench: bench/amiga/startup.s $(AMIGA_ASM) crypto/m68k/fe16.s
	$(VASM) $(VASMFLAGS) -o $@ $<

amiga: build/amiga/x25519bench

run: build/amiga/x25519bench
	tools/run-fsuae.sh $< 300

clean:
	rm -rf build

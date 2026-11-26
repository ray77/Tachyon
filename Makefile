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

CRYPTO_SRC := crypto/ref/x25519_ref.c crypto/ref/sha512.c crypto/ref/ed25519.c crypto/ref/sha256.c crypto/ref/aes.c crypto/ref/drbg.c crypto/ref/noise.c crypto/ref/rsa.c
BENCH_SRC  := bench/x25519_bench.c
# no linker available on macOS: one unity translation unit -> one .s -> vasm -Fhunkexe
UNITY_SRC  := bench/amiga/unity.c
AMIGA_ASM  := build/amiga/x25519bench.s

.PHONY: all host-test amiga run vamos vectors clean

all: host-test amiga

# ---- host ------------------------------------------------------------------
build/x25519_test: tests/x25519_test.c $(CRYPTO_SRC) crypto/ref/x25519.h
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/x25519_test.c $(CRYPTO_SRC) -o $@

build/ed25519_test: tests/ed25519_test.c $(CRYPTO_SRC) crypto/ref/x25519.h crypto/ref/ed25519.h crypto/ref/sha512.h
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/ed25519_test.c $(CRYPTO_SRC) -o $@

build/sha256_test: tests/sha256_test.c crypto/ref/sha256.c crypto/ref/sha256.h
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/sha256_test.c crypto/ref/sha256.c -o $@

build/noise_test: tests/noise_test.c $(CRYPTO_SRC) crypto/ref/noise.h
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/noise_test.c $(CRYPTO_SRC) -o $@

build/rsa_test: tests/rsa_test.c crypto/ref/rsa.c crypto/ref/rsa.h crypto/ref/sha256.c
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/rsa_test.c crypto/ref/rsa.c crypto/ref/sha256.c -o $@

build/drbg_test: tests/drbg_test.c crypto/ref/drbg.c crypto/ref/drbg.h crypto/ref/sha256.c
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/drbg_test.c crypto/ref/drbg.c crypto/ref/sha256.c -o $@

build/aes_test: tests/aes_test.c crypto/ref/aes.c crypto/ref/aes.h
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/aes_test.c crypto/ref/aes.c -o $@

host-test: build/x25519_test build/ed25519_test build/sha256_test build/aes_test build/drbg_test build/noise_test build/rsa_test
	./build/x25519_test tests/vectors/x25519_random.txt
	./build/ed25519_test tests/vectors
	./build/sha256_test
	./build/aes_test tests/vectors/aesgcm_random.txt
	./build/drbg_test tests/vectors/hmac_drbg.txt
	./build/noise_test tests/vectors/noise_random.txt
	./build/rsa_test tests/vectors/rsa_random.txt

vectors:
	go run ./tools/genvectors -mode x25519 -n 256 > tests/vectors/x25519_random.txt
	go run ./tools/genvectors -mode ed25519 -n 64 > tests/vectors/ed25519_random.txt
	go run ./tools/genvectors -mode xeddsa -n 64 > tests/vectors/xeddsa_random.txt
	go run ./tools/genvectors -mode sha512 -n 32 > tests/vectors/sha512_random.txt
	go run ./tools/genvectors -mode aesgcm -n 64 > tests/vectors/aesgcm_random.txt

crypto/ref/ed25519_btable.h: tools/gen_btable.c crypto/ref/ed25519.c
	$(HOSTCC) -O2 -Icrypto/ref tools/gen_btable.c crypto/ref/x25519_ref.c crypto/ref/sha512.c crypto/ref/ed25519.c -o build/gen_btable
	./build/gen_btable > $@

# ---- amiga -----------------------------------------------------------------
$(AMIGA_ASM): $(UNITY_SRC) $(CRYPTO_SRC) $(BENCH_SRC) crypto/ref/x25519.h crypto/ref/ed25519.h bench/xeddsa_vector.h
	@mkdir -p build/amiga
	$(VC) $(VCFLAGS) $(UNITY_SRC) -o=$@

crypto/m68k/fe16.s: tools/gen_fe16_asm.py
	python3 $< > $@

crypto/m68k/sha256.s: tools/gen_sha256_asm.py
	python3 $< > $@

crypto/m68k/aes.s: tools/gen_aes_asm.py
	python3 $< > $@

build/amiga/x25519bench: bench/amiga/startup.s $(AMIGA_ASM) crypto/m68k/fe16.s crypto/m68k/sha256.s crypto/m68k/aes.s crypto/m68k/mont.s
	$(VASM) $(VASMFLAGS) -o $@ $<

amiga: build/amiga/x25519bench

# fast correctness run on the host: amitools vamos (Musashi 68000, exec/dos emulated in Python).
# No custom chips, no cycle timing - use it for asm-vs-C vector checks, FS-UAE for numbers.
VAMOS := $(HOME)/opt/amitools-venv/bin/vamos
vamos: build/amiga/x25519bench
	mkdir -p build/vamos-sys && cp $< build/vamos-sys/test && rm -f build/vamos-sys/result.txt
	cd build/vamos-sys && $(VAMOS) -q -V sys:. -s 64 test > vamos.log 2>&1; grep -E 'PASS|FAIL|RESULT' build/vamos-sys/result.txt

run: build/amiga/x25519bench
	tools/run-fsuae.sh $< 600

clean:
	rm -rf build

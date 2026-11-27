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

CRYPTO_SRC := crypto/ref/x25519_ref.c crypto/ref/sha512.c crypto/ref/ed25519.c crypto/ref/sha256.c crypto/ref/aes.c crypto/ref/drbg.c crypto/ref/noise.c crypto/ref/rsa.c crypto/ref/x509.c crypto/ref/tls12.c crypto/ref/tls13.c crypto/ref/sha1.c crypto/ref/ws.c crypto/ref/heartbeat.c crypto/ref/yield.c
BENCH_SRC  := bench/x25519_bench.c
# no linker available on macOS: one unity translation unit -> one .s -> vasm -Fhunkexe
UNITY_SRC  := bench/amiga/unity.c
AMIGA_ASM  := build/amiga/x25519bench.s

.PHONY: all host-test amiga run vamos vectors clean tls-test tls13-test ws-test heartbeat-test wa-probe wa-probe-tunnel run-blitaes run-blitgcm amiga-probe run-probe vamos-probe utility13 utility13-test sana2-probe run-sana2

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

build/rsa_test: tests/rsa_test.c crypto/ref/rsa.c crypto/ref/rsa.h crypto/ref/sha256.c crypto/ref/yield.c
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/rsa_test.c crypto/ref/rsa.c crypto/ref/sha256.c crypto/ref/yield.c -o $@

build/x509_test: tests/x509_test.c crypto/ref/x509.c crypto/ref/x509.h crypto/ref/rsa.c crypto/ref/sha256.c tests/certs/wa_rsa_chain.h
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/x509_test.c crypto/ref/x509.c crypto/ref/rsa.c crypto/ref/sha256.c crypto/ref/yield.c -o $@

build/tls_test: tests/tls_test.c $(CRYPTO_SRC) crypto/ref/tls12.h
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/tls_test.c $(CRYPTO_SRC) -o $@

# TLS 1.2 RSA client against a loopback Go server (tools/tlsserver), one connection
tls-test: build/tls_test
	@mkdir -p build
	go run ./tools/tlsserver -listen 127.0.0.1:4433 -cert build/tls_test_cert.der -n 1 > build/tlsserver.log 2>&1 & \
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do grep -q READY build/tlsserver.log 2>/dev/null && break; sleep 0.5; done; \
	./build/tls_test build/tls_test_cert.der 4433 tests/vectors/tls_session.bin; r=$$?; sleep 0.5; cat build/tlsserver.log; exit $$r

build/tls13_test: tests/tls13_test.c $(CRYPTO_SRC) crypto/ref/tls13.h
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/tls13_test.c $(CRYPTO_SRC) -o $@

# TLS 1.3 client (X25519, AES-128-GCM, RSA-PSS) against a loopback Go server (tools/tls13server), six connections;
# the first is recorded to tests/vectors/tls13_session.bin for the Amiga replay (bench/tls13_vector.h)
tls13-test: build/tls13_test
	@mkdir -p build
	go run ./tools/tls13server -listen 127.0.0.1:4436 -cert build/tls13_test_cert.der -n 6 > build/tls13server.log 2>&1 & \
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do grep -q READY build/tls13server.log 2>/dev/null && break; sleep 0.5; done; \
	./build/tls13_test build/tls13_test_cert.der 4436 tests/vectors/tls13_session.bin; r=$$?; sleep 0.5; cat build/tls13server.log; exit $$r

build/ws_test: tests/ws_test.c crypto/ref/ws.c crypto/ref/ws.h crypto/ref/sha1.c crypto/ref/drbg.c crypto/ref/sha256.c
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/ws_test.c crypto/ref/ws.c crypto/ref/sha1.c crypto/ref/drbg.c crypto/ref/sha256.c -o $@

# WebSocket client against a loopback coder/websocket echo server
ws-test: build/ws_test
	go run ./tools/wsserver -listen 127.0.0.1:4434 > build/wsserver.log 2>&1 & \
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do grep -q READY build/wsserver.log 2>/dev/null && break; sleep 0.5; done; \
	./build/ws_test 4434; r=$$?; sleep 0.5; cat build/wsserver.log; exit $$r

# heartbeat (pong frames from the crypto progress hook) against the loopback echo server, which counts pongs
build/heartbeat_test: tests/heartbeat_test.c $(CRYPTO_SRC) crypto/ref/heartbeat.h crypto/ref/ws.h
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/heartbeat_test.c $(CRYPTO_SRC) -o $@

heartbeat-test: build/heartbeat_test
	go run ./tools/wsserver -listen 127.0.0.1:4435 > build/wsserver_hb.log 2>&1 & \
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do grep -q READY build/wsserver_hb.log 2>/dev/null && break; sleep 0.5; done; \
	./build/heartbeat_test 4435; r=$$?; sleep 0.5; cat build/wsserver_hb.log; exit $$r

# our own TLS 1.3 + WebSocket + Noise XX client against web.whatsapp.com with 30 s of simulated A500
# computing time and the pong heartbeat (network, manual: make wa-probe GAP=30)
GAP ?= 30
WAIP ?= $(shell dig +short web.whatsapp.com | grep -E '^[0-9.]+$$' | head -1)
PROBE_CORE := tests/wa_probe_core.c tests/wa_probe_core.h tests/certs/wa_rsa_chain.h tests/vectors/wa_client_payload.h
build/wa_probe: tests/wa_probe.c $(PROBE_CORE) $(CRYPTO_SRC) crypto/ref/heartbeat.h crypto/ref/tls13.h
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) -Itests tests/wa_probe.c tests/wa_probe_core.c $(CRYPTO_SRC) -o $@

wa-probe: build/wa_probe
	./build/wa_probe $(GAP) $(WAIP)

# same, with openssl s_client as the TLS 1.3/X25519 transport (reference run from before tls13.c existed)
wa-probe-tunnel: build/wa_probe
	./build/wa_probe $(GAP) $(WAIP) tunnel

crypto/blit/blitaes_prog.h: tools/blitaes/gen_blitaes.py tools/blitaes/sbox113.txt
	python3 $< 64 > $@

build/blitaes_test: tests/blitaes_test.c crypto/blit/blitaes.c crypto/blit/blitaes.h crypto/blit/blitaes_prog.h crypto/ref/aes.c
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) -Icrypto/blit tests/blitaes_test.c crypto/blit/blitaes.c crypto/ref/aes.c -o $@

build/blitgcm_test: tests/blitgcm_test.c crypto/blit/blitgcm.c crypto/blit/blitgcm.h crypto/blit/blitaes.c crypto/blit/blitaes.h crypto/blit/blitaes_prog.h crypto/ref/aes.c
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) -Icrypto/blit tests/blitgcm_test.c crypto/blit/blitgcm.c crypto/blit/blitaes.c crypto/ref/aes.c -o $@

build/drbg_test: tests/drbg_test.c crypto/ref/drbg.c crypto/ref/drbg.h crypto/ref/sha256.c
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/drbg_test.c crypto/ref/drbg.c crypto/ref/sha256.c -o $@

build/aes_test: tests/aes_test.c crypto/ref/aes.c crypto/ref/aes.h
	@mkdir -p build
	$(HOSTCC) $(HOST_CFLAGS) tests/aes_test.c crypto/ref/aes.c -o $@

host-test: build/x25519_test build/ed25519_test build/sha256_test build/aes_test build/drbg_test build/noise_test build/rsa_test build/x509_test build/blitaes_test build/blitgcm_test
	./build/x25519_test tests/vectors/x25519_random.txt
	./build/ed25519_test tests/vectors
	./build/sha256_test
	./build/aes_test tests/vectors/aesgcm_random.txt
	./build/drbg_test tests/vectors/hmac_drbg.txt
	./build/noise_test tests/vectors/noise_random.txt
	./build/rsa_test tests/vectors/rsa_random.txt tests/vectors/rsa_pss.txt
	./build/x509_test
	./build/blitaes_test
	./build/blitgcm_test
	$(MAKE) tls13-test

vectors:
	go run ./tools/genvectors -mode x25519 -n 256 > tests/vectors/x25519_random.txt
	go run ./tools/genvectors -mode ed25519 -n 64 > tests/vectors/ed25519_random.txt
	go run ./tools/genvectors -mode xeddsa -n 64 > tests/vectors/xeddsa_random.txt
	go run ./tools/genvectors -mode sha512 -n 32 > tests/vectors/sha512_random.txt
	go run ./tools/genvectors -mode aesgcm -n 64 > tests/vectors/aesgcm_random.txt
	go run ./tools/genvectors -mode rsapss -n 24 > tests/vectors/rsa_pss.txt

bench/tls_vector.h: tests/vectors/tls_session.bin tools/gen_tls_vector.py
	python3 tools/gen_tls_vector.py $< tv > $@

bench/tls13_vector.h: tests/vectors/tls13_session.bin tools/gen_tls_vector.py
	python3 tools/gen_tls_vector.py $< tv13 > $@

crypto/ref/ed25519_btable.h: tools/gen_btable.c crypto/ref/ed25519.c
	$(HOSTCC) -O2 -Icrypto/ref tools/gen_btable.c crypto/ref/x25519_ref.c crypto/ref/sha512.c crypto/ref/ed25519.c crypto/ref/yield.c -o build/gen_btable
	./build/gen_btable > $@

# ---- amiga -----------------------------------------------------------------
$(AMIGA_ASM): $(UNITY_SRC) $(CRYPTO_SRC) $(BENCH_SRC) crypto/ref/x25519.h crypto/ref/ed25519.h crypto/ref/tls13.h bench/xeddsa_vector.h bench/tls_vector.h bench/tls13_vector.h
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
	cd build/vamos-sys && $(VAMOS) -q -V sys:. -s 64 test > vamos.log 2>&1; grep -E 'PASS|FAIL|RESULT' result.txt

# Blitter AES experiment: own small binary
build/amiga/blitaes.s: bench/amiga/blit_unity.c crypto/blit/blitaes.c crypto/blit/blitaes_prog.h bench/blitaes_bench.c crypto/ref/aes.c
	@mkdir -p build/amiga
	$(VC) $(VCFLAGS) -Icrypto/blit bench/amiga/blit_unity.c -o=$@

build/amiga/blitaes: bench/amiga/startup_blit.s build/amiga/blitaes.s crypto/m68k/fe16.s crypto/m68k/aes.s crypto/m68k/blitexec.s
	$(VASM) $(VASMFLAGS) -o $@ bench/amiga/startup_blit.s

run-blitaes: build/amiga/blitaes
	tools/run-fsuae.sh $< 300

# Blitter AES-GCM library benchmark (crypto/blit/blitgcm.c on the real Copper/Blitter)
build/amiga/blitgcm.s: bench/amiga/blitgcm_unity.c crypto/blit/blitgcm.c crypto/blit/blitgcm.h crypto/blit/blitaes.c crypto/blit/blitaes_prog.h bench/blitgcm_bench.c crypto/ref/aes.c
	@mkdir -p build/amiga
	$(VC) $(VCFLAGS) -Icrypto/blit bench/amiga/blitgcm_unity.c -o=$@

build/amiga/blitgcm: bench/amiga/startup_blitgcm.s build/amiga/blitgcm.s crypto/m68k/aes.s crypto/m68k/blitexec.s crypto/m68k/blitgcm.s
	$(VASM) $(VASMFLAGS) -o $@ bench/amiga/startup_blitgcm.s

run-blitgcm: build/amiga/blitgcm
	tools/run-fsuae.sh $< 300

run: build/amiga/x25519bench
	tools/run-fsuae.sh $< 600

# WhatsApp probe on the Amiga: the host probe's core over bsdsocket.library (net/bsdsock_io.c), TheWire13 as the
# stack, FS-UAE's emulated A2065 on slirp (tools/run-fsuae-net.sh, docs/NETWORK.md). Network, several minutes.
PROBE_UNITY := bench/amiga/wa_probe_unity.c
build/amiga/wa_probe.s: $(PROBE_UNITY) $(CRYPTO_SRC) $(PROBE_CORE) net/bsdsock_io.c net/bsdsock_io.h net/bsdsocket13.h bench/wa_probe_amiga.c
	@mkdir -p build/amiga
	$(VC) $(VCFLAGS) -Itests $(PROBE_UNITY) -o=$@

build/amiga/wa_probe: bench/amiga/startup_probe.s build/amiga/wa_probe.s crypto/m68k/fe16.s crypto/m68k/sha256.s crypto/m68k/aes.s crypto/m68k/mont.s
	$(VASM) $(VASMFLAGS) -o $@ $<

amiga-probe: build/amiga/wa_probe

run-probe: build/amiga/wa_probe build/amiga/utility.library build/amiga/sana2_hold
	GAP=$(GAP) tools/run-fsuae-net.sh $< 600

# utility.library V37 for Kickstart 1.3 (tools/amiga/utility13.*): 2.0-era SANA-II drivers (a2065.device) need it
build/amiga/utility13_c.s: tools/amiga/utility13.c
	@mkdir -p build/amiga
	$(VC) $(VCFLAGS) $< -o=$@

build/amiga/utility.library: tools/amiga/utility13.s build/amiga/utility13_c.s
	$(VASM) $(VASMFLAGS) -o $@ $<

utility13: build/amiga/utility.library

# its test (tools/amiga/utility13_test.c): the startup is bench/amiga/startup.s with the include swapped
build/amiga/utility13_test.s: tools/amiga/utility13_test.c
	@mkdir -p build/amiga
	$(VC) $(VCFLAGS) $< -o=$@

build/amiga/utility13_test: bench/amiga/startup.s build/amiga/utility13_test.s
	sed 's#build/amiga/x25519bench.s#build/amiga/utility13_test.s#' bench/amiga/startup.s > build/amiga/startup_utility13_test.s
	$(VASM) $(VASMFLAGS) -o $@ build/amiga/startup_utility13_test.s

utility13-test: build/amiga/utility13_test build/amiga/utility.library
	rm -rf build/vamos-util && mkdir -p build/vamos-util/libs && cp build/amiga/utility.library build/vamos-util/libs/ && cp $< build/vamos-util/test
	cd build/vamos-util && $(VAMOS) -q -V sys:. -a libs:sys:libs -s 64 -O 'utility.library=mode:amiga' test > vamos.log 2>&1; cat result.txt   # mode:amiga = load ours, not vamos' fake

# SANA-II driver probe (tools/amiga/sana2_probe.c): the driver alone on the emulated A2065, no stack
build/amiga/sana2_probe.s: tools/amiga/sana2_probe.c
	@mkdir -p build/amiga
	$(VC) $(VCFLAGS) $< -o=$@

build/amiga/sana2_probe: bench/amiga/startup.s build/amiga/sana2_probe.s
	sed 's#build/amiga/x25519bench.s#build/amiga/sana2_probe.s#' bench/amiga/startup.s > build/amiga/startup_sana2_probe.s
	$(VASM) $(VASMFLAGS) -o $@ build/amiga/startup_sana2_probe.s

sana2-probe: build/amiga/sana2_probe

# holder: configures the interface with its ROM address and keeps the device open (NET_HOLD=1 in the run script)
build/amiga/sana2_hold.s: tools/amiga/sana2_hold.c
	@mkdir -p build/amiga
	$(VC) $(VCFLAGS) $< -o=$@

build/amiga/sana2_hold: bench/amiga/startup.s build/amiga/sana2_hold.s
	sed 's#build/amiga/x25519bench.s#build/amiga/sana2_hold.s#' bench/amiga/startup.s > build/amiga/startup_sana2_hold.s
	$(VASM) $(VASMFLAGS) -o $@ build/amiga/startup_sana2_hold.s

run-sana2: build/amiga/sana2_probe build/amiga/utility.library
	NET_NOSTACK=1 tools/run-fsuae-net.sh $< 120

# smoke test without a stack: vamos has no bsdsocket.library, the probe must report that and exit cleanly
vamos-probe: build/amiga/wa_probe
	mkdir -p build/vamos-sys && cp $< build/vamos-sys/test && rm -f build/vamos-sys/result.txt build/vamos-sys/done
	head -c 64 /dev/urandom > build/vamos-sys/seed.bin
	cd build/vamos-sys && $(VAMOS) -q -V sys:. -s 64 test > vamos.log 2>&1; cat result.txt

clean:
	rm -rf build

// genvectors writes test vectors using Go's standard library and libsignal as
// independent oracles for the WhatsA500 implementations.
//
//	go run ./tools/genvectors -mode x25519 -n 256 > tests/vectors/x25519_random.txt
//	go run ./tools/genvectors -mode ed25519 -n 64 > tests/vectors/ed25519_random.txt
//	go run ./tools/genvectors -mode xeddsa  -n 64 > tests/vectors/xeddsa_random.txt
//	go run ./tools/genvectors -mode sha512  -n 32 > tests/vectors/sha512_random.txt
//
// Formats (all hex, little-endian byte strings as on the wire):
//	x25519:  <scalar> <u> <out>
//	ed25519: <pk> <msg> <sig> <valid 1/0>      (every 4th line has a corrupted signature)
//	xeddsa:  <curve25519 pk> <msg> <sig> <valid 1/0>
//	sha512:  <msg> <digest>
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"go.mau.fi/libsignal/ecc"
)

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	must(err)
	return b
}

func corrupt(sig []byte, i int) {
	// flip one bit somewhere in R or S, or make S non-canonical by adding L
	switch i % 3 {
	case 0:
		sig[i%32] ^= 1 << uint(i%8)
	case 1:
		sig[32+i%32] ^= 1 << uint(i%8)
	default:
		sig[63] |= 0x40 // S >= L
	}
}

func main() {
	mode := flag.String("mode", "x25519", "x25519 | ed25519 | xeddsa | sha512 | aesgcm | noise | rsa | rsapss")
	n := flag.Int("n", 64, "number of vectors")
	flag.Parse()

	switch *mode {
	case "x25519":
		curve := ecdh.X25519()
		for i := 0; i < *n; {
			sc, u := randBytes(32), randBytes(32)
			if i%4 == 0 {
				u[31] |= 0x80
			}
			priv, err := curve.NewPrivateKey(sc)
			must(err)
			pub, err := curve.NewPublicKey(u)
			must(err)
			out, err := priv.ECDH(pub)
			if err != nil {
				continue
			}
			fmt.Printf("%x %x %x\n", sc, u, out)
			i++
		}
	case "ed25519":
		for i := 0; i < *n; i++ {
			pk, sk, err := ed25519.GenerateKey(rand.Reader)
			must(err)
			msg := randBytes(i % 200)
			sig := ed25519.Sign(sk, msg)
			valid := 1
			if i%4 == 3 {
				corrupt(sig, i)
				valid = 0
				if ed25519.Verify(pk, msg, sig) {
					valid = 1
				}
			}
			fmt.Printf("%x %x %x %d\n", pk, msg, sig, valid)
		}
	case "xeddsa":
		for i := 0; i < *n; i++ {
			kp, err := ecc.GenerateKeyPair()
			must(err)
			msg := randBytes(i % 200)
			sig := ecc.CalculateSignature(kp.PrivateKey(), msg)
			pk := kp.PublicKey().PublicKey()
			valid := 1
			if i%4 == 3 {
				corrupt(sig[:], i)
				valid = 0
				if ecc.VerifySignature(kp.PublicKey(), msg, sig) {
					valid = 1
				}
			}
			fmt.Printf("%x %x %x %d\n", pk[:], msg, sig[:], valid)
		}
	case "aesgcm":
		// <keybits> <key> <iv> <aad|-> <pt|-> <ct> <tag>
		for i := 0; i < *n; i++ {
			bits := 128
			if i%2 == 1 {
				bits = 256
			}
			key := randBytes(bits / 8)
			iv := randBytes(12)
			aad := randBytes((i * 7) % 40)
			pt := randBytes((i * 13) % 300)
			block, err := aes.NewCipher(key)
			must(err)
			g, err := cipher.NewGCM(block)
			must(err)
			out := g.Seal(nil, iv, pt, aad)
			ct, tag := out[:len(pt)], out[len(pt):]
			hx := func(b []byte) string {
				if len(b) == 0 {
					return "-"
				}
				return hex.EncodeToString(b)
			}
			fmt.Printf("%d %x %x %s %s %s %x\n", bits, key, iv, hx(aad), hx(pt), hx(ct), tag)
		}
	case "noise":
		noiseVectors(*n)
	case "rsa":
		rsaVectors(*n)
	case "rsapss":
		rsaPssVectors(*n)
	case "sha512":
		for i := 0; i < *n; i++ {
			msg := randBytes(i * 13)
			d := sha512.Sum512(msg)
			fmt.Printf("%x %x\n", msg, d[:])
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown mode")
		os.Exit(2)
	}
}

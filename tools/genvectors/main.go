// genvectors writes random X25519 test vectors using Go's standard library
// (crypto/ecdh) as an independent oracle for the WhatsA500 implementations.
//
//	go run ./tools/genvectors -n 256 > tests/vectors/x25519_random.txt
//
// Each line: <scalar hex> <u hex> <expected output hex>, all little-endian
// byte strings as in RFC 7748. Inputs producing an all-zero output (low-order
// points) are skipped because crypto/ecdh rejects them; they are covered by
// dedicated vectors instead.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
)

func main() {
	n := flag.Int("n", 256, "number of vectors")
	flag.Parse()
	curve := ecdh.X25519()
	for i := 0; i < *n; {
		var sc, u [32]byte
		if _, err := rand.Read(sc[:]); err != nil {
			panic(err)
		}
		if _, err := rand.Read(u[:]); err != nil {
			panic(err)
		}
		if i%4 == 0 {
			u[31] |= 0x80 // exercise the "ignore bit 255" rule
		}
		priv, err := curve.NewPrivateKey(sc[:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		pub, err := curve.NewPublicKey(u[:])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		out, err := priv.ECDH(pub)
		if err != nil {
			continue // low-order point, skip
		}
		fmt.Printf("%s %s %s\n", hex.EncodeToString(sc[:]), hex.EncodeToString(u[:]), hex.EncodeToString(out))
		i++
	}
}

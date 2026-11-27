package main

// Deterministic XEdDSA signing vectors for xeddsa_sign (crypto/ref/ed25519.c): libsignal's ecc.CalculateSignature
// draws its 64 nonce bytes from crypto/rand, so the library cannot produce a reproducible signature. This is the
// same algorithm as go.mau.fi/libsignal v0.2.3 ecc/SignCurve25519.go `sign` with the random bytes passed in;
// every vector is additionally checked with the real ecc.VerifySignature, so a copy error would show up here.
//
//	go run ./tools/genvectors -mode xeddsa-sign -n 64 > tests/vectors/xeddsa_sign.txt
//	format: <clamped curve25519 priv> <random 64> <msg|-> <sig>

import (
	"crypto/sha512"
	"fmt"

	"filippo.io/edwards25519"
	"go.mau.fi/libsignal/ecc"
)

func xeddsaSignDeterministic(priv *[32]byte, message []byte, random [64]byte) [64]byte {
	var A edwards25519.Point
	scalar, _ := edwards25519.NewScalar().SetBytesWithClamping(priv[:])
	A.ScalarBaseMult(scalar)
	publicKey := *(*[32]byte)(A.Bytes())

	diversifier := [32]byte{0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	h := sha512.New()
	h.Write(diversifier[:])
	h.Write(priv[:])
	h.Write(message)
	h.Write(random[:])
	var r [64]byte
	h.Sum(r[:0])
	rReduced, _ := edwards25519.NewScalar().SetUniformBytes(r[:])
	var R edwards25519.Point
	R.ScalarBaseMult(rReduced)
	encodedR := *(*[32]byte)(R.Bytes())

	h.Reset()
	h.Write(encodedR[:])
	h.Write(publicKey[:])
	h.Write(message)
	var hram [64]byte
	h.Sum(hram[:0])
	hramReduced, _ := edwards25519.NewScalar().SetUniformBytes(hram[:])
	s := edwards25519.NewScalar().MultiplyAdd(hramReduced, scalar, rReduced)

	var sig [64]byte
	copy(sig[:32], encodedR[:])
	copy(sig[32:], s.Bytes())
	sig[63] |= publicKey[31] & 0x80
	return sig
}

func xeddsaSignVectors(n int) {
	for i := 0; i < n; i++ {
		kp, err := ecc.GenerateKeyPair()
		must(err)
		priv := kp.PrivateKey().Serialize()
		var random [64]byte
		copy(random[:], randBytes(64))
		msg := randBytes((i * 37) % 300)
		sig := xeddsaSignDeterministic(&priv, msg, random)
		if !ecc.VerifySignature(kp.PublicKey(), msg, sig) {
			panic("deterministic XEdDSA signature does not verify with libsignal")
		}
		m := "-"
		if len(msg) > 0 {
			m = fmt.Sprintf("%x", msg)
		}
		fmt.Printf("%x %x %s %x\n", priv[:], random[:], m, sig[:])
	}
}

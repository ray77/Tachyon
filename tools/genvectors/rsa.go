package main

// RSA-2048 vectors for the TLS fallback path (RSA key transport + PKCS#1 v1.5 chain
// signatures): Go's crypto/rsa as the oracle.
// Line: n e msg sig valid x xe   (x random < n, xe = x^e mod n)

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"math/big"
)

func rsaVectors(n int) {
	for i := 0; i < n; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		must(err)
		msg := randBytes(10 + i*17%300)
		h := sha256.Sum256(msg)
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, h[:])
		must(err)
		valid := 1
		if i%4 == 3 {
			corrupt(sig, i)
			valid = 0
			if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, h[:], sig) == nil {
				valid = 1
			}
		}
		x, err := rand.Int(rand.Reader, key.N)
		must(err)
		xe := new(big.Int).Exp(x, big.NewInt(int64(key.E)), key.N)
		fmt.Printf("%0512x %x %x %x %d %0512x %0512x\n", key.N, key.E, msg, sig, valid, x, xe)
	}
}

// RSASSA-PSS vectors (SHA-256, MGF1-SHA256, salt length 32 = TLS 1.3 rsa_pss_rsae_sha256).
// Line: n e msg sig valid
func rsaPssVectors(n int) {
	for i := 0; i < n; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		must(err)
		msg := randBytes(10 + i*23%400)
		h := sha256.Sum256(msg)
		sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		must(err)
		valid := 1
		if i%4 == 3 {
			corrupt(sig, i)
			valid = 0
			if rsa.VerifyPSS(&key.PublicKey, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil {
				valid = 1
			}
		}
		fmt.Printf("%0512x %x %x %x %d\n", key.N, key.E, msg, sig, valid)
	}
}

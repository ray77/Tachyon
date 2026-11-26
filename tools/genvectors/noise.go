package main

// Noise_XX_25519_AESGCM_SHA256 handshake vectors in the WhatsApp dialect.
//
// The client side runs on whatsmeow's own socket.NoiseHandshake (the code the
// real client uses), the server side on a mirror written here from the same
// source. The mirror also recomputes the client's outputs and must agree with
// whatsmeow byte for byte before a vector is emitted, so the mirror's final
// transport keys (not reachable through whatsmeow's API without a socket) are
// trustworthy.
//
// Output line (hex fields, space separated):
//   header clientEphPriv clientStaticPriv serverEphPriv serverStaticPriv certPayload clientPayload
//   serverEphPub serverStaticCt certCt   (ServerHello as the client sees it)
//   serverStaticPub clientStaticCt clientPayloadCt writeKey readKey
//   frame0Plain frame0Ct                 (first transport frame client -> server)

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"go.mau.fi/whatsmeow/socket"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

type mirror struct {
	hash, salt []byte
	key        cipher.AEAD
	counter    uint32
}

func gcm(key []byte) cipher.AEAD {
	b, err := aes.NewCipher(key)
	must(err)
	g, err := cipher.NewGCM(b)
	must(err)
	return g
}

func iv(c uint32) []byte { v := make([]byte, 12); binary.BigEndian.PutUint32(v[8:], c); return v }

func (m *mirror) start(pattern, header []byte) {
	m.hash = pattern
	m.salt = pattern
	m.key = gcm(pattern)
	m.auth(header)
}
func (m *mirror) auth(d []byte) { h := sha256.Sum256(append(append([]byte{}, m.hash...), d...)); m.hash = h[:] }
func (m *mirror) hk(ikm []byte) (w, r []byte) {
	h := hkdf.New(sha256.New, ikm, m.salt, nil)
	w, r = make([]byte, 32), make([]byte, 32)
	_, err := io.ReadFull(h, w)
	must(err)
	_, err = io.ReadFull(h, r)
	must(err)
	return
}
func (m *mirror) mix(priv, pub []byte) {
	s, err := curve25519.X25519(priv, pub)
	must(err)
	w, r := m.hk(s)
	m.salt = w
	m.key = gcm(r)
	m.counter = 0
}
func (m *mirror) enc(p []byte) []byte {
	c := m.key.Seal(nil, iv(m.counter), p, m.hash)
	m.counter++
	m.auth(c)
	return c
}
func (m *mirror) dec(c []byte) []byte {
	p, err := m.key.Open(nil, iv(m.counter), c, m.hash)
	must(err)
	m.counter++
	m.auth(c)
	return p
}
func (m *mirror) finish() (w, r []byte) { return m.hk(nil) }

func pub(priv []byte) []byte { p, err := curve25519.X25519(priv, curve25519.Basepoint); must(err); return p }

func noiseVectors(n int) {
	pattern := []byte(socket.NoiseStartPattern)
	for i := 0; i < n; i++ {
		header := socket.WAConnHeader
		if i%3 == 1 {
			header = randBytes(4)
		}
		cEph, cSt, sEph, sSt := randBytes(32), randBytes(32), randBytes(32), randBytes(32)
		for _, k := range [][]byte{cEph, cSt, sEph, sSt} {
			k[0] &= 248
			k[31] &= 127
			k[31] |= 64
		}
		cert := randBytes(100 + i*7%600)
		cpl := randBytes(50 + i*13%400)
		frame := randBytes(1 + i*31%900)

		// server (mirror, responder)
		var s mirror
		s.start(pattern, header)
		s.auth(pub(cEph))
		s.auth(pub(sEph))
		s.mix(sEph, pub(cEph))
		sStaticCt := s.enc(pub(sSt))
		s.mix(sSt, pub(cEph))
		certCt := s.enc(cert)

		// client on whatsmeow
		nh := socket.NewNoiseHandshake()
		nh.Start(socket.NoiseStartPattern, header)
		nh.Authenticate(pub(cEph))
		nh.Authenticate(pub(sEph))
		must(nh.MixSharedSecretIntoKey(*(*[32]byte)(cEph), *(*[32]byte)(pub(sEph))))
		stPlain, err := nh.Decrypt(sStaticCt)
		must(err)
		if !bytes.Equal(stPlain, pub(sSt)) {
			panic("server static mismatch")
		}
		must(nh.MixSharedSecretIntoKey(*(*[32]byte)(cEph), *(*[32]byte)(stPlain)))
		certPlain, err := nh.Decrypt(certCt)
		must(err)
		if !bytes.Equal(certPlain, cert) {
			panic("cert mismatch")
		}
		cStaticCt := nh.Encrypt(pub(cSt))
		must(nh.MixSharedSecretIntoKey(*(*[32]byte)(cSt), *(*[32]byte)(pub(sEph))))
		cplCt := nh.Encrypt(cpl)

		// client on the mirror: must agree with whatsmeow
		var c mirror
		c.start(pattern, header)
		c.auth(pub(cEph))
		c.auth(pub(sEph))
		c.mix(cEph, pub(sEph))
		if !bytes.Equal(c.dec(sStaticCt), pub(sSt)) {
			panic("mirror static")
		}
		c.mix(cEph, pub(sSt))
		if !bytes.Equal(c.dec(certCt), cert) {
			panic("mirror cert")
		}
		if !bytes.Equal(c.enc(pub(cSt)), cStaticCt) {
			panic("mirror client static ct differs from whatsmeow")
		}
		c.mix(cSt, pub(sEph))
		if !bytes.Equal(c.enc(cpl), cplCt) {
			panic("mirror client payload ct differs from whatsmeow")
		}
		// server finishes
		if !bytes.Equal(s.dec(cStaticCt), pub(cSt)) {
			panic("server dec static")
		}
		s.mix(sEph, pub(cSt))
		if !bytes.Equal(s.dec(cplCt), cpl) {
			panic("server dec payload")
		}
		// both sides derive the same (first, second) pair from the same salt; whatsmeow (the
		// client) writes with the first and reads with the second, so the server does the reverse
		cw, cr := c.finish()
		sw, sr := s.finish()
		if !bytes.Equal(cw, sw) || !bytes.Equal(cr, sr) {
			panic("final key derivation differs between the two sides")
		}
		// first transport frame client -> server: AES-256-GCM, iv counter 0, no AD
		frameCt := gcm(cw).Seal(nil, iv(0), frame, nil)

		fmt.Printf("%x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x %x\n",
			header, cEph, cSt, sEph, sSt, cert, cpl,
			pub(sEph), sStaticCt, certCt,
			pub(sSt), cStaticCt, cplCt, cw, cr,
			frame, frameCt)
	}
}

// Loopback TLS 1.3 server restricted to X25519 and an RSA-2048 certificate - the test
// oracle for crypto/ref/tls13.c (Go negotiates TLS_AES_128_GCM_SHA256 from our single
// offered suite and signs CertificateVerify with rsa_pss_rsae_sha256). Writes its
// self-signed certificate (DER) to the given path so the client can pin it, then echoes
// application data (each record echoed back with "echo:" prefixed) until the client
// closes. Connections whose handshake fails (the wrong-root test) are reported and skipped.
//
//   go run ./tools/tls13server -listen 127.0.0.1:4436 -cert build/tls13_test_cert.der -n 3
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:4436", "address")
	certPath := flag.String("cert", "build/tls13_test_cert.der", "where to write the server certificate (DER)")
	n := flag.Int("n", 1, "number of connections to serve")
	flag.Parse()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "tls-test.localhost"},
		DNSNames:           []string{"tls-test.localhost", "*.test.localhost"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(*certPath, der, 0o644); err != nil {
		panic(err)
	}
	cfg := &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519},
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		panic(err)
	}
	fmt.Println("READY", ln.Addr().String())
	for i := 0; i < *n; i++ {
		c, err := ln.Accept()
		if err != nil {
			panic(err)
		}
		t := tls.Server(c, cfg)
		if err := t.Handshake(); err != nil {
			fmt.Println("HANDSHAKE ERROR:", err)
			c.Close()
			continue
		}
		st := t.ConnectionState()
		fmt.Printf("HANDSHAKE OK version=%04x suite=%04x\n", st.Version, st.CipherSuite)
		buf := make([]byte, 16384)
		for {
			m, err := t.Read(buf)
			if err != nil {
				break
			}
			if _, err := t.Write(append([]byte("echo:"), buf[:m]...)); err != nil {
				break
			}
		}
		t.Close()
		fmt.Println("CLOSED")
	}
}

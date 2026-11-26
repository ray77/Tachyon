// Loopback TLS 1.2 server restricted to TLS_RSA_WITH_AES_128_GCM_SHA256 - the test
// oracle for crypto/ref/tls12.c. Writes its self-signed RSA-2048 certificate (DER)
// to the given path so the client can pin it, then echoes application data
// (each record echoed back with "echo:" prefixed) until the client closes.
//
//   go run ./tools/tlsserver -listen 127.0.0.1:4433 -cert build/tls_test_cert.der -n 1
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
	listen := flag.String("listen", "127.0.0.1:4433", "address")
	certPath := flag.String("cert", "build/tls_test_cert.der", "where to write the server certificate (DER)")
	n := flag.Int("n", 1, "number of connections to serve")
	flag.Parse()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "tls-test.localhost"},
		DNSNames:     []string{"tls-test.localhost", "*.test.localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_GCM_SHA256},
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

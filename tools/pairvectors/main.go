// pairvectors is the whatsmeow-side oracle for Tachyon's pairing code (proto/clientpayload.c, proto/pairing.c).
// It uses the whatsmeow version pinned in go.mod (c2ce5c3) so that the C code is compared with the reference
// implementation itself, not with a reading of it. Offline; nothing here talks to a server.
//
//	go run ./tools/pairvectors -mode clientpayload > build/clientpayload_ref.bin
//	    whatsmeow's registration and login ClientPayload for the fixed test identity below
//	    (u32 BE length + bytes, twice); tests/clientpayload_test.c builds the same identity and compares.
//	go run ./tools/pairvectors -mode pairsuccess > tests/vectors/pair_success_iq.bin
//	    a synthetic pair-success IQ frame (flags byte + binary node) as the server would send it after the phone
//	    scanned our QR: ADVDeviceIdentity{rawID, timestamp, keyIndex 3} signed by a test account key, HMAC under
//	    the test ADV secret, device/lid/platform/biz children; tests/pairing_test.c must verify and answer it.
//	go run ./tools/pairvectors -mode verify-sign -in build/pair_device_sign.bin -ref tests/vectors/pair_success_iq.bin
//	    checks the pair-device-sign IQ frame the C code produced: structure, key-index, account key cleared, details
//	    unchanged, device signature valid under the test identity key (libsignal ecc.VerifySignature).
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"os"

	"go.mau.fi/libsignal/ecc"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/proto/waCompanionReg"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

// The fixed test identity, mirrored in tests/clientpayload_test.c and tests/pairing_test.c.
func pattern(mul, add byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)*mul + add
	}
	return b
}

func clampedPair(priv []byte) *keys.KeyPair {
	var p [32]byte
	copy(p[:], priv)
	p[0] &= 248
	p[31] &= 127
	p[31] |= 64
	return keys.NewKeyPairFromPrivateKey(p)
}

const testJIDUser = "4917612345678"
const testLIDUser = "123456789012345"
const testDevice = 7
const testIQID = "3EB0ABCDEF"
const testKeyIndex = 3

var (
	noiseKey    = clampedPair(pattern(3, 1, 32))
	identityKey = clampedPair(pattern(5, 2, 32))
	preKey      = clampedPair(pattern(7, 3, 32))
	spkSig      = pattern(1, 0x40, 64)
	advSecret   = pattern(1, 0xA0, 32)
	accountKey  = clampedPair(pattern(11, 5, 32))
)

func testDevice_() *store.Device {
	var sig [64]byte
	copy(sig[:], spkSig)
	store.DeviceProps.Os = proto.String("Amiga 500")
	store.DeviceProps.PlatformType = waCompanionReg.DeviceProps_FIREFOX.Enum() // proto/clientpayload.h WA_PLATFORM_TYPE
	return &store.Device{
		NoiseKey:       noiseKey,
		IdentityKey:    identityKey,
		SignedPreKey:   &keys.PreKey{KeyPair: *preKey, KeyID: 1, Signature: &sig},
		RegistrationID: 0x1234,
		AdvSecretKey:   advSecret,
	}
}

func writeChunk(b []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(b)))
	os.Stdout.Write(l[:])
	os.Stdout.Write(b)
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func deviceIdentityDetails() []byte {
	d, err := proto.Marshal(&waAdv.ADVDeviceIdentity{
		RawID:     proto.Uint32(1234567),
		Timestamp: proto.Uint64(1764300000),
		KeyIndex:  proto.Uint32(testKeyIndex),
	})
	must(err)
	return d
}

func main() {
	mode := flag.String("mode", "clientpayload", "clientpayload | pairsuccess | verify-sign")
	in := flag.String("in", "", "verify-sign: the pair-device-sign frame written by tests/pairing_test.c")
	ref := flag.String("ref", "", "verify-sign: the pair-success frame the test answered")
	flag.Parse()

	switch *mode {
	case "clientpayload":
		d := testDevice_()
		reg, err := proto.Marshal(d.GetClientPayload())
		must(err)
		jid := types.NewADJID(testJIDUser, 0, testDevice)
		d.ID = &jid
		login, err := proto.Marshal(d.GetClientPayload())
		must(err)
		writeChunk(reg)
		writeChunk(login)
		fmt.Fprintf(os.Stderr, "registration %d bytes, login %d bytes (whatsmeow version %s, hash %x)\n",
			len(reg), len(login), store.GetWAVersion().String(), store.GetWAVersion().Hash())

	case "pairsuccess":
		details := deviceIdentityDetails()
		accMsg := append(append([]byte{6, 0}, details...), identityKey.Pub[:]...)
		accSig := ecc.CalculateSignature(ecc.NewDjbECPrivateKey(*accountKey.Priv), accMsg)
		signed, err := proto.Marshal(&waAdv.ADVSignedDeviceIdentity{
			Details:             details,
			AccountSignatureKey: accountKey.Pub[:],
			AccountSignature:    accSig[:],
		})
		must(err)
		h := hmac.New(sha256.New, advSecret)
		h.Write(signed)
		container, err := proto.Marshal(&waAdv.ADVSignedDeviceIdentityHMAC{Details: signed, HMAC: h.Sum(nil)})
		must(err)
		node := waBinary.Node{
			Tag:   "iq",
			Attrs: waBinary.Attrs{"from": types.ServerJID, "id": testIQID, "type": "set", "t": "1764300000"},
			Content: []waBinary.Node{{Tag: "pair-success", Content: []waBinary.Node{
				{Tag: "device-identity", Content: container},
				{Tag: "device", Attrs: waBinary.Attrs{
					"jid": types.NewADJID(testJIDUser, 0, testDevice),
					"lid": types.JID{User: testLIDUser, Server: types.HiddenUserServer, Device: testDevice},
				}},
				{Tag: "platform", Attrs: waBinary.Attrs{"name": "android"}},
				{Tag: "biz", Attrs: waBinary.Attrs{"name": "Amiga Test"}},
			}}},
		}
		frame, err := waBinary.Marshal(node) // flags byte 0 + node, as the server sends it inside the Noise frame
		must(err)
		os.Stdout.Write(frame)
		fmt.Fprintf(os.Stderr, "pair-success frame %d bytes, account key %x\n", len(frame), accountKey.Pub[:])

	case "verify-sign":
		data, err := os.ReadFile(*in)
		must(err)
		refData, err := os.ReadFile(*ref)
		must(err)
		if len(data) < 2 || data[0] != 0 || len(refData) < 2 || refData[0] != 0 {
			fmt.Fprintln(os.Stderr, "FAIL verify-sign: frames must start with the flags byte 0")
			os.Exit(1)
		}
		node, err := waBinary.Unmarshal(data[1:])
		must(err)
		refNode, err := waBinary.Unmarshal(refData[1:])
		must(err)
		fail := func(f string, a ...any) { fmt.Fprintf(os.Stderr, "FAIL verify-sign: "+f+"\n", a...); os.Exit(1) }
		if node.Tag != "iq" || node.Attrs["type"] != "result" || node.Attrs["id"] != refNode.Attrs["id"] {
			fail("iq header wrong: %s", node.String())
		}
		if to, ok := node.Attrs["to"].(types.JID); !ok || to != types.ServerJID {
			fail("to is not s.whatsapp.net: %v", node.Attrs["to"])
		}
		sign := node.GetChildByTag("pair-device-sign")
		di := sign.GetChildByTag("device-identity")
		if di.Tag != "device-identity" || di.Attrs["key-index"] != fmt.Sprint(testKeyIndex) {
			fail("device-identity / key-index wrong: %s", node.String())
		}
		content, _ := di.Content.([]byte)
		var self waAdv.ADVSignedDeviceIdentity
		must(proto.Unmarshal(content, &self))
		var refContainer waAdv.ADVSignedDeviceIdentityHMAC
		refPS := refNode.GetChildByTag("pair-success")
		refDI, _ := refPS.GetChildByTag("device-identity").Content.([]byte)
		must(proto.Unmarshal(refDI, &refContainer))
		var refSigned waAdv.ADVSignedDeviceIdentity
		must(proto.Unmarshal(refContainer.Details, &refSigned))
		if len(self.AccountSignatureKey) != 0 {
			fail("accountSignatureKey not cleared")
		}
		if !bytes.Equal(self.Details, refSigned.Details) || !bytes.Equal(self.AccountSignature, refSigned.AccountSignature) {
			fail("details or account signature changed")
		}
		if len(self.DeviceSignature) != 64 {
			fail("device signature length %d", len(self.DeviceSignature))
		}
		var pub [32]byte
		curve25519.ScalarBaseMult(&pub, identityKey.Priv)
		msg := append(append(append([]byte{6, 1}, self.Details...), pub[:]...), accountKey.Pub[:]...)
		var sig [64]byte
		copy(sig[:], self.DeviceSignature)
		if !ecc.VerifySignature(ecc.NewDjbECPublicKey(pub), msg, sig) {
			fail("device signature does not verify under the identity key")
		}
		// the reverse check: re-marshal with whatsmeow and compare with the C encoder byte for byte
		expect, err := proto.Marshal(&self)
		must(err)
		if !bytes.Equal(expect, content) {
			fail("self-signed identity bytes differ from whatsmeow's marshal:\n got  %x\n want %x", content, expect)
		}
		fmt.Println("OK verify-sign: pair-device-sign IQ well formed, key-index", testKeyIndex, ", device signature valid, bytes match whatsmeow's marshal")
	default:
		fmt.Fprintln(os.Stderr, "unknown mode")
		os.Exit(2)
	}
}

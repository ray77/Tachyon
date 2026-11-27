// signalvectors is the libsignal-side oracle for Tachyon's Signal session layer (proto/signal.c): X3DH as
// initiator and responder, the Double Ratchet, PreKeySignalMessage / SignalMessage bytes and the MAC, with
// go.mau.fi/libsignal v0.2.3 (the version whatsmeow uses) running BOTH parties. Every key pair the library would
// draw from crypto/rand is either fixed here (the parties' long-term keys, base keys and the first sending
// ratchet keys, through the library's own ratchet/record packages) or read back out of the session record
// afterwards (the ratchet keys created while decrypting), so tests/signal_test.c can feed the identical bytes to
// the C code through a scripted RNG and compare every ciphertext bit for bit. Offline; nothing talks to a server.
//
//	go run ./tools/signalvectors > tests/vectors/signal_vectors.txt
//	    lines "name=hex" (empty value: "name="), comments start with '#'
//	go run ./tools/signalvectors -mode check-message -in build/msg.bin
//	    (tests/wa_msg_sim.c) decrypts a <enc type=pkmsg> body the C core produced for the fixed phone identity
//
// Alice is the companion (our side, the fixed test identity of tools/pairvectors), Bob the phone.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/ratchet"
	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/state/record"
	"go.mau.fi/libsignal/tests"
	"go.mau.fi/libsignal/util/optional"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/whatsmeow/proto/waE2E"
)

var ctx = context.Background()
var ser = serialize.NewProtoBufSerializer()

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func check(ok bool, what string) {
	if !ok {
		fmt.Fprintln(os.Stderr, "FAIL:", what)
		os.Exit(1)
	}
}

func pattern(mul, add byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)*mul + add
	}
	return b
}

func fixedPair(mul, add byte) *ecc.ECKeyPair { return ecc.CreateKeyPair(pattern(mul, add, 32)) }

var out []string

func emit(name string, v []byte)  { out = append(out, fmt.Sprintf("%s=%x", name, v)) }
func emitU(name string, v uint32) { out = append(out, fmt.Sprintf("%s=%08x", name, v)) }
func emitPair(name string, kp *ecc.ECKeyPair) {
	p := kp.PrivateKey().Serialize()
	q := kp.PublicKey().PublicKey()
	emit(name+"_priv", p[:])
	emit(name+"_pub", q[:])
}
func comment(s string) { out = append(out, "# "+s) }

type party struct {
	name  string
	idKP  *identity.KeyPair
	regID uint32
	ids   *tests.InMemoryIdentityKey
	pks   *tests.InMemoryPreKey
	spks  *tests.InMemorySignedPreKey
	sess  *tests.InMemorySession
}

func newParty(name string, idPair *ecc.ECKeyPair, regID uint32) *party {
	kp := identity.NewKeyPair(identity.NewKey(idPair.PublicKey()), idPair.PrivateKey())
	return &party{name: name, idKP: kp, regID: regID,
		ids: tests.NewInMemoryIdentityKey(kp, regID), pks: tests.NewInMemoryPreKey(),
		spks: tests.NewInMemorySignedPreKey(), sess: tests.NewInMemorySession(ser)}
}

func (p *party) builder(remote *protocol.SignalAddress) *session.Builder {
	return session.NewBuilder(p.sess, p.pks, p.spks, p.ids, remote, ser)
}
func (p *party) cipher(remote *protocol.SignalAddress) *session.Cipher {
	return session.NewCipher(p.builder(remote), remote)
}

// the signed prekey signature as libsignal makes it: XEdDSA over 05 || pub under the identity key
func signSPK(p *party, spk *ecc.ECKeyPair) [64]byte {
	sig := ecc.CalculateSignature(p.idKP.PrivateKey(), spk.PublicKey().Serialize())
	check(ecc.VerifySignature(p.idKP.PublicKey().PublicKey(), spk.PublicKey().Serialize(), sig), "spk signature verifies")
	return sig
}

func bundleOf(p *party, spkID uint32, spk *ecc.ECKeyPair, sig [64]byte, opkID uint32, opk *ecc.ECKeyPair) *prekey.Bundle {
	var opkPub ecc.ECPublicKeyable
	opkIDOpt := optional.NewEmptyUint32()
	if opk != nil {
		opkPub = opk.PublicKey()
		opkIDOpt = optional.NewOptionalUint32(opkID)
	}
	return prekey.NewBundle(p.regID, 0, opkIDOpt, spkID, opkPub, spk.PublicKey(), sig, p.idKP.PublicKey())
}

// session.Builder.ProcessBundle with the base key and the first sending ratchet key given instead of drawn
// (the same steps in the same order, through the library's ratchet and record packages); dumps the derived keys
func processBundleFixed(prefix string, me *party, remote *protocol.SignalAddress, b *prekey.Bundle, baseKey, ratchetKey *ecc.ECKeyPair) {
	check(ecc.VerifySignature(b.IdentityKey().PublicKey(), b.SignedPreKey().Serialize(), b.SignedPreKeySignature()), "bundle signature")
	rec, err := me.sess.LoadSession(ctx, remote)
	must(err)
	params := ratchet.NewEmptySenderParameters()
	params.SetOurBaseKey(baseKey)
	params.SetOurIdentityKey(me.idKP)
	params.SetTheirIdentityKey(b.IdentityKey())
	params.SetTheirSignedPreKey(b.SignedPreKey())
	params.SetTheirRatchetKey(b.SignedPreKey())
	params.SetTheirOneTimePreKey(b.PreKey())
	if !rec.IsFresh() {
		rec.ArchiveCurrentState()
	}
	st := rec.SessionState()
	derived, err := ratchet.CalculateSenderSession(params)
	must(err)
	sending, err := derived.RootKey.CreateChain(params.TheirRatchetKey(), ratchetKey)
	must(err)
	st.SetVersion(protocol.CurrentVersion)
	st.SetRemoteIdentityKey(params.TheirIdentityKey())
	st.SetLocalIdentityKey(params.OurIdentityKey().PublicKey())
	st.AddReceiverChain(params.TheirRatchetKey(), derived.ChainKey.Current())
	st.SetSenderChain(ratchetKey, sending.ChainKey)
	st.SetRootKey(sending.RootKey)
	st.SetUnacknowledgedPreKeyMessage(b.PreKeyID(), b.SignedPreKeyID(), baseKey.PublicKey())
	st.SetLocalRegistrationID(me.regID)
	st.SetRemoteRegistrationID(b.RegistrationID())
	st.SetSenderBaseKey(baseKey.PublicKey().Serialize())
	must(me.sess.StoreSession(ctx, remote, rec))
	must(me.ids.SaveIdentity(ctx, remote, b.IdentityKey()))
	emit(prefix+"_x3dh_root", derived.RootKey.Bytes())
	emit(prefix+"_x3dh_chain", derived.ChainKey.Key())
	emit(prefix+"_send_root", sending.RootKey.Bytes())
	emit(prefix+"_send_chain", sending.ChainKey.Key())
	mk := st.SenderChainKey().MessageKeys()
	emit(prefix+"_m0_cipherkey", mk.CipherKey())
	emit(prefix+"_m0_mackey", mk.MacKey())
	emit(prefix+"_m0_iv", mk.Iv())
}

func encrypt(name string, me *party, remote *protocol.SignalAddress, pt []byte) []byte {
	msg, err := me.cipher(remote).Encrypt(ctx, pt)
	must(err)
	out = append(out, fmt.Sprintf("%s_type=%02x", name, msg.Type()))
	emit(name+"_pt", pt)
	emit(name, msg.Serialize())
	return msg.Serialize()
}

func decryptPK(me *party, remote *protocol.SignalAddress, b []byte) ([]byte, error) {
	pk, err := protocol.NewPreKeySignalMessageFromBytes(b, ser.PreKeySignalMessage, ser.SignalMessage)
	if err != nil {
		return nil, err
	}
	return me.cipher(remote).DecryptMessage(ctx, pk)
}

func decryptMsg(me *party, remote *protocol.SignalAddress, b []byte) ([]byte, error) {
	sm, err := protocol.NewSignalMessageFromBytes(b, ser.SignalMessage)
	if err != nil {
		return nil, err
	}
	return me.cipher(remote).Decrypt(ctx, sm)
}

// a record that went through the store, as whatsmeow's database store hands it back: not "fresh" any more, so a new
// session archives the current state (the in-memory test store would otherwise overwrite it in place)
func persist(p *party, remote *protocol.SignalAddress) {
	rec, err := p.sess.LoadSession(ctx, remote)
	must(err)
	again, err := record.NewSessionFromBytes(rec.Serialize(), ser.Session, ser.State)
	must(err)
	must(p.sess.StoreSession(ctx, remote, again))
}

func expectPlain(what string, pt []byte, err error, want []byte) {
	must(err)
	check(bytes.Equal(pt, want), what+": plaintext")
}

func dumpState(prefix string, me *party, remote *protocol.SignalAddress) {
	rec, err := me.sess.LoadSession(ctx, remote)
	must(err)
	st := rec.SessionState()
	emit(prefix+"_root", st.RootKey().Bytes())
	emitPair(prefix+"_ratchet", st.SenderRatchetKeyPair())
	emit(prefix+"_send_chain", st.SenderChainKey().Key())
	emitU(prefix+"_send_index", st.SenderChainKey().Index())
	emitU(prefix+"_prev_counter", st.PreviousCounter())
}

// Alice = the fixed test identity of tools/pairvectors (tests/clientpayload_test.c): identity 5/2, signed prekey 7/3 id 1,
// registration id 0x1234. Bob = the phone.
var (
	aliceIdent = fixedPair(5, 2)
	aliceSPK   = fixedPair(7, 3)
	aliceOPK   = fixedPair(37, 23)
	bobIdent   = fixedPair(19, 11)
	bobSPK     = fixedPair(23, 13)
	bobOPK     = fixedPair(29, 17)
)

const aliceSPKID, aliceOPKID, aliceRegID = 1, 5, 0x1234
const bobSPKID, bobOPKID, bobRegID = 7, 42, 0xBEEF

func setup() (alice, bob *party, addrAlice, addrBob *protocol.SignalAddress, aliceSig, bobSig [64]byte) {
	alice = newParty("alice", aliceIdent, aliceRegID)
	bob = newParty("bob", bobIdent, bobRegID)
	addrAlice = protocol.NewSignalAddress("4917612345678", 7)
	addrBob = protocol.NewSignalAddress("4917612345678", 0)
	aliceSig = signSPK(alice, aliceSPK)
	bobSig = signSPK(bob, bobSPK)
	must(alice.spks.StoreSignedPreKey(ctx, aliceSPKID, record.NewSignedPreKey(aliceSPKID, 0, aliceSPK, aliceSig, ser.SignedPreKeyRecord)))
	must(alice.pks.StorePreKey(ctx, aliceOPKID, record.NewPreKey(aliceOPKID, aliceOPK, ser.PreKeyRecord)))
	must(bob.spks.StoreSignedPreKey(ctx, bobSPKID, record.NewSignedPreKey(bobSPKID, 0, bobSPK, bobSig, ser.SignedPreKeyRecord)))
	must(bob.pks.StorePreKey(ctx, bobOPKID, record.NewPreKey(bobOPKID, bobOPK, ser.PreKeyRecord)))
	return
}

func vectors() {
	alice, bob, addrAlice, addrBob, aliceSig, bobSig := setup()
	comment("Tachyon Signal vectors (tools/signalvectors, go.mau.fi/libsignal v0.2.3). Alice = companion (test identity), Bob = phone.")
	comment("long-term keys")
	emitPair("alice_ident", aliceIdent)
	emitU("alice_regid", aliceRegID)
	emitU("alice_spk_id", aliceSPKID)
	emitPair("alice_spk", aliceSPK)
	emit("alice_spk_sig", aliceSig[:])
	emitU("alice_opk_id", aliceOPKID)
	emitPair("alice_opk", aliceOPK)
	emitPair("bob_ident", bobIdent)
	emitU("bob_regid", bobRegID)
	emitU("bob_spk_id", bobSPKID)
	emitPair("bob_spk", bobSPK)
	emit("bob_spk_sig", bobSig[:])
	emitU("bob_opk_id", bobOPKID)
	emitPair("bob_opk", bobOPK)

	// ---- scenario 1: Alice fetches Bob's bundle and writes first --------------------------------------------
	comment("s1: Alice initiates (X3DH with one-time prekey), two prekey messages, Bob answers three times, Alice reads them out of order")
	aliceBase := fixedPair(17, 9)
	aliceRatchet1 := fixedPair(41, 29)
	emitPair("s1_alice_base", aliceBase)
	emitPair("s1_alice_ratchet1", aliceRatchet1)
	bobBundle := bundleOf(bob, bobSPKID, bobSPK, bobSig, bobOPKID, bobOPK)
	processBundleFixed("s1", alice, addrBob, bobBundle, aliceBase, aliceRatchet1)
	pt1 := append([]byte("Hallo vom Amiga 500"), bytes.Repeat([]byte{5}, 5)...) // whatsmeow padding: 1..15 x the pad byte
	pt2 := append([]byte("zweite Nachricht, gleiche Kette"), bytes.Repeat([]byte{1}, 1)...)
	pk1 := encrypt("s1_pkmsg1", alice, addrBob, pt1)
	check(pk1[0] == 0x33, "version byte 0x33")
	pk2 := encrypt("s1_pkmsg2", alice, addrBob, pt2)

	// Bob: X3DH as responder from the prekey message (uses his signed prekey 7 and one-time prekey 42), decrypts both
	pt, err := decryptPK(bob, addrAlice, pk1)
	expectPlain("bob pkmsg1", pt, err, pt1)
	dumpState("s1_bob1", bob, addrAlice) // his first sending ratchet key was drawn while decrypting: the C side gets it from here
	contains, _ := bob.pks.ContainsPreKey(ctx, bobOPKID)
	check(!contains, "one-time prekey 42 removed after use")
	pt, err = decryptPK(bob, addrAlice, pk2)
	expectPlain("bob pkmsg2", pt, err, pt2)
	// the same prekey message again: the session exists for this base key, the inner counter is old -> rejected
	_, err = decryptPK(bob, addrAlice, pk1)
	check(err != nil, "replayed prekey message rejected")
	comment("s1_pkmsg1 delivered twice: libsignal rejects the second copy (old counter)")

	r1 := append([]byte("Antwort eins"), bytes.Repeat([]byte{3}, 3)...)
	r2 := append([]byte("Antwort zwei"), bytes.Repeat([]byte{7}, 7)...)
	r3 := append([]byte("Antwort drei"), bytes.Repeat([]byte{2}, 2)...)
	m1 := encrypt("s1_msg1", bob, addrAlice, r1)
	check(m1[0] == 0x33 && len(m1) > 9, "signal message")
	m2 := encrypt("s1_msg2", bob, addrAlice, r2)
	m3 := encrypt("s1_msg3", bob, addrAlice, r3)

	// Alice: msg2 first (counter 1: the key for counter 0 is skipped and kept), then msg1 (from the skipped keys), then msg3
	pt, err = decryptMsg(alice, addrBob, m2)
	expectPlain("alice msg2", pt, err, r2)
	dumpState("s1_alice2", alice, addrBob) // her second ratchet key, drawn while decrypting
	pt, err = decryptMsg(alice, addrBob, m1)
	expectPlain("alice msg1 (skipped key)", pt, err, r1)
	pt, err = decryptMsg(alice, addrBob, m3)
	expectPlain("alice msg3", pt, err, r3)
	_, err = decryptMsg(alice, addrBob, m1)
	check(err != nil, "replayed msg1 rejected")
	comment("s1_msg1 delivered twice: the second copy is rejected (old counter, key consumed)")

	// Alice writes on the new chain (DH ratchet done while decrypting msg2): a plain SignalMessage now, the prekey part is acknowledged
	pt3 := append([]byte("dritte Nachricht, neue Kette"), bytes.Repeat([]byte{4}, 4)...)
	m4 := encrypt("s1_msg4", alice, addrBob, pt3)
	check(m4[0] == 0x33 && bytes.HasPrefix(m4[1:], []byte{0x0a, 0x21, 0x05}), "msg4 is a SignalMessage (ratchetKey first)")
	pt, err = decryptMsg(bob, addrAlice, m4)
	expectPlain("bob msg4", pt, err, pt3)
	dumpState("s1_bob2", bob, addrAlice)
	r4 := append([]byte("Antwort vier"), bytes.Repeat([]byte{15}, 15)...)
	m5 := encrypt("s1_msg5", bob, addrAlice, r4)
	pt, err = decryptMsg(alice, addrBob, m5)
	expectPlain("alice msg5", pt, err, r4)
	dumpState("s1_alice3", alice, addrBob)

	// negative cases, asserted here so the C test's expectations are the library's behaviour
	bad := append([]byte{}, m5...)
	bad[len(bad)-1] ^= 1
	_, err = decryptMsg(alice, addrBob, bad)
	check(err != nil, "tampered MAC rejected")
	bad = append([]byte{}, m5...)
	bad[len(bad)-12] ^= 1
	_, err = decryptMsg(alice, addrBob, bad)
	check(err != nil, "tampered ciphertext rejected")
	badSig := bobSig
	badSig[5] ^= 0x40
	badBundle := bundleOf(bob, bobSPKID, bobSPK, badSig, bobOPKID, bobOPK)
	scratch := newParty("scratch", aliceIdent, aliceRegID)
	err = scratch.builder(addrBob).ProcessBundle(ctx, badBundle)
	check(err != nil, "bundle with a bad signature rejected")
	comment("s1_msg5 with its last byte flipped (MAC), with a ciphertext byte flipped, and Bob's bundle with a flipped signature bit: all rejected")

	// Bob writes once more under this session before scenario 2 replaces it: Alice must still read it (previous state)
	r5 := append([]byte("alte Sitzung, letzte Nachricht"), bytes.Repeat([]byte{9}, 9)...)
	m6 := encrypt("s1_msg6", bob, addrAlice, r5)

	// ---- scenario 2: Bob fetches Alice's bundle and starts a fresh session (Alice = responder with our stored prekeys) --------
	comment("s2: Bob initiates with Alice's bundle (signed prekey 1, one-time prekey 5); both sides archive the s1 state")
	persist(alice, addrBob)
	persist(bob, addrAlice)
	bobBase := fixedPair(43, 31)
	bobRatchet3 := fixedPair(47, 37)
	emitPair("s2_bob_base", bobBase)
	emitPair("s2_bob_ratchet1", bobRatchet3)
	aliceBundle := bundleOf(alice, aliceSPKID, aliceSPK, aliceSig, aliceOPKID, aliceOPK)
	processBundleFixed("s2", bob, addrAlice, aliceBundle, bobBase, bobRatchet3)
	q1 := append([]byte("Neue Sitzung vom Telefon"), bytes.Repeat([]byte{8}, 8)...)
	pk3 := encrypt("s2_pkmsg1", bob, addrAlice, q1)
	pt, err = decryptPK(alice, addrBob, pk3)
	expectPlain("alice s2 pkmsg1", pt, err, q1)
	dumpState("s2_alice1", alice, addrBob)
	contains, _ = alice.pks.ContainsPreKey(ctx, aliceOPKID)
	check(!contains, "one-time prekey 5 removed after use")
	{
		// the old session's last message arrives late: decrypted with the archived state (on a copy of Alice's record,
		// so the main flow below stays on the new session; libsignal would promote the old state)
		rec, err := alice.sess.LoadSession(ctx, addrBob)
		must(err)
		clone, err := record.NewSessionFromBytes(rec.Serialize(), ser.Session, ser.State)
		must(err)
		scratch := newParty("scratch", aliceIdent, aliceRegID)
		must(scratch.sess.StoreSession(ctx, addrBob, clone))
		pt, err := decryptMsg(scratch, addrBob, m6)
		expectPlain("alice s1 msg6 via the archived state", pt, err, r5)
		comment("s1_msg6 (old session) decrypts after s2_pkmsg1 through the archived state")
	}
	a1 := append([]byte("Antwort in der neuen Sitzung"), bytes.Repeat([]byte{6}, 6)...)
	m7 := encrypt("s2_msg1", alice, addrBob, a1)
	pt, err = decryptMsg(bob, addrAlice, m7)
	expectPlain("bob s2 msg1", pt, err, a1)
	dumpState("s2_bob2", bob, addrAlice)
	q2 := append([]byte("und zurueck"), bytes.Repeat([]byte{11}, 11)...)
	m8 := encrypt("s2_msg2", bob, addrAlice, q2)
	pt, err = decryptMsg(alice, addrBob, m8)
	expectPlain("alice s2 msg2", pt, err, q2)
	dumpState("s2_alice2", alice, addrBob)

	// a prekey message that names a one-time prekey Alice does not hold
	{
		fake := newParty("fake", fixedPair(53, 41), 0x4242)
		fakeBase := fixedPair(59, 43)
		fakeRatchet := fixedPair(61, 47)
		gone := bundleOf(alice, aliceSPKID, aliceSPK, aliceSig, 999, fixedPair(67, 53))
		processBundleFixed("s3", fake, addrAlice, gone, fakeBase, fakeRatchet)
		pkx := encrypt("s3_pkmsg_unknown_opk", fake, addrAlice, []byte("x"))
		_, err = decryptPK(alice, protocol.NewSignalAddress("fake", 0), pkx)
		check(err != nil, "prekey message with an unknown one-time prekey rejected")
		comment("s3_pkmsg_unknown_opk names one-time prekey 999: rejected (no such prekey)")
	}

	// ---- wa: what the phone sends to the companion in the self chat: real waE2E.Message protobufs with WhatsApp's padding,
	// a prekey message (fresh parties, so Alice's one-time prekey 5 is unused) and a second, plain one on the same session
	comment("wa: the phone's messages to us as the probe core sees them (tests/wa_pair_sim.c): Message protobuf + padding, pkmsg then msg")
	{
		alice2, bob2, addrAlice2, addrBob2, aliceSig2, _ := setup()
		_ = addrBob2
		bundle := bundleOf(alice2, aliceSPKID, aliceSPK, aliceSig2, aliceOPKID, aliceOPK)
		processBundleFixed("wa", bob2, addrAlice2, bundle, fixedPair(71, 59), fixedPair(73, 61))
		dest := "4917612345678@s.whatsapp.net"
		text1 := "Antwort vom Telefon: hallo Amiga!"
		m1, err := proto.Marshal(&waE2E.Message{DeviceSentMessage: &waE2E.DeviceSentMessage{DestinationJID: &dest, Message: &waE2E.Message{Conversation: &text1}}})
		must(err)
		emit("wa_text1", []byte(text1))
		encrypt("wa_pkmsg1", bob2, addrAlice2, append(m1, bytes.Repeat([]byte{4}, 4)...))
		text2 := "zweite Nachricht, gleiche Sitzung \u00e4\u00f6\u00fc"
		m2, err := proto.Marshal(&waE2E.Message{ExtendedTextMessage: &waE2E.ExtendedTextMessage{Text: &text2}})
		must(err)
		emit("wa_text2", []byte(text2))
		encrypt("wa_msg2", bob2, addrAlice2, append(m2, bytes.Repeat([]byte{9}, 9)...))
	}

	for _, l := range out {
		fmt.Println(l)
	}
	fmt.Fprintf(os.Stderr, "%d lines\n", len(out))
}

// check-message: the phone's view of the <enc type=pkmsg> body the C core sent to Bob (device 0 of the test number) in
// the simulator: Bob processes it with his fixed keys, strips WhatsApp's padding, parses the waE2E.Message (expected as
// DeviceSentMessage for our own number) and compares the text with -want
func checkMessage(path, want string) {
	b, err := os.ReadFile(path)
	must(err)
	_, bob, addrAlice, _, _, _ := setup()
	pt, err := decryptPK(bob, addrAlice, b)
	must(err)
	check(len(pt) > 0, "plaintext")
	pad := int(pt[len(pt)-1])
	check(pad >= 1 && pad <= 15 && pad <= len(pt) && bytes.Equal(pt[len(pt)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)), "whatsapp padding 1..15")
	var msg waE2E.Message
	must(proto.Unmarshal(pt[:len(pt)-pad], &msg))
	dsm := msg.GetDeviceSentMessage()
	check(dsm != nil, "DeviceSentMessage wrapper for our own number")
	check(dsm.GetDestinationJID() == "4917612345678@s.whatsapp.net", "destination JID")
	check(dsm.GetMessage().GetConversation() == want, "conversation text == "+want)
	fmt.Printf("check-message: libsignal decrypted the probe's pkmsg (%d bytes): DeviceSentMessage to %s, conversation %q\n", len(b), dsm.GetDestinationJID(), dsm.GetMessage().GetConversation())
}

func main() {
	mode := flag.String("mode", "vectors", "vectors | check-message")
	in := flag.String("in", "", "check-message: the pkmsg body")
	want := flag.String("want", "", "check-message: the expected text")
	flag.Parse()
	switch *mode {
	case "vectors":
		vectors()
	case "check-message":
		checkMessage(*in, *want)
	default:
		must(fmt.Errorf("unknown mode %q", *mode))
	}
}

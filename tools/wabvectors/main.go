// Reference vectors for tests/wabinary_test.c: nodes encoded by whatsmeow's binary package (the version
// pinned in go.mod), each with a text dump of what whatsmeow's own decoder reads back.
//
//	go run ./tools/wabvectors > tests/vectors/wabinary_ref.bin      (make wabinary-vectors)
//
// Per vector: u32 big endian frame length, frame (flags byte + node), u32 dump length, dump.
// Dump: node = "(" str {" " str "=" value} [" " value | " [" {node} "]"] ")", attributes sorted by key,
// str = "s:" hex, bytes = "b:" hex, JID = "j:" hex(user) "/" hex(server) "/" device "/" integrator.
// The attribute order inside a frame follows Go's map iteration and changes from run to run.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"strings"

	wabin "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/binary/token"
	"go.mau.fi/whatsmeow/types"
)

type attrs = wabin.Attrs
type node = wabin.Node

func dumpValue(out *strings.Builder, v any) {
	switch t := v.(type) {
	case string:
		fmt.Fprintf(out, "s:%x", t)
	case []byte:
		fmt.Fprintf(out, "b:%x", t)
	case types.JID:
		fmt.Fprintf(out, "j:%x/%x/%d/%d", t.User, t.Server, t.Device, t.Integrator)
	default:
		panic(fmt.Sprintf("unexpected value %T", v))
	}
}

func dump(out *strings.Builder, n *node) {
	out.WriteByte('(')
	dumpValue(out, n.Tag)
	keys := make([]string, 0, len(n.Attrs))
	for k := range n.Attrs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.WriteByte(' ')
		dumpValue(out, k)
		out.WriteByte('=')
		dumpValue(out, n.Attrs[k])
	}
	switch c := n.Content.(type) {
	case nil:
	case []node:
		out.WriteString(" [")
		for i := range c {
			dump(out, &c[i])
		}
		out.WriteByte(']')
	default:
		out.WriteByte(' ')
		dumpValue(out, c)
	}
	out.WriteByte(')')
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

func jid(user, server string, device uint16) types.JID {
	return types.JID{User: user, Server: server, Device: device}
}

func main() {
	var v []node
	add := func(n ...node) { v = append(v, n...) }
	// plain structure, single-byte tokens, every dictionary
	add(node{Tag: "iq"})
	add(node{Tag: "iq", Attrs: attrs{"type": "get", "xmlns": "urn:xmpp:ping", "to": types.ServerJID}})
	for d := range token.DoubleByteTokens {
		add(node{Tag: token.DoubleByteTokens[d][0], Attrs: attrs{"id": token.DoubleByteTokens[d][255]}, Content: token.DoubleByteTokens[d][128]})
	}
	add(node{Tag: token.SingleByteTokens[1], Content: token.SingleByteTokens[len(token.SingleByteTokens)-1]})
	// packed strings: even, odd, all symbols, longest packed and first unpacked length
	for _, s := range []string{"5", "42", "491701234567", "49170123456", "1.5-2", "-.-.", "0A1B2C", "ABC", "F",
		"DEADBEEF0123456789", strings.Repeat("7", 127), strings.Repeat("7", 128), strings.Repeat("B", 127), strings.Repeat("B", 128)} {
		add(node{Tag: "message", Attrs: attrs{"id": s}, Content: s})
	}
	// raw strings and byte content
	for _, s := range []string{"md", "abc", "Hello World", "Grüße \x00 ok", strings.Repeat("x", 255), strings.Repeat("x", 256)} {
		add(node{Tag: "message", Attrs: attrs{"id": s}, Content: s})
	}
	for _, n := range []int{0, 1, 32, 255, 256, 5000} {
		add(node{Tag: "enc", Content: pattern(n)})
	}
	add(node{Tag: "custom-tag-not-in-dictionary", Attrs: attrs{"custom-key": "custom value"}})
	// JIDs
	for _, j := range []types.JID{
		jid("491701234567", types.DefaultUserServer, 0), jid("", types.DefaultUserServer, 0), jid("", types.GroupServer, 0),
		jid("120363012345678901", types.GroupServer, 0), jid("49170-1612345678", types.GroupServer, 0),
		jid("status", types.BroadcastServer, 0), jid("0", types.LegacyUserServer, 0), jid("123456789012345", types.HiddenUserServer, 0),
		jid("123456789012345", types.NewsletterServer, 0),
		jid("491701234567", types.DefaultUserServer, 1), jid("491701234567", types.DefaultUserServer, 255),
		jid("123456789012345", types.HiddenUserServer, 99), jid("491701234567", types.HostedServer, 0),
		jid("491701234567", types.HostedServer, 99), jid("123456789012345", types.HostedLIDServer, 5),
		jid("100012345678901", types.MessengerServer, 0), jid("100012345678901", types.MessengerServer, 4660),
		{User: "12345678", Server: types.InteropServer, Device: 3, Integrator: 4660},
	} {
		add(node{Tag: "receipt", Attrs: attrs{"from": j}, Content: j})
	}
	// lists: empty, nested, 255/256 children, node list header past 255 elements
	add(node{Tag: "list", Content: []node{}})
	add(node{Tag: "iq", Content: []node{{Tag: "list", Content: []node{{Tag: "item", Attrs: attrs{"jid": jid("1", types.DefaultUserServer, 0)}, Content: []node{{Tag: "devices"}}}}}}})
	for _, n := range []int{255, 256, 300} {
		kids := make([]node, n)
		for i := range kids {
			kids[i] = node{Tag: "item", Attrs: attrs{"id": fmt.Sprint(i)}}
		}
		add(node{Tag: "list", Content: kids})
	}
	for _, n := range []int{127, 128, 140} {
		a := attrs{}
		for i := range n {
			a[fmt.Sprintf("k%d", i)] = fmt.Sprint(i)
		}
		add(node{Tag: "config", Attrs: a, Content: []byte{1}})
	}

	var out bytes.Buffer
	put := func(b []byte) {
		binary.Write(&out, binary.BigEndian, uint32(len(b)))
		out.Write(b)
	}
	for _, n := range v {
		frame, err := wabin.Marshal(n)
		if err != nil {
			panic(err)
		}
		back, err := wabin.Unmarshal(frame[1:])
		if err != nil {
			panic(fmt.Sprintf("%s: %v", n.Tag, err))
		}
		var s strings.Builder
		dump(&s, back)
		put(frame)
		put([]byte(s.String()))
	}
	os.Stdout.Write(out.Bytes())
	fmt.Fprintf(os.Stderr, "wabvectors: %d vectors, %d bytes\n", len(v), out.Len())
}

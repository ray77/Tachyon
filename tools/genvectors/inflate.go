package main

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// inflate vectors: "<name> <hex zlib stream> <hex plain>" per line (plain "-" when empty); stored, fixed-only
// (HuffmanOnly) and dynamic blocks at several levels, texts and random bytes, plus a WA-like binary node blob.
func genInflate() {
	type in struct {
		name string
		data []byte
	}
	rnd := func(n int) []byte { b := make([]byte, n); rand.Read(b); return b }
	text := strings.Repeat("WhatsApp fuer den Amiga 500 - Tachyon. Freistehendes C, 68000, 7 MHz. ", 60)
	stanza := []byte("\x00\xf8\x0f\x4c\x16\x0a\xfc\x0a1764300000" + strings.Repeat("\x01\x02\x03abcabcabcabd", 40))
	inputs := []in{
		{"empty", nil},
		{"one", []byte("a")},
		{"short", []byte("hello hello hello hello")},
		{"text", []byte(text)},
		{"stanza", stanza},
		{"zeros", make([]byte, 3000)},
		{"random200", rnd(200)},
		{"random4k", rnd(4096)},
		{"mixed", append(append([]byte(text[:500]), rnd(700)...), []byte(text[:900])...)},
		{"long12k", []byte(strings.Repeat(text, 3))},
	}
	levels := []struct {
		name string
		lvl  int
	}{{"stored", zlib.NoCompression}, {"huff", zlib.HuffmanOnly}, {"fast", zlib.BestSpeed}, {"default", zlib.DefaultCompression}, {"best", zlib.BestCompression}}
	for _, i := range inputs {
		for _, l := range levels {
			if len(i.data) > 2000 && l.name != "default" && l.name != "stored" {
				continue // keep the vector file small: big inputs only stored + dynamic
			}
			if len(i.data) > 6000 && l.name == "stored" {
				continue
			}
			var buf bytes.Buffer
			w, err := zlib.NewWriterLevel(&buf, l.lvl)
			if err != nil {
				panic(err)
			}
			w.Write(i.data)
			w.Close()
			plain := "-"
			if len(i.data) > 0 {
				plain = hex.EncodeToString(i.data)
			}
			fmt.Printf("%s-%s %s %s\n", i.name, l.name, hex.EncodeToString(buf.Bytes()), plain)
		}
	}
	// a stream with a non-final stored block followed by a final fixed block (flush in between)
	{
		var buf bytes.Buffer
		w, _ := zlib.NewWriterLevel(&buf, flate.BestSpeed)
		w.Write([]byte("first part, flushed; "))
		w.Flush()
		w.Write([]byte("second part second part second part."))
		w.Close()
		fmt.Printf("multiblock %s %s\n", hex.EncodeToString(buf.Bytes()), hex.EncodeToString([]byte("first part, flushed; second part second part second part.")))
	}
	_ = os.Stdout
}

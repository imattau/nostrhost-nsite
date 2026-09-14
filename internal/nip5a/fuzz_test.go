package nip5a

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

// deterministicHexKeys generates a spread of 32-byte values to drive the
// codec property tests (not random, so the tests are reproducible).
func deterministicHexKeys(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		b := big.NewInt(int64(i*0x9e3779b1 + 1))
		var buf [32]byte
		b.FillBytes(buf[:])
		out = append(out, hex.EncodeToString(buf[:]))
	}
	return out
}

func TestBase36CodecProperty(t *testing.T) {
	for _, hexv := range deterministicHexKeys(64) {
		enc, err := Base36Encode32(hexv)
		if err != nil {
			t.Fatalf("encode %s: %v", hexv, err)
		}
		if len(enc) != 50 {
			t.Fatalf("encode %s: %d chars, want 50", hexv, len(enc))
		}
		dec, err := Base36Decode50(enc)
		if err != nil {
			t.Fatalf("decode %s: %v", enc, err)
		}
		if dec != hexv {
			t.Fatalf("roundtrip %s -> %s", hexv, dec)
		}
	}
}

// TestLabelRoundtripProperty checks encode -> decode round-trips for all
// three site forms over many keys and identifiers.
func TestLabelRoundtripProperty(t *testing.T) {
	for _, pk := range deterministicHexKeys(48) {
		npub, err := NPub(pk)
		if err != nil {
			t.Fatal(err)
		}
		if st, id, _, ok := DecodeLabel(npub); !ok || st != SiteRoot || id != pk {
			t.Fatalf("root roundtrip %s: got %v %q ok=%v", pk, st, id, ok)
		}

		for _, d := range []string{"a", "blog", "my-site", strings.Repeat("x", 13)} {
			named, err := NamedLabel(pk, d)
			if err != nil {
				t.Fatal(err)
			}
			if st, id, gotD, ok := DecodeLabel(named); !ok || st != SiteNamed || id != pk || gotD != d {
				t.Fatalf("named roundtrip %s/%s: got %v %q %q ok=%v", pk, d, st, id, gotD, ok)
			}
		}

		snap, err := SnapshotLabel(pk)
		if err != nil {
			t.Fatal(err)
		}
		if st, id, _, ok := DecodeLabel(snap); !ok || st != SiteSnapshot || id != pk {
			t.Fatalf("snapshot roundtrip %s: got %v %q ok=%v", pk, st, id, ok)
		}
	}
}

// FuzzDecodeLabel guarantees the host-label parser never panics and never
// returns ok=true for a string outside the DNS label length bound — a hostile
// Host header must always resolve to a bounded outcome.
func FuzzDecodeLabel(f *testing.F) {
	f.Add("npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
	f.Add("v" + strings.Repeat("0", 50))
	f.Add(strings.Repeat("a", 63))
	f.Add(strings.Repeat("a", 64))
	f.Add("")
	f.Add("npub1%2f")
	f.Fuzz(func(t *testing.T, label string) {
		st, hexID, d, ok := DecodeLabel(label)
		if !ok {
			return
		}
		if len(label) > LabelMaxLen {
			t.Fatalf("ok=true for %d-char label (max %d)", len(label), LabelMaxLen)
		}
		if len(hexID) != 64 {
			t.Fatalf("ok=true but hexID %q is not 64 chars", hexID)
		}
		if st == SiteNamed && !IsValidD(d) {
			t.Fatalf("named label decoded with invalid d %q", d)
		}
		_ = fmt.Sprintf("%v %s %s", st, hexID, d)
	})
}

// FuzzBase36Decode50 guarantees the decoder never panics on arbitrary 50-char
// input and only accepts lowercase base36 digits.
func FuzzBase36Decode50(f *testing.F) {
	f.Add(strings.Repeat("0", 50))
	f.Add(strings.Repeat("z", 50))
	f.Add(strings.Repeat("Z", 50))
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		_, err := Base36Decode50(s)
		if err != nil {
			return
		}
		if len(s) != 50 {
			t.Fatalf("decoded non-50-char input %q", s)
		}
		if !reB36Fifty.MatchString(s) {
			t.Fatalf("decoded input %q that fails the base36 grammar", s)
		}
	})
}

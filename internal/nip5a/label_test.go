package nip5a

import (
	"strings"
	"testing"
)

const testPubkey = "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"

func TestBase36Roundtrip(t *testing.T) {
	values := []string{
		testPubkey,
		strings.Repeat("0", 64),
		strings.Repeat("f", 64),
		"0000000000000000000000000000000000000000000000000000000000000001",
	}
	for _, hexv := range values {
		enc, err := Base36Encode32(hexv)
		if err != nil {
			t.Fatalf("encode %s: %v", hexv, err)
		}
		if len(enc) != 50 {
			t.Fatalf("encode %s: got %d chars, want 50", hexv, len(enc))
		}
		dec, err := Base36Decode50(enc)
		if err != nil {
			t.Fatalf("decode %s: %v", enc, err)
		}
		if dec != hexv {
			t.Fatalf("roundtrip: %s != %s", dec, hexv)
		}
	}
}

func TestNamedLabelBounds(t *testing.T) {
	if l, _ := Base36Encode32(testPubkey); len(l) != 50 {
		t.Fatalf("pubkeyB36 must be 50 chars, got %d", len(l))
	}
	short, _ := NamedLabel(testPubkey, "a")
	if len(short) != 51 {
		t.Fatalf("label with 1-char d must be 51, got %d", len(short))
	}
	max, _ := NamedLabel(testPubkey, strings.Repeat("a", 13))
	if len(max) != LabelMaxLen {
		t.Fatalf("label with 13-char d must be %d, got %d", LabelMaxLen, len(max))
	}
	if !IsValidD(strings.Repeat("a", 13)) {
		t.Error("13-char d must be valid")
	}
	for _, bad := range []string{strings.Repeat("a", 14), "blog-", "Blog"} {
		if IsValidD(bad) {
			t.Errorf("d %q must be invalid", bad)
		}
	}
}

func TestDecodeLabelForms(t *testing.T) {
	npub, err := NPub(testPubkey)
	if err != nil {
		t.Fatal(err)
	}
	if len(npub) != LabelMaxLen {
		t.Fatalf("root npub must be %d chars, got %d", LabelMaxLen, len(npub))
	}
	if st, hexID, _, ok := DecodeLabel(npub); !ok || st != SiteRoot || hexID != testPubkey {
		t.Fatalf("decode npub: got %v %q %v", st, hexID, ok)
	}

	named, _ := NamedLabel(testPubkey, "blog")
	if st, hexID, d, ok := DecodeLabel(named); !ok || st != SiteNamed || hexID != testPubkey || d != "blog" {
		t.Fatalf("decode named: got %v %q %q %v", st, hexID, d, ok)
	}

	snap, _ := SnapshotLabel(strings.Repeat("ab", 32))
	if st, hexID, _, ok := DecodeLabel(snap); !ok || st != SiteSnapshot || hexID != strings.Repeat("ab", 32) {
		t.Fatalf("decode snapshot: got %v %q %v", st, hexID, ok)
	}
}

func TestDecodeLabelGarbage(t *testing.T) {
	for _, label := range []string{
		"",
		"not-a-label",
		"npub1tampered",
		"v" + strings.Repeat("0", 49), // 49 chars, not 50
		strings.Repeat("b", 50) + "-", // d ends with '-'
		strings.Repeat("a", 64),       // over the DNS label limit
	} {
		if st, _, _, ok := DecodeLabel(label); ok {
			t.Errorf("label %q should not decode, got %v", label, st)
		}
	}
}

func TestCanonicalSiteURL(t *testing.T) {
	label, _ := NamedLabel(testPubkey, "blog")
	got := CanonicalSiteURL(label, "sites.example.org")
	want := label + ".sites.example.org"
	if got != want {
		t.Fatalf("canonical: got %q want %q", got, want)
	}
}

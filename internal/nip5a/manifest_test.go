package nip5a

import (
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

const testSK = "3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d"

func sign(t *testing.T, kind int, tags nostr.Tags, sk string) *nostr.Event {
	t.Helper()
	ev := &nostr.Event{CreatedAt: nostr.Now(), Kind: kind, Tags: tags, Content: ""}
	if err := ev.Sign(sk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return ev
}

func TestAggregateHashOrderIndependence(t *testing.T) {
	a := []Path{{Path: "/index.html", Hash: "a" + strings.Repeat("1", 63)}, {Path: "/about.html", Hash: "b" + strings.Repeat("2", 63)}}
	b := []Path{{Path: "/about.html", Hash: "b" + strings.Repeat("2", 63)}, {Path: "/index.html", Hash: "a" + strings.Repeat("1", 63)}}
	if AggregateHash(a) != AggregateHash(b) {
		t.Fatal("aggregate hash must be order-independent")
	}
}

func TestAggregateHashKnownAnswer(t *testing.T) {
	// NIP-5A "Aggregate Hash" example inputs, sorted ascending by line.
	got := AggregateHash([]Path{
		{Path: "/favicon.ico", Hash: "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"},
		{Path: "/index.html", Hash: "186ea5fd14e88fd1ac49351759e7ab906fa94892002b60bf7f5a428f28ca1c99"},
	})
	if want := "c2ff582b672a4c689c5e1753528f03dd31b95ec1fdcc3d82d25e7d91e8769638"; got != want {
		t.Fatalf("aggregate: got %q want %q", got, want)
	}
}

func TestBadKind(t *testing.T) {
	ev := sign(t, 99999, nostr.Tags{{"path", "/index.html", strings.Repeat("a", 64)}}, testSK)
	v := Validate(ev, Options{})
	if v.Valid {
		t.Fatal("kind 99999 must be invalid")
	}
	if !contains(v.Errors, "bad_kind") {
		t.Fatalf("want bad_kind in %v", v.Errors)
	}
}

func TestForbiddenSignerGuard(t *testing.T) {
	hostPk, err := nostr.GetPublicKey(strings.Repeat("deadbeef", 8))
	if err != nil {
		t.Fatal(err)
	}
	ev := sign(t, KindRoot, nostr.Tags{{"path", "/index.html", strings.Repeat("a", 64)}}, strings.Repeat("deadbeef", 8))
	if got := Validate(ev, Options{}); !got.Valid {
		t.Fatalf("without the guard the same event must be valid, got %v", got.Errors)
	}
	got := Validate(ev, Options{ForbiddenPubkeys: map[string]struct{}{hostPk: {}}})
	if got.Valid || !contains(got.Errors, "forbidden_signer") {
		t.Fatalf("guard must flag forbidden_signer, got %v", got.Errors)
	}
}

func TestSnapshotRequiresXAndA(t *testing.T) {
	tags := nostr.Tags{
		{"a", "35128:" + strings.Repeat("ab", 32) + ":blog"},
		{"path", "/index.html", strings.Repeat("a", 64)},
	}
	ev := sign(t, KindSnapshot, tags, testSK)
	v := Validate(ev, Options{})
	if v.Valid || !contains(v.Errors, "missing_aggregate_x") {
		t.Fatalf("snapshot without x must be invalid, got %v", v.Errors)
	}
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}

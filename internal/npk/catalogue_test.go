package npk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

func releaseEventAt(createdAt nostr.Timestamp, name, version, x string) *nostr.Event {
	ev := releaseEvent(name, version, x)
	ev.CreatedAt = createdAt
	return ev
}

func TestLoadCatalogueMissingFileIsNil(t *testing.T) {
	cat, err := LoadCatalogue(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing catalogue must not error: %v", err)
	}
	if cat != nil {
		t.Fatalf("missing catalogue must yield nil, got %+v", cat)
	}
}

func TestLoadCatalogueParseError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalogue.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCatalogue(path); err == nil {
		t.Fatal("malformed catalogue must error")
	}
}

func writeCatalogue(t *testing.T, releases, revocations []nostr.Event) *Catalogue {
	t.Helper()
	cat := &Catalogue{CreatedAt: uint64(time.Now().Unix()), Releases: releases, Revocations: revocations}
	body, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "catalogue.json")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCatalogue(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return loaded
}

func TestCatalogueNewestPicksNewestValidRelease(t *testing.T) {
	pubkey := "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
	older := releaseEventAt(1_000_000, "root", "1.0.0", "aa"+strings.Repeat("bb", 31))
	older.PubKey = pubkey
	newer := releaseEventAt(1_003_600, "root", "2.0.0", "cc"+strings.Repeat("dd", 31))
	newer.PubKey = pubkey
	otherSite := releaseEventAt(1_007_200, "blog", "1.0.0", "ee"+strings.Repeat("ff", 31))
	otherSite.PubKey = pubkey

	cat := writeCatalogue(t, []nostr.Event{*older, *newer, *otherSite}, nil)

	rel := cat.Newest(pubkey, "root")
	if rel == nil {
		t.Fatal("expected a release for root")
	}
	if rel.Version != "2.0.0" || rel.EventID != newer.ID {
		t.Fatalf("expected newest root release, got %+v", rel)
	}
	if got := cat.Newest(pubkey, "blog"); got == nil {
		t.Fatal("blog release must resolve")
	}
	if got := cat.Newest(pubkey, "unknown"); got != nil {
		t.Fatalf("unknown name must be nil, got %+v", got)
	}
	if got := cat.Newest("deadbeef", "root"); got != nil {
		t.Fatalf("unknown publisher must be nil, got %+v", got)
	}
}

func TestCatalogueNewestExcludesRevoked(t *testing.T) {
	pubkey := "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
	rel := releaseEventAt(1_000_000, "root", "1.0.0", "aa"+strings.Repeat("bb", 31))
	rel.PubKey = pubkey
	rev := &nostr.Event{Kind: 9901, PubKey: pubkey, Tags: nostr.Tags{{"e", rel.ID}}}
	cat := writeCatalogue(t, []nostr.Event{*rel}, []nostr.Event{*rev})

	if got := cat.Newest(pubkey, "root"); got != nil {
		t.Fatalf("revoked release must be excluded, got %+v", got)
	}
}

func TestCatalogueNewestIgnoresForeignRevocation(t *testing.T) {
	pubkey := "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
	other := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	rel := releaseEventAt(1_000_000, "root", "1.0.0", "aa"+strings.Repeat("bb", 31))
	rel.PubKey = pubkey
	// Revocation signed by a different publisher must not suppress the release.
	rev := &nostr.Event{Kind: 9901, PubKey: other, Tags: nostr.Tags{{"e", rel.ID}}}
	cat := writeCatalogue(t, []nostr.Event{*rel}, []nostr.Event{*rev})

	if got := cat.Newest(pubkey, "root"); got == nil {
		t.Fatal("a foreign revocation must not suppress the release")
	}
}

func TestCatalogueNewestSkipsNonReleaseEvents(t *testing.T) {
	pubkey := "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
	rel := releaseEventAt(1_000_000, "root", "1.0.0", "aa"+strings.Repeat("bb", 31))
	rel.PubKey = pubkey
	note := &nostr.Event{Kind: 1, PubKey: pubkey, CreatedAt: rel.CreatedAt + 3600, Tags: nostr.Tags{{"name", "root"}}}
	cat := writeCatalogue(t, []nostr.Event{*rel, *note}, nil)

	if got := cat.Newest(pubkey, "root"); got == nil || got.Version != "1.0.0" {
		t.Fatalf("non-release events must be ignored, got %+v", got)
	}
}

func TestCatalogueNilReceiver(t *testing.T) {
	var cat *Catalogue
	if got := cat.Newest("pub", "root"); got != nil {
		t.Fatalf("nil catalogue must yield nil, got %+v", got)
	}
}
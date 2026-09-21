package resolve

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/imattau/nostrhost-nsite/internal/cache"
	"github.com/imattau/nostrhost-nsite/internal/nip5a"
	"github.com/imattau/nostrhost-nsite/internal/npk"
)

func TestKeyAndFilter(t *testing.T) {
	key, f, err := keyAndFilter(nip5a.SiteRoot, "aa", "", "")
	if err != nil || key != "root:aa" || f.Kinds[0] != nip5a.KindRoot {
		t.Fatalf("root: %s %v %v", key, f, err)
	}
	key, f, err = keyAndFilter(nip5a.SiteNamed, "aa", "blog", "")
	if err != nil || key != "named:aa:blog" || f.Tags["d"][0] != "blog" {
		t.Fatalf("named: %s %v %v", key, f, err)
	}
	if _, _, err := keyAndFilter(nip5a.SiteNamed, "aa", "", ""); err == nil {
		t.Fatal("named without d must error")
	}
	key, f, err = keyAndFilter(nip5a.SiteSnapshot, "", "", "id123")
	if err != nil || key != "snap:id123" || f.IDs[0] != "id123" {
		t.Fatalf("snapshot: %s %v %v", key, f, err)
	}
	if _, _, err := keyAndFilter(nip5a.SiteSnapshot, "", "", ""); err == nil {
		t.Fatal("snapshot without id must error")
	}
}

func TestManifestCacheShortCircuit(t *testing.T) {
	ctx := context.Background()
	pk := "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
	mc := cache.NewManifestCache(time.Duration(3600)*time.Second, time.Duration(60)*time.Second)
	ev := &nostr.Event{Kind: nip5a.KindRoot, PubKey: pk}
	mc.Put("root:"+pk, ev)
	r := New([]string{}, mc, nil, 5000) // no relays: cache must be the only path
	got, err := r.Manifest(ctx, nip5a.SiteRoot, pk, "", "")
	if err != nil || got == nil || got.Kind != nip5a.KindRoot {
		t.Fatalf("cache short-circuit failed: %v %v", got, err)
	}
	mc.PutNegative("root:unknown")
	if got, err := r.Manifest(ctx, nip5a.SiteRoot, "unknown", "", ""); err != nil || got != nil {
		t.Fatalf("negative short-circuit failed: %v %v", got, err)
	}
}

func TestReleaseCacheShortCircuit(t *testing.T) {
	ctx := context.Background()
	pk := "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
	mc := cache.NewManifestCache(time.Hour, time.Minute)
	rel := &npk.Release{Publisher: pk, Name: "root", Version: "1.0.0", SHA256: "ab" + strings.Repeat("cd", 31)}
	mc.Put("release:"+pk+":root", rel)
	r := New([]string{}, mc, nil, 5000) // no relays: cache must be the only path
	got, err := r.Release(ctx, pk, "root")
	if err != nil || got == nil || got.SHA256 != rel.SHA256 {
		t.Fatalf("release cache short-circuit failed: %+v %v", got, err)
	}
	mc.PutNegative("release:" + pk + ":missing")
	if got, err := r.Release(ctx, pk, "missing"); err != nil || got != nil {
		t.Fatalf("negative short-circuit failed: %+v %v", got, err)
	}
}

func TestReleaseFromCatalogueWithoutRelays(t *testing.T) {
	ctx := context.Background()
	pk := "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
	cat := &npk.Catalogue{
		Releases: []nostr.Event{
			{Kind: 9900, PubKey: pk, CreatedAt: 1_000_000, Tags: nostr.Tags{
				{"d", "root/1.0.0/x86_64"}, {"v", "1"}, {"name", "root"},
				{"version", "1.0.0"}, {"os", "linux"}, {"arch", "x86_64"},
				{"format", "npk"}, {"x", "ab" + strings.Repeat("cd", 31)},
			}},
		},
	}
	mc := cache.NewManifestCache(time.Hour, time.Minute)
	// No relays: the catalogue must be the only source of the release.
	r := New([]string{}, mc, nil, 5000, cat)
	got, err := r.Release(ctx, pk, "root")
	if err != nil || got == nil || got.Version != "1.0.0" {
		t.Fatalf("catalogue-backed release failed: %+v %v", got, err)
	}
	// A miss falls through to relays (none configured) and caches negatively.
	if got, err := r.Release(ctx, pk, "missing"); err != nil || got != nil {
		t.Fatalf("catalogue miss must fall through: %+v %v", got, err)
	}
	if !mc.Negative("release:" + pk + ":missing") {
		t.Fatal("catalogue miss must cache negatively")
	}
}

func TestReleaseIgnoresNilCatalogue(t *testing.T) {
	ctx := context.Background()
	pk := "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
	mc := cache.NewManifestCache(time.Hour, time.Minute)
	// Explicit nil catalogue (default behaviour): no relays, no release.
	r := New([]string{}, mc, nil, 5000, (*npk.Catalogue)(nil))
	if got, err := r.Release(ctx, pk, "root"); err != nil || got != nil {
		t.Fatalf("nil catalogue must behave like the relay-only path: %+v %v", got, err)
	}
}

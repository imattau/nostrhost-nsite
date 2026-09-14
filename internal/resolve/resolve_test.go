package resolve

import (
	"context"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/imattau/nostrhost-nsite/internal/cache"
	"github.com/imattau/nostrhost-nsite/internal/nip5a"
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

// Package resolve fetches and validates NIP-5A site manifests from the
// configured public relays. Results are cached (positive and negative); only
// validated manifests are ever returned or cached.
package resolve

import (
	"context"
	"fmt"

	"github.com/nbd-wtf/go-nostr"

	"github.com/imattau/nostrhost-nsite/internal/cache"
	"github.com/imattau/nostrhost-nsite/internal/nip5a"
	"github.com/imattau/nostrhost-nsite/internal/npk"
)

// Resolver resolves manifests and author metadata from public relays.
type Resolver struct {
	relays    []string
	mcache    *cache.ManifestCache
	forbidden map[string]struct{}
	maxPaths  int
	// catalogue is the optional local npack catalogue (npack refresh). When
	// set, release resolution consults it before the relays; nil keeps the
	// relay-only behaviour.
	catalogue *npk.Catalogue
}

func New(relays []string, mcache *cache.ManifestCache, forbidden map[string]struct{}, maxPaths int, catalogue ...*npk.Catalogue) *Resolver {
	var cat *npk.Catalogue
	if len(catalogue) > 0 {
		cat = catalogue[0]
	}
	return &Resolver{relays: relays, mcache: mcache, forbidden: forbidden, maxPaths: maxPaths, catalogue: cat}
}

// Relays exposes the configured lookup set (for diagnostics/tests).
func (r *Resolver) Relays() []string { return r.relays }

// Manifest returns the validated manifest for a site, or nil when none is
// found (including when the only matching events fail validation). For
// replaceable/addressable kinds the newest valid event wins; older or invalid
// manifests are ignored.
func (r *Resolver) Manifest(ctx context.Context, siteType nip5a.SiteType, pubkey, d, id string) (*nostr.Event, error) {
	key, filter, err := keyAndFilter(siteType, pubkey, d, id)
	if err != nil {
		return nil, err
	}
	if cached, ok := r.mcache.Get(key); ok {
		if ev, isEvent := cached.(*nostr.Event); isEvent {
			return ev, nil
		}
		return nil, nil
	}
	if r.mcache.Negative(key) {
		return nil, nil
	}

	best := newestEvent(ctx, r.relays, filter, true)
	if best == nil {
		r.mcache.PutNegative(key)
		return nil, nil
	}

	v := nip5a.Validate(best, nip5a.Options{ForbiddenPubkeys: r.forbidden, MaxPaths: r.maxPaths})
	if !v.Valid {
		r.mcache.PutNegative(key)
		return nil, nil
	}
	r.mcache.Put(key, best)
	return best, nil
}

// BlossomServers returns the author's kind 10063 (BUD-03) server list from
// the lookup relays, in order. The newest event wins.
func (r *Resolver) BlossomServers(ctx context.Context, pubkey string) []string {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	best := newestEvent(ctx, r.relays, nostr.Filter{Kinds: []int{10063}, Authors: []string{pubkey}}, false)
	if best == nil {
		return nil
	}
	var servers []string
	for _, t := range best.Tags {
		if len(t) >= 2 && t[0] == "server" {
			servers = append(servers, t[1])
		}
	}
	return servers
}

// Release resolves the newest valid kind-9900 release of publisher/name. When
// a local npack catalogue is configured it is consulted first (no relay round
// trip); on a miss the lookup relays are queried, with the same positive/
// negative cache as manifests. Returns (nil, nil) when no valid, unrevoked
// release is found.
func (r *Resolver) Release(ctx context.Context, publisher, name string) (*npk.Release, error) {
	key := "release:" + publisher + ":" + name
	if cached, ok := r.mcache.Get(key); ok {
		if rel, isRel := cached.(*npk.Release); isRel {
			return rel, nil
		}
		return nil, nil
	}
	if r.mcache.Negative(key) {
		return nil, nil
	}
	if r.catalogue != nil {
		if rel := r.catalogue.Newest(publisher, name); rel != nil {
			r.mcache.Put(key, rel)
			return rel, nil
		}
	}
	rel, err := npk.NewestRelease(ctx, r.relays, publisher, name)
	if err != nil {
		return nil, err
	}
	if rel == nil {
		r.mcache.PutNegative(key)
		return nil, nil
	}
	r.mcache.Put(key, rel)
	return rel, nil
}

// newestEvent subscribes to relays with the given filter and returns the
// event with the highest CreatedAt seen before EOSE, or nil if none matched.
// When dedupeByID is true, repeated deliveries of the same event ID are
// skipped before the newest-wins comparison.
func newestEvent(ctx context.Context, relays []string, filter nostr.Filter, dedupeByID bool) *nostr.Event {
	pool := nostr.NewSimplePool(ctx)
	defer pool.Close("done")

	var seen map[string]struct{}
	if dedupeByID {
		seen = map[string]struct{}{}
	}

	best := (*nostr.Event)(nil)
	for hit := range pool.SubManyEose(ctx, relays, nostr.Filters{filter}) {
		if hit.Event == nil {
			continue
		}
		if dedupeByID {
			if _, dup := seen[hit.Event.ID]; dup {
				continue
			}
			seen[hit.Event.ID] = struct{}{}
		}
		if best != nil && hit.Event.CreatedAt <= best.CreatedAt {
			continue
		}
		best = hit.Event
	}
	return best
}

func keyAndFilter(siteType nip5a.SiteType, pubkey, d, id string) (string, nostr.Filter, error) {
	switch siteType {
	case nip5a.SiteRoot:
		return "root:" + pubkey, nostr.Filter{Kinds: []int{nip5a.KindRoot}, Authors: []string{pubkey}}, nil
	case nip5a.SiteNamed:
		if d == "" {
			return "", nostr.Filter{}, fmt.Errorf("named site requires a d identifier")
		}
		return "named:" + pubkey + ":" + d, nostr.Filter{Kinds: []int{nip5a.KindNamed}, Authors: []string{pubkey}, Tags: nostr.TagMap{"d": []string{d}}}, nil
	case nip5a.SiteSnapshot:
		if id == "" {
			return "", nostr.Filter{}, fmt.Errorf("snapshot requires an event id")
		}
		return "snap:" + id, nostr.Filter{Kinds: []int{nip5a.KindSnapshot}, IDs: []string{id}}, nil
	default:
		return "", nostr.Filter{}, fmt.Errorf("unknown site type %q", siteType)
	}
}

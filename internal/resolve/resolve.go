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
)

// Resolver resolves manifests and author metadata from public relays.
type Resolver struct {
	relays    []string
	mcache    *cache.ManifestCache
	forbidden map[string]struct{}
	maxPaths  int
}

func New(relays []string, mcache *cache.ManifestCache, forbidden map[string]struct{}, maxPaths int) *Resolver {
	return &Resolver{relays: relays, mcache: mcache, forbidden: forbidden, maxPaths: maxPaths}
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

	pool := nostr.NewSimplePool(ctx)
	defer pool.Close("done")

	best := (*nostr.Event)(nil)
	seen := map[string]struct{}{}
	for hit := range pool.SubManyEose(ctx, r.relays, nostr.Filters{filter}) {
		if hit.Event == nil {
			continue
		}
		if _, dup := seen[hit.Event.ID]; dup {
			continue
		}
		seen[hit.Event.ID] = struct{}{}
		if best != nil && hit.Event.CreatedAt <= best.CreatedAt {
			continue
		}
		best = hit.Event
	}
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
	pool := nostr.NewSimplePool(ctx)
	defer pool.Close("done")

	best := (*nostr.Event)(nil)
	for hit := range pool.SubManyEose(ctx, r.relays, nostr.Filters{{Kinds: []int{10063}, Authors: []string{pubkey}}}) {
		if hit.Event == nil {
			continue
		}
		if best == nil || hit.Event.CreatedAt > best.CreatedAt {
			best = hit.Event
		}
	}
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

// Local npack catalogue support: the gateway can resolve kind-9900 releases
// from the durable catalogue.json that `npack refresh` builds from relays,
// instead of querying relays on every release miss. The catalogue is a plain
// snapshot of release (kind-9900) and revocation (kind-9901) events, so the
// resolution rules here mirror NewestRelease exactly -- the file is just a
// cheaper, operator-refreshed source of the same events.
package npk

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/nbd-wtf/go-nostr"
)

// Catalogue is the on-disk shape of `npack refresh`'s catalogue.json: a
// snapshot of signed release and revocation events. Events keep their original
// author and signature; npack verifies them while refreshing, so the file only
// ever holds valid, author-signed events.
type Catalogue struct {
	CreatedAt   uint64        `json:"created_at"`
	Releases    []nostr.Event `json:"releases"`
	Revocations []nostr.Event `json:"revocations"`
}

// LoadCatalogue reads a refreshed npack catalogue. A missing file is not an
// error: it returns (nil, nil) so the gateway silently falls back to relays
// until the operator has run `npack refresh`.
func LoadCatalogue(path string) (*Catalogue, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var c Catalogue
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// Newest returns the newest valid kind-9900 release of publisher/name in the
// catalogue, or nil when the catalogue holds none. A release is valid when it
// carries the required x/name/version tags (the same check the relay path
// applies) and, if present, has not been revoked by a kind-9901 event from the
// same publisher. Newest wins on created_at.
func (c *Catalogue) Newest(publisher, name string) *Release {
	if c == nil {
		return nil
	}
	revoked := make(map[string]struct{})
	for _, rev := range c.Revocations {
		if rev.Kind != 9901 || rev.PubKey != publisher {
			continue
		}
		for _, t := range rev.Tags {
			if len(t) >= 2 && t[0] == "e" {
				revoked[t[1]] = struct{}{}
			}
		}
	}
	var best *nostr.Event
	for i := range c.Releases {
		ev := &c.Releases[i]
		if ev.Kind != KindRelease || ev.PubKey != publisher || releaseName(ev) != name {
			continue
		}
		if best != nil && ev.CreatedAt <= best.CreatedAt {
			continue
		}
		best = ev
	}
	if best == nil {
		return nil
	}
	rel := parseRelease(best)
	if rel == nil {
		return nil
	}
	if _, isRevoked := revoked[best.ID]; isRevoked {
		return nil
	}
	return rel
}
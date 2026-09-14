package nip5a

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

// corpusEvent mirrors the lowercase NIP-01 object form in the corpus files
// (go-nostr's Event uses easyjson, so we map explicitly).
type corpusEvent struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

func (c corpusEvent) nostrEvent() *nostr.Event {
	tags := make(nostr.Tags, 0, len(c.Tags))
	for _, t := range c.Tags {
		tags = append(tags, nostr.Tag(t))
	}
	return &nostr.Event{
		ID:        c.ID,
		PubKey:    c.PubKey,
		CreatedAt: nostr.Timestamp(c.CreatedAt),
		Kind:      c.Kind,
		Tags:      tags,
		Content:   c.Content,
		Sig:       c.Sig,
	}
}

type corpusExpect struct {
	Valid         bool     `json:"valid"`
	Errors        []string `json:"errors"`
	SiteType      string   `json:"site_type"`
	AggregateHash string   `json:"aggregate_hash"`
	Label         string   `json:"label"`
	D             string   `json:"d"`
	MaxPaths      int      `json:"max_paths"`
}

type corpusCase struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Event       corpusEvent  `json:"event"`
	Expect      corpusExpect `json:"expect"`
}

// corpusDir resolves the shared corpus. It prefers $NSITES_CORPUS, then the
// parent-repo path relative to this package; an empty string means the corpus
// is unavailable (standalone checkout) and the test skips.
func corpusDir() string {
	if d := os.Getenv("NSITES_CORPUS"); d != "" {
		return d
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}
	// internal/nip5a -> libs/nostrhost-nsite -> <repo root>
	root := filepath.Join(filepath.Dir(file), "..", "..", "..")
	d := filepath.Join(root, "tools", "tests", "nsites", "corpus")
	if _, err := os.Stat(d); err == nil {
		return d
	}
	return ""
}

func hostPubkey(t *testing.T) string {
	t.Helper()
	pk, err := nostr.GetPublicKey(strings.Repeat("deadbeef", 8))
	if err != nil {
		t.Fatalf("derive host pubkey: %v", err)
	}
	return pk
}

func TestCorpus(t *testing.T) {
	dir := corpusDir()
	if dir == "" {
		t.Skip("nsites corpus not present (set NSITES_CORPUS or check out the parent repo)")
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no corpus files in %s: %v", dir, err)
	}
	forbidden := map[string]struct{}{hostPubkey(t): {}}

	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		var c corpusCase
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		if c.Name != strings.TrimSuffix(filepath.Base(f), ".json") {
			t.Errorf("%s: name %q does not match filename", f, c.Name)
		}
		t.Run(c.Name, func(t *testing.T) {
			v := Validate(c.Event.nostrEvent(), Options{
				ForbiddenPubkeys: forbidden,
				MaxPaths:         c.Expect.MaxPaths,
			})
			if c.Expect.Valid {
				if !v.Valid {
					t.Fatalf("expected valid, got errors %v", v.Errors)
				}
			} else {
				if v.Valid {
					t.Fatalf("expected invalid (%v), got valid", c.Expect.Errors)
				}
				if got, want := sortedCopy(v.Errors), sortedCopy(c.Expect.Errors); !equal(got, want) {
					t.Fatalf("errors mismatch: got %v want %v", got, want)
				}
			}
			if c.Expect.SiteType != "" && string(v.SiteType) != c.Expect.SiteType {
				t.Errorf("site_type: got %q want %q", v.SiteType, c.Expect.SiteType)
			}
			if c.Expect.AggregateHash != "" && v.AggregateHash != c.Expect.AggregateHash {
				t.Errorf("aggregate_hash: got %q want %q", v.AggregateHash, c.Expect.AggregateHash)
			}
			if c.Expect.Label != "" && v.Label != c.Expect.Label {
				t.Errorf("label: got %q want %q", v.Label, c.Expect.Label)
			}
			if c.Expect.Valid && c.Expect.Label != "" {
				siteType, hexID, d, ok := DecodeLabel(c.Expect.Label)
				if !ok {
					t.Fatalf("expected label %q to decode", c.Expect.Label)
				}
				switch siteType {
				case SiteRoot, SiteNamed:
					if hexID != c.Event.PubKey {
						t.Errorf("decoded pubkey %q != event pubkey %q", hexID, c.Event.PubKey)
					}
					if siteType == SiteNamed && d != c.Expect.D {
						t.Errorf("decoded d %q != %q", d, c.Expect.D)
					}
				case SiteSnapshot:
					if hexID != c.Event.ID {
						t.Errorf("decoded id %q != event id %q", hexID, c.Event.ID)
					}
				}
			}
		})
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

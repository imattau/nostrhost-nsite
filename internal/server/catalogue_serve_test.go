package server

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/imattau/nostrhost-nsite/internal/blossom"
	"github.com/imattau/nostrhost-nsite/internal/cache"
	"github.com/imattau/nostrhost-nsite/internal/config"
	"github.com/imattau/nostrhost-nsite/internal/nip5a"
	"github.com/imattau/nostrhost-nsite/internal/npk"
	"github.com/imattau/nostrhost-nsite/internal/resolve"
)

// newCatalogueServer wires a server whose release resolution comes from a
// local npack catalogue (no relays, no per-request kind-9900 query): the
// manifest cache holds the site manifest, the bundle store holds the .npk,
// and the resolver reads the release from catalogue.json.
func newCatalogueServer(t *testing.T, pubkey string) *Server {
	t.Helper()
	body, sha := npkSiteFixture(t)

	event := &nostr.Event{
		PubKey:    pubkey,
		CreatedAt: nostr.Now(),
		Kind:      nip5a.KindRoot,
		Tags: nostr.Tags{
			{"path", "/index.html", h([]byte("<h1>index via npk</h1>\n"))},
			{"server", "https://blossom.invalid"},
		},
	}
	if err := event.Sign(serveSK); err != nil {
		t.Fatal(err)
	}

	release := &nostr.Event{
		PubKey:    pubkey,
		CreatedAt: nostr.Now(),
		Kind:      npk.KindRelease,
		Tags: nostr.Tags{
			{"d", "root/1.0.0/x86_64"}, {"v", "1"}, {"name", "root"},
			{"version", "1.0.0"}, {"os", "linux"}, {"arch", "x86_64"},
			{"format", "npk"}, {"x", sha},
		},
	}
	if err := release.Sign(serveSK); err != nil {
		t.Fatal(err)
	}

	cat := &npk.Catalogue{CreatedAt: uint64(time.Now().Unix()), Releases: []nostr.Event{*release}}
	catBody, err := json.Marshal(cat)
	if err != nil {
		t.Fatal(err)
	}
	catPath := filepath.Join(t.TempDir(), "catalogue.json")
	if err := os.WriteFile(catPath, catBody, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := npk.LoadCatalogue(catPath)
	if err != nil {
		t.Fatal(err)
	}

	mcache := cache.NewManifestCache(time.Hour, time.Minute)
	mcache.Put("root:"+pubkey, event)
	blobs, err := cache.NewBlobStore(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	bundles, err := npk.NewBundleStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bundles.Unpack(sha, body); err != nil {
		t.Fatal(err)
	}

	cfg := config.Defaults()
	cfg.Domain = testDomain
	cfg.Sites = []config.Site{{Pubkey: pubkey, Kind: nip5a.KindRoot, D: ""}}
	cfg.Npk.Enabled = true
	cfg.Npk.CataloguePath = catPath

	srv := New(cfg, nil)
	srv.Configure(Backends{
		// No relays at all: the catalogue is the only release source.
		Resolver: resolve.New([]string{}, mcache, nil, 5000, loaded),
		Fetcher:  blossom.New(blossom.Options{AllowHTTP: true, AllowLoopback: true}),
		Blobs:    blobs,
		Npk:      bundles,
	})
	return srv
}

func TestServeFromNpkViaCatalogue(t *testing.T) {
	pk, _ := nostr.GetPublicKey(serveSK)
	s := newCatalogueServer(t, pk)
	host := npub(t) + "." + testDomain

	rr := get(s, host, "/index.html")
	if rr.Code != http.StatusOK {
		t.Fatalf("/index.html via catalogue: got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "index via npk") {
		t.Fatalf("/index.html: unexpected body %q", rr.Body.String())
	}
}
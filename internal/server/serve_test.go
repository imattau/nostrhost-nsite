package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/imattau/nostrhost-nsite/internal/blossom"
	"github.com/imattau/nostrhost-nsite/internal/cache"
	"github.com/imattau/nostrhost-nsite/internal/config"
	"github.com/imattau/nostrhost-nsite/internal/nip5a"
	"github.com/imattau/nostrhost-nsite/internal/resolve"
)

const serveSK = "3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d"

func h(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// newServingServer wires a fully-configured server whose manifest cache is
// pre-populated so no relay is contacted.
func newServingServer(t *testing.T, pubkey string) (*Server, *httptest.Server) {
	t.Helper()

	indexBody := []byte("<h1>index</h1>\n")
	notFoundBody := []byte("<h1>missing</h1>\n")
	tamperedHash := h([]byte("will-never-be-served"))

	blobServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sha := strings.TrimPrefix(r.URL.Path, "/")
		switch sha {
		case h(indexBody):
			_, _ = w.Write(indexBody)
		case h(notFoundBody):
			_, _ = w.Write(notFoundBody)
		case tamperedHash:
			_, _ = w.Write([]byte("<h1>tampered</h1>"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(blobServer.Close)

	event := &nostr.Event{
		PubKey:    pubkey,
		CreatedAt: nostr.Now(),
		Kind:      nip5a.KindRoot,
		Tags: nostr.Tags{
			{"path", "/index.html", h(indexBody)},
			{"path", "/404.html", h(notFoundBody)},
			{"path", "/tampered.html", tamperedHash},
			{"server", blobServer.URL},
		},
		Content: "",
	}
	if err := event.Sign(serveSK); err != nil {
		t.Fatal(err)
	}

	mcache := cache.NewManifestCache(
		time.Duration(config.Defaults().Relays.ManifestTTLSeconds)*time.Second,
		time.Duration(config.Defaults().Relays.NegativeTTLSeconds)*time.Second,
	)
	mcache.Put("root:"+pubkey, event)

	blobs, err := cache.NewBlobStore(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Domain = testDomain
	cfg.Sites = []config.Site{{Pubkey: pubkey, Kind: nip5a.KindRoot, D: ""}}

	srv := New(cfg, nil)
	srv.Configure(Backends{
		Resolver: resolve.New([]string{"wss://dummy.example.org"}, mcache, nil, 5000),
		Fetcher:  blossom.New(blossom.Options{AllowHTTP: true, AllowLoopback: true}),
		Blobs:    blobs,
	})
	return srv, blobServer
}

func get(s *Server, host, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.Host = host
	rr := httptest.NewRecorder()
	s.handlePublic(rr, req)
	return rr
}

func TestServeRootIndex(t *testing.T) {
	pk, _ := nostr.GetPublicKey(serveSK)
	s, _ := newServingServer(t, pk)
	host := npub(t) + "." + testDomain

	rr := get(s, host, "/")
	if rr.Code != http.StatusOK {
		t.Fatalf("/: got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "<h1>index</h1>") {
		t.Fatalf("/: unexpected body %q", rr.Body.String())
	}
	if rr.Header().Get("ETag") == "" {
		t.Fatal("ETag must be present")
	}
	if !strings.Contains(rr.Header().Get("Cache-Control"), "max-age=3600") {
		t.Fatal("cache-control missing")
	}
	if rr.Header().Get("Content-Type") == "" || !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("content type: %q", rr.Header().Get("Content-Type"))
	}
	if rr.Header().Get("Set-Cookie") != "" {
		t.Fatal("no Set-Cookie allowed on the gateway origin")
	}
}

func TestServeIndexHtmlAndETag304(t *testing.T) {
	pk, _ := nostr.GetPublicKey(serveSK)
	s, _ := newServingServer(t, pk)
	host := npub(t) + "." + testDomain

	if rr := get(s, host, "/index.html"); rr.Code != http.StatusOK {
		t.Fatalf("/index.html: got %d", rr.Code)
	}
	etag := get(s, host, "/index.html").Header().Get("ETag")
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/index.html", nil)
	req.Host = host
	req.Header.Set("If-None-Match", etag)
	rr := httptest.NewRecorder()
	s.handlePublic(rr, req)
	if rr.Code != http.StatusNotModified {
		t.Fatalf("If-None-Match: want 304 got %d", rr.Code)
	}
}

func TestServeMissingFallsBackTo404(t *testing.T) {
	pk, _ := nostr.GetPublicKey(serveSK)
	s, _ := newServingServer(t, pk)
	host := npub(t) + "." + testDomain
	rr := get(s, host, "/nope")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("/nope: want 404 got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "<h1>missing</h1>") {
		t.Fatalf("/nope: expected the site's 404.html, got %q", rr.Body.String())
	}
}

func TestServeRejectsTamperedBlob(t *testing.T) {
	pk, _ := nostr.GetPublicKey(serveSK)
	s, _ := newServingServer(t, pk)
	host := npub(t) + "." + testDomain
	rr := get(s, host, "/tampered.html")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("tampered blob must be a 404 (verify-before-serve), got %d", rr.Code)
	}
}

func TestServeRejectsHostilePaths(t *testing.T) {
	pk, _ := nostr.GetPublicKey(serveSK)
	s, _ := newServingServer(t, pk)
	host := npub(t) + "." + testDomain
	for _, path := range []string{"/../etc/passwd", "/%2e%2e/etc/passwd", "/%252e%252e/etc/passwd", "/..%2fetc", "/index.html%00"} {
		if rr := get(s, host, path); rr.Code != http.StatusNotFound {
			t.Errorf("path %q: want 404 got %d", path, rr.Code)
		}
	}
}

func TestServeUnknownHost404(t *testing.T) {
	pk, _ := nostr.GetPublicKey(serveSK)
	s, _ := newServingServer(t, pk)
	if rr := get(s, "bogus."+testDomain, "/"); rr.Code != http.StatusNotFound {
		t.Fatalf("unknown host: want 404 got %d", rr.Code)
	}
}

func TestNormalisePath(t *testing.T) {
	cases := map[string]string{
		"/":             "/index.html",
		"/blog/":        "/blog/index.html",
		"/blog":         "/blog/index.html",
		"/index.html":   "/index.html",
		"/a/b/file.css": "/a/b/file.css",
	}
	for in, want := range cases {
		got, ok := normalisePath(in)
		if !ok || got != want {
			t.Errorf("%q: got %q %v want %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"../etc", "/../x", "/%252e", "/a\\b", "no-slash", "/seg\x00ment"} {
		if _, ok := normalisePath(in); ok {
			t.Errorf("%q must be rejected", in)
		}
	}
}

func TestManifestCacheShortCircuit(t *testing.T) {
	ctx := context.Background()
	pk, _ := nostr.GetPublicKey(serveSK)
	mc := cache.NewManifestCache(time.Hour, time.Minute)
	ev := &nostr.Event{Kind: nip5a.KindRoot, PubKey: pk}
	mc.Put("root:"+pk, ev)
	r := resolve.New([]string{}, mc, nil, 5000) // no relays: cache must be the only path
	got, err := r.Manifest(ctx, nip5a.SiteRoot, pk, "", "")
	if err != nil || got == nil || got.Kind != nip5a.KindRoot {
		t.Fatalf("cache short-circuit failed: %v %v", got, err)
	}
	// Negative cache short-circuit.
	mc.PutNegative("root:unknown")
	if got, err := r.Manifest(ctx, nip5a.SiteRoot, "unknown", "", ""); err != nil || got != nil {
		t.Fatalf("negative short-circuit failed: %v %v", got, err)
	}
}

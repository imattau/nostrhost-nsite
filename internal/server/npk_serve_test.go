package server

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/nbd-wtf/go-nostr"

	"github.com/imattau/nostrhost-nsite/internal/blossom"
	"github.com/imattau/nostrhost-nsite/internal/cache"
	"github.com/imattau/nostrhost-nsite/internal/config"
	"github.com/imattau/nostrhost-nsite/internal/nip5a"
	"github.com/imattau/nostrhost-nsite/internal/npk"
	"github.com/imattau/nostrhost-nsite/internal/resolve"
)

// npkSiteFixture builds a tar.zst archive whose root contains index.html and
// style.css plus a .npack metadata directory (the npack v1 site-bundle shape).
func npkSiteFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	files := map[string]string{
		"index.html": "<h1>index via npk</h1>\n",
		"style.css":  "body{}\n",
	}
	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(content))}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	meta := ".npack/manifest.json"
	manifest := `{"publisher":"site","name":"root","version":"1.0.0","sha256":""}`
	hdr := &tar.Header{Name: meta, Mode: 0o644, Size: int64(len(manifest))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(manifest)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var zstBuf bytes.Buffer
	zw, err := zstd.NewWriter(&zstBuf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(zstBuf.Bytes())
	return zstBuf.Bytes(), hex.EncodeToString(sum[:])
}

// newNpkServer wires a server whose manifest cache is pre-populated and whose
// npk bundle store is pre-loaded with the site bundle, so no relay or Blossom
// contact is made during serving.
func newNpkServer(t *testing.T, pubkey string) (*Server, *httptest.Server, *npk.BundleStore) {
	t.Helper()
	body, sha := npkSiteFixture(t)

	event := &nostr.Event{
		PubKey:    pubkey,
		CreatedAt: nostr.Now(),
		Kind:      nip5a.KindRoot,
		Tags: nostr.Tags{
			{"path", "/index.html", h([]byte("<h1>index via npk</h1>\n"))},
			{"path", "/style.css", h([]byte("body{}\n"))},
			{"server", "https://blossom.invalid"},
		},
		Content: "",
	}
	if err := event.Sign(serveSK); err != nil {
		t.Fatal(err)
	}

	release := &npk.Release{Publisher: pubkey, Name: npk.NameRoot, Version: "1.0.0", SHA256: sha, EventID: "e" + strings.Repeat("0", 63)}

	mcache := cache.NewManifestCache(time.Hour, time.Minute)
	mcache.Put("root:"+pubkey, event)
	mcache.Put("release:"+pubkey+":"+npk.NameRoot, release)
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

	srv := New(cfg, nil)
	srv.Configure(Backends{
		Resolver: resolve.New([]string{"wss://dummy.example.org"}, mcache, nil, 5000),
		Fetcher:  blossom.New(blossom.Options{AllowHTTP: true, AllowLoopback: true}),
		Blobs:    blobs,
		Npk:      bundles,
	})
	return srv, nil, bundles
}

func TestServeFromNpkBundle(t *testing.T) {
	pk, _ := nostr.GetPublicKey(serveSK)
	s, _, _ := newNpkServer(t, pk)
	host := npub(t) + "." + testDomain

	rr := get(s, host, "/index.html")
	if rr.Code != http.StatusOK {
		t.Fatalf("/index.html: got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "index via npk") {
		t.Fatalf("/index.html: unexpected body %q", rr.Body.String())
	}
	if rr.Header().Get("ETag") == "" {
		t.Fatal("ETag must be present")
	}
	if rr.Header().Get("Content-Type") == "" || !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("content type: %q", rr.Header().Get("Content-Type"))
	}

	css := get(s, host, "/style.css")
	if css.Code != http.StatusOK || !strings.Contains(css.Body.String(), "body{}") {
		t.Fatalf("/style.css: got %d %q", css.Code, css.Body.String())
	}
}

func TestNpkBundleMissingPath404(t *testing.T) {
	pk, _ := nostr.GetPublicKey(serveSK)
	s, _, _ := newNpkServer(t, pk)
	host := npub(t) + "." + testDomain
	// The bundle exists but has no 404.html fallback; the manifest has no
	// /missing either, so it must be a plain 404.
	if rr := get(s, host, "/missing"); rr.Code != http.StatusNotFound {
		t.Fatalf("/missing: want 404 got %d", rr.Code)
	}
}

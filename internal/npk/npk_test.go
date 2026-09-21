package npk

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/nbd-wtf/go-nostr"
)

// npkFixture builds a deterministic tar.zst archive (the npack v1 format)
// containing index.html and style.css at the archive root plus a .npack
// metadata directory. Returns the archive bytes and its sha256.
func npkFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	files := map[string]string{
		"index.html": "<h1>site via npk</h1>\n",
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
	manifest := `{"publisher":"site","name":"site","version":"1.0.0","sha256":""}`
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

func TestBundleStoreUnpackAndOpen(t *testing.T) {
	body, sha := npkFixture(t)
	store, err := NewBundleStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if store.Has(sha) {
		t.Fatal("bundle should not exist before unpack")
	}
	bundle, err := store.Unpack(sha, body)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.SHA256 != sha {
		t.Fatalf("bundle sha mismatch: %s != %s", bundle.SHA256, sha)
	}
	if !store.Has(sha) {
		t.Fatal("bundle should exist after unpack")
	}

	index, err := store.Open(sha, "/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if string(index) != "<h1>site via npk</h1>\n" {
		t.Fatalf("unexpected index content: %q", index)
	}
	css, err := store.Open(sha, "/style.css")
	if err != nil {
		t.Fatal(err)
	}
	if string(css) != "body{}\n" {
		t.Fatalf("unexpected css content: %q", css)
	}
	if _, err := store.Open(sha, "/.npack/manifest.json"); err == nil {
		t.Fatal(".npack metadata must not be exposed")
	}
	if _, err := store.Open(sha, "/missing.txt"); err == nil {
		t.Fatal("missing path should error")
	}
}

func TestBundleStoreRejectsHashMismatch(t *testing.T) {
	body, _ := npkFixture(t)
	store, err := NewBundleStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	other := sha256.Sum256([]byte("different"))
	if _, err := store.Unpack(hex.EncodeToString(other[:]), body); err == nil {
		t.Fatal("hash mismatch must be rejected")
	}
	if store.Has(hex.EncodeToString(other[:])) {
		t.Fatal("a failed unpack must not leave a bundle")
	}
}

func TestBundleStoreRejectsTraversalAndLinks(t *testing.T) {
	// Build a hostile tar with a traversal member and a symlink.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	escape := &tar.Header{Name: "../escape.txt", Mode: 0o644, Size: 4}
	if err := tw.WriteHeader(escape); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("boom")); err != nil {
		t.Fatal(err)
	}
	link := &tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}
	if err := tw.WriteHeader(link); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var zstBuf bytes.Buffer
	zw, _ := zstd.NewWriter(&zstBuf)
	_, _ = zw.Write(tarBuf.Bytes())
	_ = zw.Close()
	sum := sha256.Sum256(zstBuf.Bytes())
	sha := hex.EncodeToString(sum[:])

	store, err := NewBundleStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Unpack(sha, zstBuf.Bytes()); err == nil {
		t.Fatal("traversal/symlink archive must be rejected")
	}
	if store.Has(sha) {
		t.Fatal("hostile archive must not leave a bundle")
	}
	// Nothing escaped outside the store.
	entries, _ := os.ReadDir(filepath.Dir(store.dir))
	for _, e := range entries {
		if e.Name() == "escape.txt" {
			t.Fatal("traversal member escaped the store")
		}
	}
}

func TestParseReleaseRequiresCoreTags(t *testing.T) {
	if parseRelease(nil) != nil {
		t.Fatal("nil event must yield nil release")
	}
	good := releaseEvent("root", "1.0.0", "ab"+strings.Repeat("cd", 31))
	if rel := parseRelease(good); rel == nil {
		t.Fatal("valid release event must parse")
	} else if rel.SHA256 != strings.ToLower(rel.SHA256) {
		t.Fatal("sha256 must be lowercased")
	}
	missingX := releaseEvent("root", "1.0.0", "")
	if parseRelease(missingX) != nil {
		t.Fatal("release without x must be invalid")
	}
	wrongName := releaseEvent("other", "1.0.0", "ab"+strings.Repeat("cd", 31))
	rel := parseRelease(wrongName)
	if rel == nil || rel.Name != "other" {
		t.Fatalf("wrong name must still parse with its own name, got %+v", rel)
	}
}

func TestBundleRelSafety(t *testing.T) {
	good := []string{"/index.html", "/assets/app.js", "/404.html"}
	for _, p := range good {
		if _, ok := bundleRel(p); !ok {
			t.Fatalf("expected %q to be safe", p)
		}
	}
	bad := []string{"/../escape", "/.npack/manifest.json", "no-slash", "/a\\b", ".."}
	for _, p := range bad {
		if _, ok := bundleRel(p); ok {
			t.Fatalf("expected %q to be rejected", p)
		}
	}
}

func releaseEvent(name, version, x string) *nostr.Event {
	tags := nostr.Tags{
		{"d", name + "/" + version + "/x86_64"},
		{"v", "1"},
		{"name", name},
		{"version", version},
		{"os", "linux"},
		{"arch", "x86_64"},
		{"format", "npk"},
	}
	if x != "" {
		tags = append(tags, nostr.Tag{"x", x})
	}
	return &nostr.Event{Kind: KindRelease, Tags: tags}
}

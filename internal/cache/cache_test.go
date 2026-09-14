package cache

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sha(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

func TestBlobStorePutGet(t *testing.T) {
	dir := t.TempDir()
	s, err := NewBlobStore(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	key := sha("hello blob")
	body := []byte("hello blob")
	if _, err := s.Put(key, bytes.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	if !s.Has(key) {
		t.Fatal("blob should be present")
	}
	rc, err := s.Open(key)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(rc); err != nil {
		t.Fatal(err)
	}
	if buf.String() != "hello blob" {
		t.Fatalf("got %q", buf.String())
	}
}

func TestBlobStoreRejectsHashMismatch(t *testing.T) {
	dir := t.TempDir()
	s, err := NewBlobStore(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	key := sha("expected content")
	if _, err := s.Put(key, bytes.NewReader([]byte("not the right content"))); err == nil {
		t.Fatal("hash mismatch must not be stored")
	}
	if s.Has(key) {
		t.Fatal("mismatched blob must not appear in the cache")
	}
}

func TestBlobStoreQuotaEviction(t *testing.T) {
	dir := t.TempDir()
	quota := int64(2000)
	s, err := NewBlobStore(dir, quota)
	if err != nil {
		t.Fatal(err)
	}
	// Three ~1000-byte blobs under a 2000-byte quota: one must be evicted.
	keys := make([]string, 3)
	for i := 0; i < 3; i++ {
		body := bytes.Repeat([]byte{byte('a' + i)}, 1000)
		key := sha(string(body))
		keys[i] = key
		if _, err := s.Put(key, bytes.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	}
	// Content-addressed: the third put evicts the least-recently-used blob.
	present := 0
	for _, k := range keys {
		if s.Has(k) {
			present++
		}
	}
	if present > 2 {
		t.Fatalf("quota should cap stored blobs, %d present", present)
	}
	if s.Used() > quota {
		t.Fatalf("used %d exceeds quota %d", s.Used(), quota)
	}
}

func TestManifestCachePositiveNegative(t *testing.T) {
	m := NewManifestCache(time.Hour, time.Hour)
	ev := "kind-15128"
	m.Put("root:abc", ev)
	if got, ok := m.Get("root:abc"); !ok || got != ev {
		t.Fatal("positive hit expected")
	}
	m.PutNegative("root:missing")
	if _, ok := m.Get("root:missing"); ok {
		t.Fatal("negative key must not yield a positive event")
	}
	if !m.Negative("root:missing") {
		t.Fatal("negative hit expected")
	}
}

func TestManifestCacheExpiry(t *testing.T) {
	m := NewManifestCache(50*time.Millisecond, 50*time.Millisecond)
	m.Put("root:abc", "x")
	if _, ok := m.Get("root:abc"); !ok {
		t.Fatal("fresh entry expected")
	}
	time.Sleep(80 * time.Millisecond)
	if _, ok := m.Get("root:abc"); ok {
		t.Fatal("expired entry must miss")
	}
}

func TestBlobStorePersistsAcrossOpen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := NewBlobStore(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	key := sha("persisted")
	if _, err := s.Put(key, bytes.NewReader([]byte("persisted"))); err != nil {
		t.Fatal(err)
	}
	s2, err := NewBlobStore(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Has(key) {
		t.Fatal("blob store must survive re-open")
	}
}

// Package cache provides the content-addressed blob store and the manifest
// caches for the gateway. Blobs are stored on disk keyed by sha256; manifests
// are cached in memory with a positive and negative TTL.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// BlobStore is a content-addressed disk cache bounded by a byte quota. Writes
// are verified: bytes are only stored when their sha256 matches the key, so a
// poisoned fetch never lands in the cache (plan §4.1 "hash verified before any
// byte is written to cache or served").
type BlobStore struct {
	dir   string
	quota int64

	mu      sync.Mutex
	used    int64
	sizes   map[string]int64
	lastUse map[string]time.Time
}

// NewBlobStore opens (creating if needed) a blob cache under dir with the
// given quota in bytes.
func NewBlobStore(dir string, quota int64) (*BlobStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &BlobStore{dir: dir, quota: quota, sizes: map[string]int64{}, lastUse: map[string]time.Time{}}
	if err := s.scan(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *BlobStore) scan() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || len(e.Name()) != 64 {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		s.sizes[e.Name()] = info.Size()
		s.lastUse[e.Name()] = info.ModTime()
		s.used += info.Size()
	}
	return nil
}

func (s *BlobStore) path(sha string) string {
	return filepath.Join(s.dir, sha)
}

// Has reports whether the blob is cached.
func (s *BlobStore) Has(sha string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sizes[sha] > 0
}

// Open returns a reader for a cached blob. The caller must close it.
func (s *BlobStore) Open(sha string) (io.ReadCloser, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.Open(s.path(sha))
	if err != nil {
		return nil, err
	}
	s.lastUse[sha] = time.Now()
	return f, nil
}

// Put streams src to the cache under sha, verifying the digest before the
// rename. Returns the stored size. The caller must provide the expected sha.
func (s *BlobStore) Put(sha string, src io.Reader) (int64, error) {
	tmp, err := os.CreateTemp(s.dir, ".tmp-*")
	if err != nil {
		return 0, err
	}
	defer os.Remove(tmp.Name())

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), src)
	if err != nil {
		tmp.Close()
		return 0, err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sha {
		tmp.Close()
		return 0, fmt.Errorf("blob hash mismatch: expected %s got %s", sha, got)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.Rename(tmp.Name(), s.path(sha)); err != nil {
		return 0, err
	}
	s.sizes[sha] = n
	s.lastUse[sha] = time.Now()
	s.used += n
	s.evictLocked()
	return n, nil
}

// evictLocked removes least-recently-used blobs until under quota.
func (s *BlobStore) evictLocked() {
	if s.used <= s.quota {
		return
	}
	order := make([]string, 0, len(s.lastUse))
	for sha := range s.lastUse {
		order = append(order, sha)
	}
	sort.Slice(order, func(i, j int) bool {
		return s.lastUse[order[i]].Before(s.lastUse[order[j]])
	})
	for _, sha := range order {
		if s.used <= s.quota {
			break
		}
		if err := os.Remove(s.path(sha)); err == nil {
			s.used -= s.sizes[sha]
			delete(s.sizes, sha)
			delete(s.lastUse, sha)
		}
	}
}

// Used reports the current cached bytes.
func (s *BlobStore) Used() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.used
}

// ManifestCache caches resolved manifests (positive) and misses (negative).
type ManifestCache struct {
	mu      sync.Mutex
	ttl     time.Duration
	negTTL  time.Duration
	items   map[string]manifestEntry
	negated map[string]time.Time
}

type manifestEntry struct {
	event   any // *nostr.Event kept opaque to avoid the import here
	expires time.Time
}

// NewManifestCache builds a manifest cache with the given positive and
// negative TTLs.
func NewManifestCache(ttl, negTTL time.Duration) *ManifestCache {
	return &ManifestCache{ttl: ttl, negTTL: negTTL, items: map[string]manifestEntry{}, negated: map[string]time.Time{}}
}

// Get returns the cached event (as any) and true on a fresh positive hit.
func (m *ManifestCache) Get(key string) (any, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.items[key]
	if !ok || time.Now().After(e.expires) {
		delete(m.items, key)
		return nil, false
	}
	return e.event, true
}

// Negative reports a fresh negative hit for key.
func (m *ManifestCache) Negative(key string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	until, ok := m.negated[key]
	if !ok || time.Now().After(until) {
		return false
	}
	return true
}

// Put stores a positive hit.
func (m *ManifestCache) Put(key string, event any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.items[key] = manifestEntry{event: event, expires: time.Now().Add(m.ttl)}
	delete(m.negated, key)
}

// PutNegative records a miss for the negative TTL.
func (m *ManifestCache) PutNegative(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.negated[key] = time.Now().Add(m.negTTL)
	delete(m.items, key)
}

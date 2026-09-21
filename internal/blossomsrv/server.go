// Package blossomsrv implements the optional local Blossom server (Phase 5,
// D4). It is a BUD-01/BUD-02 server: blobs are stored content-addressed on
// disk under sha256 and served at GET/HEAD /<sha256>; uploads are accepted at
// PUT /upload?sha256=<sha> when the caller presents a valid kind-24242 auth
// event (BUD-02), covering the uploaded digest, signed by an admitted key.
//
// The component carries its own quota, abuse and retention contract: a byte
// quota bounds total stored bytes, a per-blob cap bounds any single upload,
// and a retention window lets stale blobs be swept. It is disabled by default;
// the gateway enables it through config ([blossom.local]) and fetches from it
// through the loopback allowance the gateway's SSRF policy grants that exact
// listener (D4: "the fetch-boundary rules apply to a loopback destination,
// which the gateway's SSRF policy must then allow explicitly").
package blossomsrv

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// SHA256Hex is a 64-char lowercase hex sha256 digest.
func validSHA(sha string) bool {
	if len(sha) != 64 {
		return false
	}
	_, err := hex.DecodeString(sha)
	return err == nil
}

// Server is the local content-addressed Blossom server.
type Server struct {
	dir     string
	quota   int64
	maxBlob int64
	retain  time.Duration // 0 = keep forever
	allow   map[string]struct{}
	log     *slog.Logger

	mu   sync.Mutex
	used int64
}

// Options configure the Blossom server.
type Options struct {
	// Dir is the content-addressed blob directory (created on demand).
	Dir string
	// QuotaBytes bounds total stored bytes; uploads that would exceed it are
	// refused. 0 disables the quota check.
	QuotaBytes int64
	// MaxBlobBytes caps a single blob; 0 means no cap.
	MaxBlobBytes int64
	// Retention caps how long a blob may live before the sweeper removes it;
	// 0 keeps blobs forever.
	Retention time.Duration
	// AllowPubkeys admits uploads signed by these hex pubkeys. A nil or empty
	// set admits any valid kind-24242 auth event (open upload); the gateway
	// operator restricts this when the component is exposed beyond the loop.
	AllowPubkeys []string
	Log          *slog.Logger
}

// New builds a Blossom server, scanning the existing store for quota/retention
// accounting.
func New(opts Options) (*Server, error) {
	if opts.Dir == "" {
		return nil, errors.New("blossom: dir is required")
	}
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, err
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	s := &Server{
		dir:     opts.Dir,
		quota:   opts.QuotaBytes,
		maxBlob: opts.MaxBlobBytes,
		retain:  opts.Retention,
		allow:   make(map[string]struct{}, len(opts.AllowPubkeys)),
		log:     opts.Log,
	}
	for _, k := range opts.AllowPubkeys {
		s.allow[k] = struct{}{}
	}
	if err := s.scan(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Server) path(sha string) string { return filepath.Join(s.dir, sha) }

func (s *Server) scan() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range entries {
		if e.IsDir() || !validSHA(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		s.used += info.Size()
	}
	return nil
}

// Used reports the current stored bytes.
func (s *Server) Used() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.used
}

// BlobCount reports the number of stored blobs.
func (s *Server) BlobCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	entries, _ := os.ReadDir(s.dir)
	for _, e := range entries {
		if !e.IsDir() && validSHA(e.Name()) {
			n++
		}
	}
	return n
}

// Has reports whether the blob is present.
func (s *Server) Has(sha string) bool {
	if !validSHA(sha) {
		return false
	}
	_, err := os.Stat(s.path(sha))
	return err == nil
}

// Get returns the stored bytes for sha.
func (s *Server) Get(sha string) ([]byte, error) {
	if !validSHA(sha) {
		return nil, fmt.Errorf("blossom: invalid sha")
	}
	body, err := os.ReadFile(s.path(sha))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		return nil, err
	}
	return body, nil
}

// Put stores bytes under sha, verifying the digest and the quota/max-blob
// caps. The upload auth event is verified before the bytes are written.
func (s *Server) Put(sha string, r io.Reader, auth *nostr.Event) (int64, error) {
	if !validSHA(sha) {
		return 0, fmt.Errorf("blossom: invalid sha")
	}
	if err := s.authorize(auth, sha); err != nil {
		return 0, err
	}

	var buf strings.Builder
	var n int64
	var err error
	if s.maxBlob > 0 {
		// Bound the read at the cap+1 so an oversized upload is refused
		// without buffering an unbounded body.
		n, err = io.Copy(&buf, io.LimitReader(r, s.maxBlob+1))
		if err != nil {
			return 0, err
		}
		if n > s.maxBlob {
			return 0, fmt.Errorf("blossom: blob exceeds %d bytes", s.maxBlob)
		}
	} else {
		n, err = io.Copy(&buf, r)
		if err != nil {
			return 0, err
		}
	}
	body := []byte(buf.String())
	if sum := sha256.Sum256(body); hex.EncodeToString(sum[:]) != sha {
		return 0, fmt.Errorf("blossom: upload hash mismatch: expected %s", sha)
	}

	s.mu.Lock()
	if _, exists := os.Stat(s.path(sha)); exists == nil {
		// Content-addressed idempotency: the blob is already present (bytes
		// are identical by construction, the digest matched), so there is
		// nothing to write and no quota charge.
		s.mu.Unlock()
		return int64(len(body)), nil
	}
	if s.quota > 0 && s.used+int64(len(body)) > s.quota {
		s.mu.Unlock()
		return 0, fmt.Errorf("blossom: store quota exceeded (%d bytes)", s.quota)
	}
	if err := os.WriteFile(s.path(sha), body, 0o600); err != nil {
		s.mu.Unlock()
		return 0, err
	}
	s.used += int64(len(body))
	s.mu.Unlock()
	s.log.Info("blossom blob stored", "sha", sha[:12], "bytes", len(body))
	return int64(len(body)), nil
}

// authorize verifies the BUD-02 auth event covers the uploaded digest.
// The event must be a signed kind-24242 event whose x tags include sha, by a
// key admitted via Options.AllowPubkeys (or any key when the set is empty).
func (s *Server) authorize(ev *nostr.Event, sha string) error {
	if ev == nil {
		return errors.New("blossom: missing Authorization header (Nostr <base64 kind-24242 event>)")
	}
	if ev.Kind != nostr.KindBlobs {
		return fmt.Errorf("blossom: auth event kind must be %d, got %d", nostr.KindBlobs, ev.Kind)
	}
	if !ev.CheckID() {
		return errors.New("blossom: auth event id mismatch")
	}
	if ok, _ := ev.CheckSignature(); !ok {
		return errors.New("blossom: auth event signature invalid")
	}
	if len(s.allow) > 0 {
		if _, ok := s.allow[ev.PubKey]; !ok {
			return errors.New("blossom: auth signer not admitted")
		}
	}
	covered := false
	for _, t := range ev.Tags {
		if len(t) >= 2 && t[0] == "x" && t[1] == sha {
			covered = true
			break
		}
	}
	if !covered {
		return fmt.Errorf("blossom: auth event does not cover sha %s", sha)
	}
	return nil
}

// Sweep removes blobs older than the retention window. Returns the number of
// blobs removed.
func (s *Server) Sweep() int {
	if s.retain <= 0 {
		return 0
	}
	cutoff := time.Now().Add(-s.retain)
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !validSHA(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if os.Remove(s.path(e.Name())) == nil {
				s.mu.Lock()
				s.used -= info.Size()
				s.mu.Unlock()
				removed++
			}
		}
	}
	if removed > 0 {
		s.log.Info("blossom retention sweep", "removed", removed)
	}
	return removed
}

// Handler returns the BUD-01/BUD-02 HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte("ok\n"))
		}
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		payload, _ := json.Marshal(map[string]any{
			"used_bytes": s.Used(),
			"blobs":      s.BlobCount(),
			"quota_bytes": s.quota,
		})
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("/upload", s.handleUpload)
	mux.HandleFunc("/", s.handleBlob)
	return mux
}

func (s *Server) handleBlob(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sha := strings.TrimPrefix(r.URL.Path, "/")
	if !validSHA(sha) {
		http.NotFound(w, r)
		return
	}
	body, err := s.Get(sha)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.Header().Set("ETag", `"`+sha+`"`)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sha := r.URL.Query().Get("sha256")
	if !validSHA(sha) {
		http.Error(w, "invalid or missing sha256 query parameter", http.StatusBadRequest)
		return
	}
	auth, err := parseAuthHeader(r.Header.Get("Authorization"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	n, err := s.Put(sha, r.Body, auth)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	base := strings.TrimSuffix(r.Header.Get("X-Forwarded-Host"), "/")
	if base == "" {
		base = r.Host
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/%s", scheme, base, sha)
	payload, _ := json.Marshal(map[string]any{"url": url, "sha256": sha, "size": n})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

// parseAuthHeader decodes a BUD-02 "Authorization: Nostr <base64url event>"
// header into the signed kind-24242 event.
func parseAuthHeader(header string) (*nostr.Event, error) {
	if !strings.HasPrefix(header, "Nostr ") {
		return nil, errors.New("blossom: Authorization must start with 'Nostr '")
	}
	raw, err := decodeURLBase64(strings.TrimPrefix(header, "Nostr "))
	if err != nil {
		return nil, fmt.Errorf("blossom: bad auth header: %w", err)
	}
	ev := &nostr.Event{}
	if err := json.Unmarshal(raw, ev); err != nil {
		return nil, fmt.Errorf("blossom: bad auth event: %w", err)
	}
	return ev, nil
}

// decodeURLBase64 decodes unpadded base64url (the BUD-02 wire format used by
// both the fork's Python client and npack's Rust client).
func decodeURLBase64(s string) ([]byte, error) {
	// Strip any trailing '=' padding so the unpadded RawURLEncoding decoder
	// accepts the header regardless of which client produced it.
	s = strings.TrimRight(s, "=")
	return base64.RawURLEncoding.DecodeString(s)
}

// SortedSHAs lists the stored blob digests (for tests and admin surfaces).
func (s *Server) SortedSHAs() []string {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && validSHA(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}
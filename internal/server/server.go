// Package server runs the public site handler and the loopback-only internal
// handler (healthz, tls-ask, status). The two handlers are separate http.Server
// instances bound to distinct listeners so /internal/* is never reachable
// through Caddy.
package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/imattau/nostrhost-nsite/internal/blossom"
	"github.com/imattau/nostrhost-nsite/internal/cache"
	"github.com/imattau/nostrhost-nsite/internal/config"
	"github.com/imattau/nostrhost-nsite/internal/metrics"
	"github.com/imattau/nostrhost-nsite/internal/nip5a"
	"github.com/imattau/nostrhost-nsite/internal/resolve"
)

// Backends are the Phase 1.3 resolution stack; nil until Configure is called.
type Backends struct {
	Resolver *resolve.Resolver
	Fetcher  *blossom.Fetcher
	Blobs    *cache.BlobStore
}

type Server struct {
	log    *slog.Logger
	mu     sync.RWMutex
	cfg    *config.Config
	allow  map[string]struct{}   // allowlisted pubkeys (hosted mode)
	custom map[string]customSite // attached FQDNs (Phase 4) -> mapped site
	be     Backends

	public   *http.Server
	internal *http.Server

	m             *metrics.Registry
	reqApex       *metrics.Counter
	reqSite       *metrics.Counter
	reqOther      *metrics.Counter
	cacheHits     *metrics.Counter
	fetchFailures *metrics.Counter
	bytesServed   *metrics.Histogram
}

// New builds a server from the given config; call Configure and Reload as the
// resolution stack and SIGHUP reloads become available.
func New(cfg *config.Config, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{log: log}
	s.m = metrics.New()
	s.reqApex = s.m.Counter("nostrhost_nsite_requests_total", "public requests by class", "class").With("apex")
	s.reqSite = s.m.Counter("nostrhost_nsite_requests_total", "public requests by class", "class").With("site")
	s.reqOther = s.m.Counter("nostrhost_nsite_requests_total", "public requests by class", "class").With("reject")
	s.cacheHits = s.m.Counter("nostrhost_nsite_cache_hits_total", "blob served from the on-disk cache")
	s.fetchFailures = s.m.Counter("nostrhost_nsite_fetch_failures_total", "blob fetch failures by class", "class")
	s.bytesServed = s.m.Histogram("nostrhost_nsite_bytes_served", "response body bytes served", []float64{1024, 16 << 10, 256 << 10, 1 << 20, 4 << 20, 16 << 20})
	s.apply(cfg)
	return s
}

// customSite is the site a custom FQDN maps to (Phase 4).
type customSite struct {
	siteType nip5a.SiteType
	pubkey   string
	d        string
}

func (s *Server) apply(cfg *config.Config) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = cfg
	allow := make(map[string]struct{}, len(cfg.Sites))
	for _, site := range cfg.Sites {
		allow[site.Pubkey] = struct{}{}
	}
	s.allow = allow
	custom := make(map[string]customSite, len(cfg.CustomDomains))
	for _, cd := range cfg.CustomDomains {
		siteType := nip5a.SiteRoot
		if cd.D != "" {
			siteType = nip5a.SiteNamed
		}
		custom[strings.ToLower(strings.TrimSuffix(cd.FQDN, "."))] = customSite{
			siteType: siteType,
			pubkey:   cd.Pubkey,
			d:        cd.D,
		}
	}
	s.custom = custom
}

// Configure installs the resolution backends. Call once after the config is
// loaded; safe to call again after a reload.
func (s *Server) Configure(be Backends) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.be = be
}

// Reload swaps the config and allowlist in place (SIGHUP path).
func (s *Server) Reload(cfg *config.Config) {
	s.apply(cfg)
	s.log.Info("config reloaded", "domain", cfg.Domain, "mode", cfg.Mode, "sites", len(cfg.Sites))
}

// Start binds both listeners and serves. Blocks until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	s.mu.RLock()
	pubAddr, intAddr := s.cfg.PublicListen, s.cfg.InternalListen
	s.mu.RUnlock()

	s.public = &http.Server{
		Addr:    pubAddr,
		Handler: http.HandlerFunc(s.handlePublic),
	}
	s.internal = &http.Server{
		Addr:    intAddr,
		Handler: http.HandlerFunc(s.handleInternal),
	}

	errCh := make(chan error, 2)
	go func() { errCh <- s.public.ListenAndServe() }()
	go func() { errCh <- s.internal.ListenAndServe() }()
	s.log.Info("listening", "public", pubAddr, "internal", intAddr)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.public.Shutdown(shutdownCtx)
		_ = s.internal.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return fmt.Errorf("serve: %w", err)
	}
}

func (s *Server) stripPort(host string) string {
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	return host
}

// isApex reports whether host (with any port stripped) is the gateway apex.
func (s *Server) isApex(host string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stripPort(strings.ToLower(strings.TrimSpace(host))) == s.cfg.Domain
}

// parseHost resolves a request Host header to a site label + type. ok is false
// for the apex and any non-site host. An attached custom FQDN (Phase 4) maps
// to the site it was verified against, served under that site's identity.
func (s *Server) parseHost(host string) (label string, siteType nip5a.SiteType, hexID, d string, ok bool) {
	s.mu.RLock()
	domain := s.cfg.Domain
	s.mu.RUnlock()

	host = s.stripPort(strings.ToLower(strings.TrimSpace(host)))
	if host == domain {
		return "", "", "", "", false // apex (host index)
	}
	suffix := "." + domain
	if !strings.HasSuffix(host, suffix) {
		// Phase 4: an attached custom FQDN is served as the site it maps to.
		s.mu.RLock()
		cs, mapped := s.custom[host]
		s.mu.RUnlock()
		if mapped {
			return host, cs.siteType, cs.pubkey, cs.d, true
		}
		return "", "", "", "", false
	}
	label = host[:len(host)-len(suffix)]
	if len(label) == 0 || len(label) > nip5a.LabelMaxLen {
		return "", "", "", "", false
	}
	siteType, hexID, d, ok = nip5a.DecodeLabel(label)
	return label, siteType, hexID, d, ok
}

// allowlisted reports whether a resolved site is allowed to be served.
//
// Hosted mode: root/named must be on the operator's allowlist. Open mode
// (Phase 5) serves any decodable label: the fork only enables open mode after
// the operator supplied a DNS-01 API token (wildcard certificates), and it is
// the exposure that mode promises, so there is no per-pubkey gate.
func (s *Server) allowlisted(siteType nip5a.SiteType, pubkey string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg.Mode == "open" {
		return true
	}
	switch siteType {
	case nip5a.SiteRoot, nip5a.SiteNamed:
		_, ok := s.allow[pubkey]
		return ok
	default:
		// Snapshots cannot be authorized without resolving the author, which
		// tls-ask must not do (plan §4.2). They are not served in hosted mode
		// until Phase 4 defines a resolution-aware answer.
		return false
	}
}

// handlePublic is the Caddy-facing site handler: host -> site -> path -> blob.
func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/internal/") {
		s.reject(w, r)
		return
	}
	if s.isApex(r.Host) {
		s.reqApex.Inc()
		s.serveApex(w)
		return
	}
	label, siteType, hexID, d, ok := s.parseHost(r.Host)
	if !ok {
		s.reject(w, r)
		return
	}
	if !s.allowlisted(siteType, hexID) {
		s.reject(w, r)
		return
	}
	path, ok := normalisePath(r.URL.Path)
	if !ok {
		s.reject(w, r)
		return
	}
	s.reqSite.Inc()
	s.log.Debug("public request", "label", label, "path", path)
	s.serveSite(w, r, siteType, hexID, d, path)
}

// reject counts a rejected public request and answers with a bounded 404.
func (s *Server) reject(w http.ResponseWriter, r *http.Request) {
	s.reqOther.Inc()
	http.NotFound(w, r)
}

func (s *Server) serveApex(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<h1>nsite gateway</h1>\n"))
}

// handleInternal is the loopback-only management handler.
func (s *Server) handleInternal(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	case "/internal/tls-ask":
		s.handleTLSAsk(w, r)
	case "/internal/status":
		s.handleStatus(w, r)
	case "/internal/metrics":
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = io.WriteString(w, s.m.Render())
	default:
		http.NotFound(w, r)
	}
}

// handleTLSAsk answers Caddy's on-demand TLS permission request. It performs
// no network calls (plan §4.2): 200 when the label decodes and is allowed —
// in hosted mode only allowlisted root/named sites, in open mode (Phase 5)
// any decodable root/named label. Snapshot labels still answer 403 in both
// modes: their author cannot be resolved without a network call.
func (s *Server) handleTLSAsk(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("domain")
	if host == "" {
		host = r.Host
	}
	if s.isApex(host) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}
	label, siteType, hexID, _, ok := s.parseHost(host)
	if !ok {
		http.Error(w, "not allowed", http.StatusForbidden)
		return
	}
	_ = label
	if siteType != nip5a.SiteRoot && siteType != nip5a.SiteNamed {
		http.Error(w, "not allowed", http.StatusForbidden)
		return
	}
	if !s.allowlisted(siteType, hexID) {
		http.Error(w, "not allowed", http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cacheBytes := int64(0)
	if s.be.Blobs != nil {
		cacheBytes = s.be.Blobs.Used()
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"domain":%q,"mode":%q,"allowlisted_sites":%d,"custom_domains":%d,"cache_bytes":%d}`, s.cfg.Domain, s.cfg.Mode, len(s.allow), len(s.custom), cacheBytes)
}

// serveSite resolves the manifest, matches the path, fetches and verifies the
// blob, and serves it with content-addressed headers. Hash verification is
// blocking (plan §4.1); a tampered or missing blob is a bounded 404.
func (s *Server) serveSite(w http.ResponseWriter, r *http.Request, siteType nip5a.SiteType, pubkey, d, path string) {
	s.mu.RLock()
	be := s.be
	s.mu.RUnlock()
	if be.Resolver == nil {
		http.NotFound(w, r)
		return
	}

	event, err := be.Resolver.Manifest(r.Context(), siteType, pubkey, d, "")
	if err != nil || event == nil {
		http.NotFound(w, r)
		return
	}

	paths := map[string]string{}
	for _, t := range event.Tags {
		if len(t) >= 3 && t[0] == "path" {
			paths[t[1]] = t[2]
		}
	}
	sha, ok := paths[path]
	if !ok {
		// NIP-5A "Not Found": fall back to /404.html if the manifest has one.
		if fallback, has := paths["/404.html"]; has {
			sha, ok = fallback, true
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		s.serveBlob(w, r, be, event, sha, "/404.html", http.StatusNotFound)
		return
	}
	s.serveBlob(w, r, be, event, sha, path, http.StatusOK)
}

// serveBlob streams a verified blob. Content-Type comes from the manifest path
// extension, never from upstream (plan §4.1). ETag is the sha256.
func (s *Server) serveBlob(w http.ResponseWriter, r *http.Request, be Backends, event *nostr.Event, sha string, contentTypePath string, status int) {
	if be.Blobs != nil && be.Blobs.Has(sha) {
		s.cacheHits.Inc()
		s.serveCached(w, r, be, sha, contentTypePath, status)
		return
	}

	servers := serverHints(event.Tags)
	if len(servers) == 0 && be.Resolver != nil {
		servers = be.Resolver.BlossomServers(r.Context(), event.PubKey)
	}
	body, err := fetchFirst(r.Context(), be.Fetcher, servers, sha)
	if err != nil || len(body) == 0 {
		s.fetchFailures.With(blossom.ClassifyFetchError(err)).Inc()
		http.NotFound(w, r)
		return
	}
	if be.Blobs != nil {
		_, _ = be.Blobs.Put(sha, strings.NewReader(string(body)))
	}
	s.serveBytes(w, r, sha, contentTypePath, body, status)
}

func (s *Server) serveCached(w http.ResponseWriter, r *http.Request, be Backends, sha, contentTypePath string, status int) {
	rc, err := be.Blobs.Open(sha)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer rc.Close()
	buf, _ := io.ReadAll(rc)
	s.serveBytes(w, r, sha, contentTypePath, buf, status)
}

func (s *Server) serveBytes(w http.ResponseWriter, r *http.Request, sha, contentTypePath string, body []byte, status int) {
	s.bytesServed.Observe(float64(len(body)))
	etag := `"` + sha + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", contentTypeFor(contentTypePath))
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func serverHints(tags nostr.Tags) []string {
	var servers []string
	for _, t := range tags {
		if len(t) >= 2 && t[0] == "server" {
			servers = append(servers, t[1])
		}
	}
	return servers
}

// fetchFirst tries each server in order until one returns verified bytes.
func fetchFirst(ctx context.Context, f *blossom.Fetcher, servers []string, sha string) ([]byte, error) {
	if f == nil || len(servers) == 0 {
		return nil, fmt.Errorf("no blossom servers")
	}
	var lastErr error
	for _, server := range servers {
		body, err := f.Fetch(ctx, server, sha)
		if err == nil {
			return body, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// normalisePath applies the NIP-5A path rules (plan §4.1 step 3): single
// percent-decode (double-encoding rejected), reject .., \, NUL/control and
// empty-ish segments, collapse //, ensure a leading slash, and append
// /index.html for directory-looking paths.
func normalisePath(p string) (string, bool) {
	decoded, err := url.PathUnescape(p)
	if err != nil || strings.Contains(decoded, "%") {
		return "", false
	}
	if !strings.HasPrefix(decoded, "/") {
		return "", false
	}
	decoded = strings.Join(strings.Split(decoded, "//"), "/") // collapse //
	for _, seg := range strings.Split(decoded, "/") {
		if strings.Contains(seg, "..") || strings.Contains(seg, "\\") {
			return "", false
		}
		for _, r := range seg {
			if r < 0x20 || r == 0x7F {
				return "", false
			}
		}
	}
	if strings.HasSuffix(decoded, "/") || !strings.Contains(lastSegment(decoded), ".") {
		decoded = strings.TrimSuffix(decoded, "/") + "/index.html"
	}
	return decoded, true
}

func lastSegment(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

var contentTypes = map[string]string{
	".html":        "text/html; charset=utf-8",
	".htm":         "text/html; charset=utf-8",
	".css":         "text/css",
	".js":          "text/javascript",
	".mjs":         "text/javascript",
	".json":        "application/json",
	".txt":         "text/plain",
	".xml":         "application/xml",
	".svg":         "image/svg+xml",
	".ico":         "image/x-icon",
	".png":         "image/png",
	".jpg":         "image/jpeg",
	".jpeg":        "image/jpeg",
	".gif":         "image/gif",
	".webp":        "image/webp",
	".woff2":       "font/woff2",
	".wasm":        "application/wasm",
	".pdf":         "application/pdf",
	".webmanifest": "application/manifest+json",
}

func contentTypeFor(path string) string {
	i := strings.LastIndex(path, ".")
	if i < 0 {
		return "application/octet-stream"
	}
	ext := strings.ToLower(path[i:])
	if ct, ok := contentTypes[ext]; ok {
		return ct
	}
	return "application/octet-stream"
}

// hashOf is a small helper used by tests to derive a blob hash.
func hashOf(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

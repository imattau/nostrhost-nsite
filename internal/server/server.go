// Package server runs the public site handler and the loopback-only internal
// handler (healthz, tls-ask, status).
//
// The public and internal handlers are separate http.Server instances bound to
// distinct listeners so /internal/* is never reachable through Caddy.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/imattau/nostrhost-nsite/internal/config"
	"github.com/imattau/nostrhost-nsite/internal/nip5a"
)

type Server struct {
	log   *slog.Logger
	mu    sync.RWMutex
	cfg   *config.Config
	allow map[string]struct{} // allowlisted pubkeys (hosted mode)

	public   *http.Server
	internal *http.Server
}

// New builds a server from the given config; call Reload after a SIGHUP.
func New(cfg *config.Config, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{log: log}
	s.apply(cfg)
	return s
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

// parseHost resolves a request Host header to a site label + type.
// ok is false for the apex and any non-site host.
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
		return "", "", "", "", false
	}
	label = host[:len(host)-len(suffix)]
	if len(label) == 0 || len(label) > nip5a.LabelMaxLen {
		return "", "", "", "", false
	}
	siteType, hexID, d, ok = nip5a.DecodeLabel(label)
	return label, siteType, hexID, d, ok
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

// allowlisted reports whether a resolved site is allowed in hosted mode.
func (s *Server) allowlisted(siteType nip5a.SiteType, pubkey string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	switch siteType {
	case nip5a.SiteRoot, nip5a.SiteNamed:
		_, ok := s.allow[pubkey]
		return ok
	default:
		// Snapshots cannot be authorized without resolving the author, which
		// tls-ask must not do (plan §4.2). They are not certificate-issuable
		// in hosted mode until Phase 4 defines a resolution-aware answer.
		return false
	}
}

// handlePublic is the Caddy-facing site handler. Manifest/blob resolution is
// Phase 1.3; until then a decodable, allowlisted host gets a bounded 404 and
// everything else gets the same 404.
func (s *Server) handlePublic(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/internal/") {
		http.NotFound(w, r)
		return
	}
	if s.isApex(r.Host) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<h1>nsite gateway</h1>"))
		return
	}
	label, siteType, hexID, _, ok := s.parseHost(r.Host)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if siteType != nip5a.SiteRoot && siteType != nip5a.SiteNamed {
		http.NotFound(w, r)
		return
	}
	if !s.allowlisted(siteType, hexID) {
		http.NotFound(w, r)
		return
	}
	// Phase 1.3: resolve manifest + blob and serve; until then a bounded 404.
	s.log.Debug("public request", "label", label, "path", r.URL.Path)
	http.NotFound(w, r)
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
	default:
		http.NotFound(w, r)
	}
}

// handleTLSAsk answers Caddy's on-demand TLS permission request. It performs
// no network calls (plan §4.2): 200 only when the label decodes and, in hosted
// mode, is allowlisted.
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
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"domain":%q,"mode":%q,"allowlisted_sites":%d}`, s.cfg.Domain, s.cfg.Mode, len(s.allow))
}

package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imattau/nostrhost-nsite/internal/config"
	"github.com/imattau/nostrhost-nsite/internal/metrics"
	"github.com/imattau/nostrhost-nsite/internal/nip5a"
)

const (
	testPubkey = "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
	testDomain = "sites.example.org"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	cfg := config.Defaults()
	cfg.Domain = testDomain
	cfg.Sites = []config.Site{{Pubkey: testPubkey, Kind: nip5a.KindRoot, D: ""}}
	cfg.Relays.Lookup = []string{"wss://relay.example.org"}
	return New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func npub(t *testing.T) string {
	t.Helper()
	n, err := nip5a.NPub(testPubkey)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func namedLabel(t *testing.T) string {
	t.Helper()
	l, err := nip5a.NamedLabel(testPubkey, "blog")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func do(s *Server, handler string, host string, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+path, nil)
	req.Host = host
	rr := httptest.NewRecorder()
	if handler == "public" {
		s.handlePublic(rr, req)
	} else {
		s.handleInternal(rr, req)
	}
	return rr
}

func TestTLSAskAllowsAllowlisted(t *testing.T) {
	s := testServer(t)
	for _, host := range []string{npub(t) + "." + testDomain, namedLabel(t) + "." + testDomain, testDomain} {
		rr := do(s, "internal", host, "/internal/tls-ask?domain="+host)
		if rr.Code != http.StatusOK {
			t.Errorf("%s: want 200 got %d", host, rr.Code)
		}
	}
}

func TestTLSAskDeniesUnknown(t *testing.T) {
	s := testServer(t)
	unknown, _ := nip5a.NPub("0000000000000000000000000000000000000000000000000000000000000000")
	cases := []string{
		unknown + "." + testDomain,
		"bogus." + testDomain,
		"a" + ".sites.other.example.org",
	}
	for _, host := range cases {
		rr := do(s, "internal", host, "/internal/tls-ask?domain="+host)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s: want 403 got %d", host, rr.Code)
		}
	}
}

func TestTLSAskDeniesSnapshotInHostedMode(t *testing.T) {
	s := testServer(t)
	snap, err := nip5a.SnapshotLabel("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	host := snap + "." + testDomain
	rr := do(s, "internal", host, "/internal/tls-ask?domain="+host)
	if rr.Code != http.StatusForbidden {
		t.Errorf("snapshot label must be denied in hosted mode, got %d", rr.Code)
	}
}

func openServer(t *testing.T) *Server {
	t.Helper()
	cfg := config.Defaults()
	cfg.Domain = testDomain
	cfg.Mode = "open"
	cfg.Sites = nil
	cfg.Relays.Lookup = []string{"wss://relay.example.org"}
	return New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestOpenModeTLSAskAllowsAnyDecodableLabel(t *testing.T) {
	s := openServer(t)
	unknown, _ := nip5a.NPub("0000000000000000000000000000000000000000000000000000000000000000")
	for _, host := range []string{unknown + "." + testDomain, namedLabel(t) + "." + testDomain, testDomain} {
		rr := do(s, "internal", host, "/internal/tls-ask?domain="+host)
		if rr.Code != http.StatusOK {
			t.Errorf("%s: open mode must allow any decodable root/named label, got %d", host, rr.Code)
		}
	}
}

func TestOpenModeStillDeniesSnapshotAndGarbage(t *testing.T) {
	s := openServer(t)
	snap, err := nip5a.SnapshotLabel("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		snap + "." + testDomain,
		"bogus." + testDomain,
		"not-a-host!" + "." + testDomain,
	}
	for _, host := range cases {
		rr := do(s, "internal", host, "/internal/tls-ask?domain="+host)
		if rr.Code != http.StatusForbidden {
			t.Errorf("%s: want 403 got %d", host, rr.Code)
		}
	}
}

func TestOpenModeStatusReportsMode(t *testing.T) {
	s := openServer(t)
	rr := do(s, "internal", "127.0.0.1", "/internal/status")
	if body := rr.Body.String(); body != `{"domain":"sites.example.org","mode":"open","allowlisted_sites":0,"custom_domains":0,"cache_bytes":0,"npk_enabled":false}` {
		t.Errorf("status body = %s", body)
	}
}

func TestHealthz(t *testing.T) {
	s := testServer(t)
	rr := do(s, "internal", "127.0.0.1", "/healthz")
	if rr.Code != http.StatusOK {
		t.Fatalf("healthz: got %d", rr.Code)
	}
}

func TestStatusJSON(t *testing.T) {
	s := testServer(t)
	rr := do(s, "internal", "127.0.0.1", "/internal/status")
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d", rr.Code)
	}
	if body := rr.Body.String(); body != `{"domain":"sites.example.org","mode":"hosted","allowlisted_sites":1,"custom_domains":0,"cache_bytes":0,"npk_enabled":false}` {
		t.Fatalf("status body: %s", body)
	}
}

func TestMetricsExposition(t *testing.T) {
	s := testServer(t)
	// A real request should bump the site/reject counters and the bytes
	// histogram; the exposition must then carry the metric families.
	do(s, "public", "bogus."+testDomain, "/")
	rr := do(s, "internal", "127.0.0.1", "/internal/metrics")
	if rr.Code != http.StatusOK {
		t.Fatalf("metrics: got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("metrics content type: %q", ct)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`nostrhost_nsite_requests_total{class="reject"} 1`,
		"# HELP nostrhost_nsite_cache_hits_total",
		"# HELP nostrhost_nsite_bytes_served",
		"# TYPE nostrhost_nsite_requests_total counter",
		"# TYPE nostrhost_nsite_bytes_served histogram",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
}

func TestMetricsFetchFailureFamily(t *testing.T) {
	// A labelled family only appears in the exposition once a label set is
	// instantiated. Trigger a fetch failure through the public path and the
	// class-labelled counter must show up with a value.
	r := metrics.New()
	fam := r.Counter("nostrhost_nsite_fetch_failures_total", "blob fetch failures by class", "class")
	// Before any With(), the family is absent from the exposition.
	if out := r.Render(); strings.Contains(out, "nostrhost_nsite_fetch_failures_total") {
		t.Fatalf("unused labelled family leaked into exposition:\n%s", out)
	}
	fam.With("network").Inc()
	out := r.Render()
	if !strings.Contains(out, `nostrhost_nsite_fetch_failures_total{class="network"} 1`) {
		t.Fatalf("missing class counter:\n%s", out)
	}
}

func TestPublicApexServesIndex(t *testing.T) {
	s := testServer(t)
	rr := do(s, "public", testDomain, "/")
	if rr.Code != http.StatusOK {
		t.Fatalf("apex: got %d", rr.Code)
	}
}

func TestPublicRejectsUnknownAndInternalPath(t *testing.T) {
	s := testServer(t)
	if rr := do(s, "public", "bogus."+testDomain, "/"); rr.Code != http.StatusNotFound {
		t.Errorf("unknown label: want 404 got %d", rr.Code)
	}
	if rr := do(s, "public", npub(t)+"."+testDomain, "/internal/healthz"); rr.Code != http.StatusNotFound {
		t.Errorf("public /internal: want 404 got %d", rr.Code)
	}
}

func TestReloadSwapsAllowlist(t *testing.T) {
	s := testServer(t)
	if rr := do(s, "internal", npub(t)+"."+testDomain, "/internal/tls-ask?domain="+npub(t)+"."+testDomain); rr.Code != http.StatusOK {
		t.Fatalf("setup: want 200 got %d", rr.Code)
	}
	cfg := config.Defaults()
	cfg.Domain = testDomain
	cfg.Relays.Lookup = []string{"wss://relay.example.org"}
	s.Reload(cfg) // allowlist now empty
	if rr := do(s, "internal", npub(t)+"."+testDomain, "/internal/tls-ask?domain="+npub(t)+"."+testDomain); rr.Code != http.StatusForbidden {
		t.Fatalf("after reload: want 403 got %d", rr.Code)
	}
}

func testServerWithCustom(t *testing.T, d string) *Server {
	t.Helper()
	cfg := config.Defaults()
	cfg.Domain = testDomain
	cfg.Sites = []config.Site{{Pubkey: testPubkey, Kind: nip5a.KindRoot, D: ""}}
	cfg.CustomDomains = []config.CustomDomain{{
		FQDN:   "blog.example.com",
		Pubkey: testPubkey,
		D:      d,
	}}
	cfg.Relays.Lookup = []string{"wss://relay.example.org"}
	return New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestParseHostCustomDomain(t *testing.T) {
	s := testServerWithCustom(t, "")
	label, siteType, hexID, d, ok := s.parseHost("blog.example.com")
	if !ok || siteType != nip5a.SiteRoot || hexID != testPubkey || d != "" || label != "blog.example.com" {
		t.Fatalf("root custom host: got (%q, %s, %s, %q, %v)", label, siteType, hexID, d, ok)
	}
	_, _, _, _, ok = s.parseHost("other.example.com")
	if ok {
		t.Fatal("non-attached host must not parse")
	}
}

func TestParseHostCustomDomainNamed(t *testing.T) {
	s := testServerWithCustom(t, "blog")
	_, siteType, hexID, d, ok := s.parseHost("blog.example.com")
	if !ok || siteType != nip5a.SiteNamed || hexID != testPubkey || d != "blog" {
		t.Fatalf("named custom host: got (%s, %s, %q, %v)", siteType, hexID, d, ok)
	}
}

func TestTLSAskAllowsCustomDomain(t *testing.T) {
	s := testServerWithCustom(t, "")
	rr := do(s, "internal", "blog.example.com", "/internal/tls-ask?domain=blog.example.com")
	if rr.Code != http.StatusOK {
		t.Fatalf("attached custom domain: want 200 got %d", rr.Code)
	}
}

func TestTLSAskDeniesNonAttachedCustomDomain(t *testing.T) {
	s := testServer(t)
	rr := do(s, "internal", "blog.example.com", "/internal/tls-ask?domain=blog.example.com")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("non-attached custom domain: want 403 got %d", rr.Code)
	}
}

func TestPublicCustomDomainIsServedAsSite(t *testing.T) {
	// An attached custom host must reach the site path (nil resolver -> 404
	// through serveSite) and must not be counted as a reject; a non-attached
	// custom host is a plain reject.
	s := testServerWithCustom(t, "")
	rr := do(s, "public", "blog.example.com", "/")
	if rr.Code != http.StatusNotFound {
		t.Fatalf("attached custom host with nil resolver: want 404 got %d", rr.Code)
	}
	do(s, "public", "other.example.com", "/")
	body := do(s, "internal", "127.0.0.1", "/internal/metrics").Body.String()
	if !strings.Contains(body, `nostrhost_nsite_requests_total{class="site"} 1`) {
		t.Fatalf("attached custom host must count as a site request:\n%s", body)
	}
	if !strings.Contains(body, `nostrhost_nsite_requests_total{class="reject"} 1`) {
		t.Fatalf("non-attached custom host must count as a reject:\n%s", body)
	}
}

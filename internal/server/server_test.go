package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/imattau/nostrhost-nsite/internal/config"
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
	if body := rr.Body.String(); body != `{"domain":"sites.example.org","mode":"hosted","allowlisted_sites":1}` {
		t.Fatalf("status body: %s", body)
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

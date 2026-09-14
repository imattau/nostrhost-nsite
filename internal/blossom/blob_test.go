package blossom

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func shaOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func testFetcher(t *testing.T, opts Options) *Fetcher {
	t.Helper()
	opts.MaxBytes = 1 << 20
	opts.Timeout = 5 * time.Second
	opts.MaxRedirects = 3
	opts.AllowHTTP = true
	opts.AllowLoopback = true
	return New(opts)
}

func TestFetchSuccess(t *testing.T) {
	body := []byte("<h1>hello</h1>")
	sha := shaOf(body)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/"+sha {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	got, err := testFetcher(t, Options{}).Fetch(context.Background(), ts.URL, sha)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Fatalf("got %q want %q", got, body)
	}
}

func TestFetchHashMismatchRejected(t *testing.T) {
	sha := shaOf([]byte("expected"))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("wrong bytes"))
	}))
	defer ts.Close()
	if _, err := testFetcher(t, Options{}).Fetch(context.Background(), ts.URL, sha); err == nil {
		t.Fatal("hash mismatch must be rejected")
	}
}

func TestFetchOversizedRejected(t *testing.T) {
	body := []byte(strings.Repeat("x", 4096))
	sha := shaOf(body)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer ts.Close()
	f := New(Options{AllowHTTP: true, AllowLoopback: true, MaxBytes: 1024, Timeout: 5 * time.Second, MaxRedirects: 3})
	if _, err := f.Fetch(context.Background(), ts.URL, sha); err == nil {
		t.Fatal("oversized blob must be rejected")
	}
}

func TestFetchRejectsLoopbackByDefault(t *testing.T) {
	body := []byte("hello")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer ts.Close()
	f := New(Options{AllowHTTP: true, Timeout: 3 * time.Second, MaxBytes: 1 << 20, MaxRedirects: 3})
	if _, err := f.Fetch(context.Background(), ts.URL, shaOf(body)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("loopback fetch must be forbidden by default, got %v", err)
	}
}

func TestFetchRejectsHTTPWithoutAllow(t *testing.T) {
	body := []byte("hello")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer ts.Close()
	f := New(Options{AllowLoopback: true, Timeout: 3 * time.Second, MaxBytes: 1 << 20, MaxRedirects: 3})
	if _, err := f.Fetch(context.Background(), ts.URL, shaOf(body)); err == nil {
		t.Fatal("http scheme without allow_http must be rejected")
	}
}

func TestFetchRedirectCap(t *testing.T) {
	body := []byte("hello")
	sha := shaOf(body)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound) // self-redirect forever
	}))
	defer ts.Close()
	_ = sha
	if _, err := testFetcher(t, Options{}).Fetch(context.Background(), ts.URL, shaOf(body)); err == nil {
		t.Fatal("excessive redirects must be rejected")
	}
}

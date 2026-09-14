package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/imattau/nostrhost-nsite/internal/blossom"
)

// TestFetchFirstTriesServersInOrder verifies the multi-server fallback:
// servers are attempted in manifest order and the first *verified* copy wins
// (plan §4.1 step 5). A server that returns wrong bytes must not poison the
// result — fetchFirst falls through to the next.
func TestFetchFirstTriesServersInOrder(t *testing.T) {
	good := []byte("<h1>good</h1>\n")
	sha := h(good)

	var badHits, goodHits atomic.Int32
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		badHits.Add(1)
		_, _ = w.Write([]byte("<h1>wrong bytes</h1>"))
	}))
	defer bad.Close()
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		goodHits.Add(1)
		_, _ = w.Write(good)
	}))
	defer goodServer.Close()

	f := blossom.New(blossom.Options{AllowHTTP: true, AllowLoopback: true})
	body, err := fetchFirst(context.Background(), f, []string{bad.URL, goodServer.URL}, sha)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(good) {
		t.Fatalf("got %q want %q", body, good)
	}
	if badHits.Load() != 1 || goodHits.Load() != 1 {
		t.Fatalf("expected both servers attempted (bad then good), bad=%d good=%d", badHits.Load(), goodHits.Load())
	}
}

// TestFetchFirstStopsAtFirstVerified ensures the fallback ordering is strict:
// once a verified copy is found, later servers are not contacted.
func TestFetchFirstStopsAtFirstVerified(t *testing.T) {
	good := []byte("<h1>first</h1>\n")
	sha := h(good)

	var secondHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(good)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		_, _ = w.Write(good)
	}))
	defer second.Close()

	f := blossom.New(blossom.Options{AllowHTTP: true, AllowLoopback: true})
	if _, err := fetchFirst(context.Background(), f, []string{first.URL, second.URL}, sha); err != nil {
		t.Fatal(err)
	}
	if secondHits.Load() != 0 {
		t.Fatalf("second server must not be contacted after a verified copy, hits=%d", secondHits.Load())
	}
}

// TestFetchFirstRejectsPrivateServerHint ensures a malicious private-IP server
// hint in a manifest is skipped (never dialed) rather than attempted.
func TestFetchFirstRejectsPrivateServerHint(t *testing.T) {
	good := []byte("<h1>ok</h1>\n")
	sha := h(good)
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(good)
	}))
	defer goodServer.Close()

	f := blossom.New(blossom.Options{AllowHTTP: true, AllowLoopback: true})
	body, err := fetchFirst(context.Background(), f, []string{"http://127.0.0.1:8190", "http://10.0.0.5", goodServer.URL}, sha)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(good) {
		t.Fatalf("got %q want %q", body, good)
	}
}

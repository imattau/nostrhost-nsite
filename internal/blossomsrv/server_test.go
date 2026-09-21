package blossomsrv

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

const testSK = "3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d"
const otherSK = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6"

func signAuth(t *testing.T, sha string, sk string) *nostr.Event {
	t.Helper()
	ev := &nostr.Event{CreatedAt: nostr.Now(), Kind: nostr.KindBlobs, Tags: nostr.Tags{{"x", sha}}, Content: ""}
	if err := ev.Sign(sk); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return ev
}

func authHeader(t *testing.T, ev *nostr.Event) string {
	t.Helper()
	raw, _ := json.Marshal(ev)
	return "Nostr " + base64.RawURLEncoding.EncodeToString(raw)
}

func shaOf(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func newTestServer(t *testing.T, opts Options) *Server {
	t.Helper()
	if opts.Dir == "" {
		opts.Dir = filepath.Join(t.TempDir(), "blobs")
	}
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func pubkey(t *testing.T, sk string) string {
	t.Helper()
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	return pk
}

func TestPutAndGet(t *testing.T) {
	s := newTestServer(t, Options{})
	body := []byte("<html>hello</html>")
	sha := shaOf(body)
	if _, err := s.Put(sha, bytes.NewReader(body), signAuth(t, sha, testSK)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(sha)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("roundtrip mismatch")
	}
	if s.BlobCount() != 1 || s.Used() != int64(len(body)) {
		t.Fatalf("accounting wrong: count=%d used=%d", s.BlobCount(), s.Used())
	}
}

func TestPutRejectsMissingAuth(t *testing.T) {
	s := newTestServer(t, Options{})
	body := []byte("x")
	if _, err := s.Put(shaOf(body), bytes.NewReader(body), nil); err == nil {
		t.Fatal("expected missing-auth rejection")
	}
}

func TestPutRejectsBadKind(t *testing.T) {
	s := newTestServer(t, Options{})
	body := []byte("x")
	sha := shaOf(body)
	ev := &nostr.Event{CreatedAt: nostr.Now(), Kind: 1, Tags: nostr.Tags{{"x", sha}}, Content: ""}
	if err := ev.Sign(testSK); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(sha, bytes.NewReader(body), ev); err == nil {
		t.Fatal("expected bad-kind rejection")
	}
}

func TestPutRejectsUncoveredSHA(t *testing.T) {
	s := newTestServer(t, Options{})
	body := []byte("x")
	sha := shaOf(body)
	other := shaOf([]byte("y"))
	// auth covers a different digest
	if _, err := s.Put(sha, bytes.NewReader(body), signAuth(t, other, testSK)); err == nil {
		t.Fatal("expected uncovered-sha rejection")
	}
}

func TestPutRejectsHashMismatch(t *testing.T) {
	s := newTestServer(t, Options{})
	if _, err := s.Put(strings.Repeat("0", 64), strings.NewReader("nope"), signAuth(t, strings.Repeat("0", 64), testSK)); err == nil {
		t.Fatal("expected hash-mismatch rejection")
	}
}

func TestPutRejectsNonAdmittedSigner(t *testing.T) {
	s := newTestServer(t, Options{AllowPubkeys: []string{pubkey(t, testSK)}})
	body := []byte("x")
	sha := shaOf(body)
	if _, err := s.Put(sha, bytes.NewReader(body), signAuth(t, sha, otherSK)); err == nil {
		t.Fatal("expected non-admitted signer rejection")
	}
}

func TestQuotaEnforced(t *testing.T) {
	s := newTestServer(t, Options{QuotaBytes: 5})
	body := []byte("123456") // 6 bytes > quota
	if _, err := s.Put(shaOf(body), bytes.NewReader(body), signAuth(t, shaOf(body), testSK)); err == nil {
		t.Fatal("expected quota rejection")
	}
	if s.BlobCount() != 0 {
		t.Fatal("nothing should have been stored")
	}
}

func TestMaxBlobEnforced(t *testing.T) {
	s := newTestServer(t, Options{MaxBlobBytes: 3})
	body := []byte("1234")
	if _, err := s.Put(shaOf(body), bytes.NewReader(body), signAuth(t, shaOf(body), testSK)); err == nil {
		t.Fatal("expected max-blob rejection")
	}
}

func TestIdempotentReupload(t *testing.T) {
	s := newTestServer(t, Options{QuotaBytes: 10})
	body := []byte("abcdef")
	sha := shaOf(body)
	if _, err := s.Put(sha, bytes.NewReader(body), signAuth(t, sha, testSK)); err != nil {
		t.Fatal(err)
	}
	// re-uploading identical content should not double-charge the quota
	if _, err := s.Put(sha, bytes.NewReader(body), signAuth(t, sha, testSK)); err != nil {
		t.Fatal(err)
	}
	if s.Used() != int64(len(body)) || s.BlobCount() != 1 {
		t.Fatalf("idempotency broke accounting: used=%d count=%d", s.Used(), s.BlobCount())
	}
}

func TestSweepRetention(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "blobs")
	s := newTestServer(t, Options{Dir: dir, Retention: time.Hour})
	body := []byte("old")
	sha := shaOf(body)
	if _, err := s.Put(sha, bytes.NewReader(body), signAuth(t, sha, testSK)); err != nil {
		t.Fatal(err)
	}
	// backdate the file beyond the retention window
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, sha), past, past); err != nil {
		t.Fatal(err)
	}
	if s.Sweep() != 1 {
		t.Fatalf("sweep should remove 1, count=%d", s.BlobCount())
	}
	if s.Has(sha) {
		t.Fatal("blob should be gone")
	}
	if s.Used() != 0 {
		t.Fatalf("used should be 0, got %d", s.Used())
	}
}

func TestSweepSkipsFresh(t *testing.T) {
	s := newTestServer(t, Options{Retention: time.Hour})
	body := []byte("new")
	sha := shaOf(body)
	if _, err := s.Put(sha, bytes.NewReader(body), signAuth(t, sha, testSK)); err != nil {
		t.Fatal(err)
	}
	if s.Sweep() != 0 || !s.Has(sha) {
		t.Fatal("fresh blob should survive the sweep")
	}
}

func TestHandlerGetAndHead(t *testing.T) {
	s := newTestServer(t, Options{})
	body := []byte("blob body")
	sha := shaOf(body)
	if _, err := s.Put(sha, bytes.NewReader(body), signAuth(t, sha, testSK)); err != nil {
		t.Fatal(err)
	}
	h := s.Handler()

	// GET
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/"+sha, nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET status %d", rr.Code)
	}
	if rr.Body.String() != string(body) {
		t.Fatal("GET body mismatch")
	}
	if rr.Header().Get("ETag") != `"`+sha+`"` {
		t.Fatal("missing ETag")
	}

	// HEAD
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodHead, "/"+sha, nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("HEAD status %d", rr.Code)
	}
	if rr.Body.Len() != 0 {
		t.Fatal("HEAD must not return a body")
	}

	// 404
	rr = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/"+strings.Repeat("a", 64), nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing blob status %d", rr.Code)
	}
}

func TestHandlerStatus(t *testing.T) {
	s := newTestServer(t, Options{QuotaBytes: 100})
	body := []byte("status payload")
	sha := shaOf(body)
	if _, err := s.Put(sha, bytes.NewReader(body), signAuth(t, sha, testSK)); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status HTTP %d", rr.Code)
	}
	var st struct {
		UsedBytes  int64 `json:"used_bytes"`
		Blobs      int   `json:"blobs"`
		QuotaBytes int64 `json:"quota_bytes"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.UsedBytes != int64(len(body)) || st.Blobs != 1 || st.QuotaBytes != 100 {
		t.Fatalf("bad status payload: %+v", st)
	}
}

func TestHandlerUpload(t *testing.T) {
	s := newTestServer(t, Options{})
	h := s.Handler()
	body := []byte("upload me")
	sha := shaOf(body)
	ev := signAuth(t, sha, testSK)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/upload?sha256="+sha, bytes.NewReader(body))
	req.Header.Set("Authorization", authHeader(t, ev))
	req.Host = "127.0.0.1:8197"
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload status %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["sha256"] != sha || resp["size"] != float64(len(body)) {
		t.Fatalf("bad upload response: %v", resp)
	}
	if got, _ := s.Get(sha); !bytes.Equal(got, body) {
		t.Fatal("stored body mismatch")
	}
}

func TestHandlerUploadRequiresAuth(t *testing.T) {
	s := newTestServer(t, Options{})
	h := s.Handler()
	body := []byte("x")
	sha := shaOf(body)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/upload?sha256="+sha, bytes.NewReader(body))
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestParseAuthHeader(t *testing.T) {
	ev := signAuth(t, shaOf([]byte("x")), testSK)
	hdr := authHeader(t, ev)
	parsed, err := parseAuthHeader(hdr)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PubKey != ev.PubKey || parsed.Kind != nostr.KindBlobs {
		t.Fatal("parsed auth mismatch")
	}
	// padded variant should also parse (some clients emit padding)
	padded := base64.URLEncoding.EncodeToString(mustJSON(t, ev))
	if _, err := parseAuthHeader("Nostr " + padded); err != nil {
		t.Fatalf("padded header should parse: %v", err)
	}
	// non-Nostr prefix
	if _, err := parseAuthHeader("Bearer xyz"); err == nil {
		t.Fatal("expected prefix rejection")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
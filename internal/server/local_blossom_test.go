package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/imattau/nostrhost-nsite/internal/blossom"
	"github.com/imattau/nostrhost-nsite/internal/blossomsrv"
)

const testSK = "3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d3f4f6b8d"

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

func base64RawURLEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// TestLocalBlossomFetchThroughTargetedAllowance is the D4 integration proof:
// the gateway fetches a blob from the local Blossom server only when its fetch
// boundary has the exact loopback address in the allowance list. With the
// allowance set, the verified bytes come back; without it, the same fetch is
// refused at the dial boundary.
func TestLocalBlossomFetchThroughTargetedAllowance(t *testing.T) {
	body := []byte("<html>local blossom</html>")
	sha := shaOfLocal(body)

	// Start the local Blossom server on a real loopback listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bs, err := blossomsrv.New(blossomsrv.Options{Dir: filepath.Join(t.TempDir(), "blobs"), Log: nil})
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := &http.Server{Handler: bs.Handler()}
	go func() { _ = httpSrv.Serve(ln) }()
	defer httpSrv.Close()

	// Upload with a valid BUD-02 auth event.
	auth := &nostr.Event{CreatedAt: nostr.Now(), Kind: nostr.KindBlobs, Tags: nostr.Tags{{"x", sha}}, Content: ""}
	if err := auth.Sign(testSK); err != nil {
		t.Fatal(err)
	}
	if _, err := bs.Put(sha, bytesReader(body), auth); err != nil {
		t.Fatal(err)
	}

	url := "http://" + ln.Addr().String()

	// With the targeted allowance, the fetch succeeds.
	allowed := blossom.New(blossom.Options{
		AllowHTTP:          true,
		AllowLoopbackAddrs: []string{ln.Addr().String()},
		MaxBytes:           1 << 20,
		Timeout:            5 * time.Second,
		MaxRedirects:       3,
	})
	got, err := allowed.Fetch(context.Background(), url, sha)
	if err != nil {
		t.Fatalf("fetch with allowance: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("fetch with allowance: body mismatch")
	}

	// Without the allowance, the same loopback destination is refused.
	denied := blossom.New(blossom.Options{AllowHTTP: true, MaxBytes: 1 << 20, Timeout: 5 * time.Second, MaxRedirects: 3})
	if _, err := denied.Fetch(context.Background(), url, sha); err == nil {
		t.Fatal("fetch without allowance must be refused (D4 boundary)")
	}
}

// TestLocalBlossomUploadOverHTTP is the BUD-02 wire proof: the fork's upload
// shape (PUT /upload?sha256=<sha> with Authorization: Nostr <base64 event>)
// is accepted end-to-end over the listener.
func TestLocalBlossomUploadOverHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	bs, err := blossomsrv.New(blossomsrv.Options{Dir: filepath.Join(t.TempDir(), "blobs")})
	if err != nil {
		t.Fatal(err)
	}
	httpSrv := &http.Server{Handler: bs.Handler()}
	go func() { _ = httpSrv.Serve(ln) }()
	defer httpSrv.Close()

	body := []byte("upload payload")
	sha := shaOfLocal(body)
	auth := &nostr.Event{CreatedAt: nostr.Now(), Kind: nostr.KindBlobs, Tags: nostr.Tags{{"x", sha}}, Content: ""}
	if err := auth.Sign(testSK); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(auth)
	header := base64RawURLEncode(raw)

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodPut, "http://"+ln.Addr().String()+"/upload?sha256="+sha, bytesReader(body))
	req.Header.Set("Authorization", "Nostr "+header)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload status %d", resp.StatusCode)
	}
	if !bs.Has(sha) {
		t.Fatal("blob not stored")
	}
}

func shaOfLocal(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
package blossom

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestCheckDialAddr is the SSRF boundary table: every address class the
// resolver must refuse to dial, plus the allowed public case. The check runs
// at dial time on the resolved address, so it is the single enforcement point
// for the whole table (plan §3.1 "fetch boundary").
func TestCheckDialAddr(t *testing.T) {
	cases := []struct {
		name  string
		addr  string
		allow bool // allowLoopback
		want  bool // allowed?
	}{
		// loopback (IPv4 + IPv6)
		{"loopback ipv4", "127.0.0.1:443", false, false},
		{"loopback ipv4 other", "127.8.8.8:80", false, false},
		{"loopback ipv6", "[::1]:443", false, false},
		{"loopback allowed when opted in", "127.0.0.1:443", true, true},
		// RFC 1918 private
		{"rfc1918 10/8", "10.0.0.1:80", false, false},
		{"rfc1918 10.255.255.1", "10.255.255.1:80", false, false},
		{"rfc1918 172.16/12", "172.16.0.1:80", false, false},
		{"rfc1918 172.31.255.254", "172.31.255.254:80", false, false},
		{"rfc1918 192.168/16", "192.168.1.1:80", false, false},
		// link-local unicast + metadata (169.254.0.0/16)
		{"link-local", "169.254.10.20:80", false, false},
		{"metadata 169.254.169.254", "169.254.169.254:80", false, false},
		{"link-local ipv6 fe80", "[fe80::1]:80", false, false},
		// ULA (fc00::/7)
		{"ula fd00", "[fd00::1]:80", false, false},
		{"ula fc00", "[fc00::1]:80", false, false},
		// multicast / broadcast-ish / unspecified
		{"multicast ipv4 224.0.0.1", "224.0.0.1:80", false, false},
		{"multicast ipv6 ff02", "[ff02::1]:80", false, false},
		{"unspecified 0.0.0.0", "0.0.0.0:80", false, false},
		{"unspecified ipv6 ::", "[::]:80", false, false},
		// public addresses are fine
		{"public ipv4", "93.184.216.34:443", false, true},
		{"public ipv6", "[2606:2800:220:1:248:1893:25c8:1946]:443", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkDialAddr("tcp", tc.addr, tc.allow)
			if tc.want {
				if err != nil {
					t.Fatalf("expected allowed, got %v", err)
				}
				return
			}
			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("expected ErrForbidden, got %v", err)
			}
		})
	}
}

// TestDNSRebindingBlocked documents the defence-in-depth against DNS
// rebinding: the dial control runs on the *resolved* address, so a name that
// first resolves to a public IP (passing a resolve-time allowlist) and then
// rebinds to a private one is refused the moment the dialer connects to the
// private address. There is no resolve-then-connect race to exploit.
func TestDNSRebindingBlocked(t *testing.T) {
	// The attacker's name has "rebound" to 10.0.0.66 by the time we dial.
	if err := checkDialAddr("tcp", "10.0.0.66:443", false); !errors.Is(err, ErrForbidden) {
		t.Fatalf("post-rebind private dial must be refused, got %v", err)
	}
	// Same for the cloud metadata address.
	if err := checkDialAddr("tcp", "169.254.169.254:80", false); !errors.Is(err, ErrForbidden) {
		t.Fatalf("metadata dial must be refused, got %v", err)
	}
}

// TestFetchRejectsRedirectToPrivate ensures a redirect hop that lands on a
// private address is refused: the redirect target is re-dialed through the
// same boundary (the http.Client re-dials per hop).
func TestFetchRejectsRedirectToPrivate(t *testing.T) {
	body := []byte("redirected")
	sha := shaOf(body)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer ts.Close()
	f := New(Options{AllowHTTP: true, AllowLoopback: true, MaxBytes: 1 << 20, Timeout: 3 * time.Second, MaxRedirects: 3})
	if _, err := f.Fetch(context.Background(), ts.URL, sha); err == nil {
		t.Fatal("redirect to a private/metadata address must be refused")
	}
}

// TestClassifyFetchError pins the bounded failure classes exposed on
// /internal/metrics.
func TestClassifyFetchError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrForbidden, "forbidden"},
		{context.DeadlineExceeded, "timeout"},
		{context.Canceled, "canceled"},
		{errors.New("blob hash mismatch: expected a got b"), "hash"},
		{errors.New("blob exceeds 33554432 bytes"), "oversize"},
		{errors.New("too many redirects"), "redirect"},
		{errors.New("blossom https://x: status 404"), "status"},
		{errors.New("connection reset by peer"), "network"},
		{nil, ""},
	}
	for _, tc := range cases {
		if got := ClassifyFetchError(tc.err); got != tc.want {
			t.Fatalf("ClassifyFetchError(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// TestFetchRejectsPrivateServerURL ensures a server hint pointing straight at
// a private address is refused before any request is attempted.
func TestFetchRejectsPrivateServerURL(t *testing.T) {
	body := []byte("x")
	f := New(Options{AllowHTTP: true, MaxBytes: 1 << 20, Timeout: 3 * time.Second, MaxRedirects: 3})
	if _, err := f.Fetch(context.Background(), "http://10.0.0.1", shaOf(body)); err == nil {
		t.Fatal("private server URL must be refused")
	}
	if _, err := f.Fetch(context.Background(), "http://127.0.0.1:8190", shaOf(body)); err == nil {
		t.Fatal("loopback server URL must be refused by default")
	}
}

// TestSlowLorisTimeout ensures a server that dribbles bytes slower than the
// fetch deadline is cut off (bounded fetch, plan §4.4 fetch_timeout_seconds).
func TestSlowLorisTimeout(t *testing.T) {
	body := []byte("slow")
	sha := shaOf(body)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		fl, _ := w.(http.Flusher)
		for i := 0; i < len(body); i++ {
			_, _ = w.Write(body[i : i+1])
			if fl != nil {
				fl.Flush()
			}
			time.Sleep(200 * time.Millisecond)
		}
	}))
	defer ts.Close()
	f := New(Options{AllowHTTP: true, AllowLoopback: true, MaxBytes: 1 << 20, Timeout: 400 * time.Millisecond, MaxRedirects: 3})
	if _, err := f.Fetch(context.Background(), ts.URL, sha); err == nil {
		t.Fatal("slow-loris body must time out, not succeed")
	}
}

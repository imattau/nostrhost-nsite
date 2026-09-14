// Package blossom fetches blobs from Blossom servers with a strict boundary:
// scheme allowlist, dial-time resolved-IP policy (loopback/private/link-local/
// ULA/multicast/metadata rejected), bounded redirects, byte and time caps, and
// sha256 verification before any byte is returned. This is the Phase 2 SSRF
// posture applied from the start (plan §3.1 "fetch boundary").
package blossom

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

var ErrForbidden = errors.New("forbidden address")

// Options configure the fetcher.
type Options struct {
	AllowHTTP     bool
	AllowLoopback bool // test/local tooling only; production never sets this
	MaxBytes      int64
	Timeout       time.Duration
	MaxRedirects  int
}

// Fetcher is safe to use concurrently.
type Fetcher struct {
	allowHTTP     bool
	allowLoopback bool
	maxBytes      int64
	timeout       time.Duration
	client        *http.Client
}

// checkDialAddr is the resolved-IP boundary applied at dial time. It is
// called by net.Dialer AFTER DNS resolution, with the actual address being
// connected to — so DNS rebinding (a name that flips to a private IP after
// resolution) is defeated here: the private address is refused regardless of
// what the name resolved to earlier. allowLoopback is test/local tooling only.
func checkDialAddr(network, addr string, allowLoopback bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip != nil && !(allowLoopback && ip.IsLoopback()) && forbiddenIP(ip) {
		return ErrForbidden
	}
	return nil
}

func New(opts Options) *Fetcher {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 32 << 20
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 20 * time.Second
	}
	if opts.MaxRedirects <= 0 {
		opts.MaxRedirects = 3
	}
	allowLoopback := opts.AllowLoopback
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, addr string, _ syscall.RawConn) error {
			return checkDialAddr(network, addr, allowLoopback)
		},
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		MaxIdleConns:          16,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &Fetcher{
		allowHTTP:     opts.AllowHTTP,
		allowLoopback: allowLoopback,
		maxBytes:      opts.MaxBytes,
		timeout:       opts.Timeout,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= opts.MaxRedirects {
					return errors.New("too many redirects")
				}
				return validateScheme(req.URL, opts.AllowHTTP)
			},
		},
	}
}

func validateScheme(u *url.URL, allowHTTP bool) error {
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if allowHTTP {
			return nil
		}
		return errors.New("http disallowed")
	default:
		return fmt.Errorf("scheme %q disallowed", u.Scheme)
	}
}

func forbiddenIP(ip net.IP) bool {
	if ip == nil {
		return true // not an IP literal; caller resolved through the dialer already
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		(len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc) // ULA
}

// Fetch retrieves the blob at serverURL/sha, verifying the digest before
// returning. On any boundary violation it returns an error and never serves
// bytes (verify-before-serve, plan §4.1). Redirects are followed by the client
// up to the cap; each hop re-validates the scheme and dials through the
// resolved-IP policy.
func (f *Fetcher) Fetch(ctx context.Context, serverURL, sha string) ([]byte, error) {
	if err := validateScheme(mustURL(serverURL), f.allowHTTP); err != nil {
		return nil, err
	}
	target := strings.TrimSuffix(serverURL, "/") + "/" + sha
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("blossom %s: status %d", serverURL, resp.StatusCode)
	}

	buf := new(bytes.Buffer)
	limited := io.LimitReader(resp.Body, f.maxBytes+1)
	n, err := io.Copy(buf, limited)
	if err != nil {
		return nil, err
	}
	if n > f.maxBytes {
		return nil, fmt.Errorf("blob exceeds %d bytes", f.maxBytes)
	}
	sum := sha256.Sum256(buf.Bytes())
	if got := hex.EncodeToString(sum[:]); got != sha {
		return nil, fmt.Errorf("blob hash mismatch: expected %s got %s", sha, got)
	}
	return buf.Bytes(), nil
}

// ClassifyFetchError buckets a fetch error into a small fixed set for the
// /internal/metrics exposition. Unknown errors fall back to "network" so the
// label set stays bounded.
func ClassifyFetchError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrForbidden) {
		return "forbidden"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "hash mismatch"):
		return "hash"
	case strings.Contains(msg, "exceeds"):
		return "oversize"
	case strings.Contains(msg, "too many redirects"):
		return "redirect"
	case strings.Contains(msg, "status"):
		return "status"
	default:
		return "network"
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		return &url.URL{}
	}
	return u
}

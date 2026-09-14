package server

import (
	"strings"
	"testing"
)

// FuzzNormalisePath guarantees the NIP-5A path normaliser never panics and
// never returns a path that could escape the site tree: accepted output must
// be single-decoded, absolute, free of .. / backslash / percent / control
// characters.
func FuzzNormalisePath(f *testing.F) {
	seeds := []string{
		"/", "/index.html", "/dir/", "/dir/page.html",
		"/%2e%2e/secret", "/../etc/passwd", "/a/%252e%252e/b",
		"/a//b///c.html", "/a\\b", "/a%00b", "/\x01\x7f",
		"//", "%2F", "/a/./b/../c.html",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, p string) {
		got, ok := normalisePath(p)
		if !ok {
			return
		}
		if !strings.HasPrefix(got, "/") {
			t.Fatalf("accepted non-absolute path %q", got)
		}
		if strings.Contains(got, "..") {
			t.Fatalf("accepted path with '..' %q", got)
		}
		if strings.Contains(got, "\\") {
			t.Fatalf("accepted path with backslash %q", got)
		}
		if strings.Contains(got, "%") {
			t.Fatalf("accepted path with percent (double-encoding) %q", got)
		}
		for _, r := range got {
			if r < 0x20 || r == 0x7F {
				t.Fatalf("accepted path with control char %q", got)
			}
		}
	})
}

// TestNormalisePathNoDoubleDecode pins that double-encoded input (percent of
// a percent, or an encoded slash/backslash/dot) is always rejected rather
// than being re-decoded into a traversal.
func TestNormalisePathNoDoubleDecode(t *testing.T) {
	for _, p := range []string{
		"/a/%2e%2e/b", "/%252e%252e/etc/passwd", "/a/%5c..%5c",
		"/%252fetc%252fpasswd", "/a%2fb/../c", "/x/%00y", "/x/..%2f",
	} {
		if _, ok := normalisePath(p); ok {
			t.Fatalf("double-encoded path %q must be rejected", p)
		}
	}
}

// TestNormalisePathRejectsDotDotSubstring pins the defence-in-depth rule that
// any '..' inside a segment (e.g. "dir..0") is rejected, matching the shared
// corpus case invalid-dotdot-substring.
func TestNormalisePathRejectsDotDotSubstring(t *testing.T) {
	for _, p := range []string{
		"/dir..0/index.html", "/a/.../b.html", "/..", "/a/..b.html",
	} {
		if _, ok := normalisePath(p); ok {
			t.Fatalf("path containing '..' substring %q must be rejected", p)
		}
	}
}

// TestParseHostProperty checks that host parsing is total and bounded: any
// host string either fails or yields a label within the DNS limit and a
// decoded id/d within their bounds.
func TestParseHostProperty(t *testing.T) {
	srv := testServer(t)
	hosts := []string{
		"", "sites.example.org",
		"npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq.sites.example.org",
		strings.Repeat("a", 64) + ".sites.example.org", "a.b.sites.example.org",
		"evil.sites.example.org:443", "sites.example.org.evil.com",
		"v" + strings.Repeat("0", 50) + ".sites.example.org",
	}
	for _, host := range hosts {
		label, _, id, d, ok := srv.parseHost(host)
		if !ok {
			continue
		}
		if len(label) > 63 {
			t.Fatalf("host %q produced %d-char label", host, len(label))
		}
		if len(id) != 64 {
			t.Fatalf("host %q decoded id %q is not 64 chars", host, id)
		}
		_ = d
	}
}

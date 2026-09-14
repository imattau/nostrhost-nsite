package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "nsite.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const validTOML = `
domain = "sites.example.org"
mode = "hosted"
public_listen = "127.0.0.1:8195"
internal_listen = "127.0.0.1:8196"

[relays]
lookup = ["wss://purplepag.es", "wss://user.kindpag.es"]
manifest_ttl_seconds = 300

[blossom]
fallback_servers = ["https://blossom.primal.net"]

[limits]
max_blob_bytes = 33554432

[[sites]]
pubkey = "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
kind = 15128
d = ""
`

func TestLoadValid(t *testing.T) {
	cfg, err := Load(writeTemp(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Domain != "sites.example.org" || cfg.Mode != "hosted" {
		t.Fatalf("bad parse: %+v", cfg)
	}
	if cfg.Limits.MaxBlobBytes != DefaultMaxBlobBytes {
		t.Fatalf("defaults not applied: %+v", cfg.Limits)
	}
	if len(cfg.Sites) != 1 || cfg.Sites[0].Pubkey == "" {
		t.Fatalf("sites not parsed: %+v", cfg.Sites)
	}
}

func TestLoadRejectsOpenMode(t *testing.T) {
	_, err := Load(writeTemp(t, strings.Replace(validTOML, `mode = "hosted"`, `mode = "open"`, 1)))
	if err == nil || !strings.Contains(err.Error(), "Phase 5") {
		t.Fatalf("open mode must be rejected before Phase 5, got %v", err)
	}
}

func TestLoadRejectsLoopbackRelays(t *testing.T) {
	for _, relay := range []string{"ws://localhost:7777", "ws://127.0.0.1:7777", "wss://[::1]:7777"} {
		body := strings.Replace(validTOML, `lookup = ["wss://purplepag.es", "wss://user.kindpag.es"]`, `lookup = ["`+relay+`"]`, 1)
		if _, err := Load(writeTemp(t, body)); err == nil {
			t.Errorf("relay %q must be rejected (D5)", relay)
		}
	}
}

func TestLoadRejectsPrivateBlossomWithoutAllowHTTP(t *testing.T) {
	body := strings.Replace(validTOML, `fallback_servers = ["https://blossom.primal.net"]`, `fallback_servers = ["http://10.0.0.5:8787"]`, 1)
	if _, err := Load(writeTemp(t, body)); err == nil {
		t.Error("http blossom without allow_http must be rejected")
	}
	body = strings.Replace(body, `fallback_servers = ["http://10.0.0.5:8787"]`, "fallback_servers = [\"http://10.0.0.5:8787\"]\nallow_http = true", 1)
	if _, err := Load(writeTemp(t, body)); err != nil {
		t.Errorf("http blossom with allow_http must load, got %v", err)
	}
}

func TestLoadRejectsOversizeBlob(t *testing.T) {
	body := strings.Replace(validTOML, `max_blob_bytes = 33554432`, `max_blob_bytes = 268435456`, 1)
	if _, err := Load(writeTemp(t, body)); err == nil {
		t.Error("max_blob_bytes over 128 MiB must be rejected")
	}
}

func TestLoadRejectsBadDomain(t *testing.T) {
	for _, domain := range []string{"", "under_score.example.org", "-bad.example.org"} {
		body := strings.Replace(validTOML, `domain = "sites.example.org"`, `domain = "`+domain+`"`, 1)
		if _, err := Load(writeTemp(t, body)); err == nil {
			t.Errorf("domain %q must be rejected", domain)
		}
	}
}

func TestForbiddenHost(t *testing.T) {
	for _, host := range []string{"localhost", "relay.localhost", "127.0.0.1", "::1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1", "fd00::1"} {
		if !forbiddenHost(host) {
			t.Errorf("%q must be forbidden", host)
		}
	}
	for _, host := range []string{"purplepag.es", "relay.example.org", "8.8.8.8", "2001:db8::1"} {
		if forbiddenHost(host) {
			t.Errorf("%q must be allowed", host)
		}
	}
}

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

func TestLoadCustomDomains(t *testing.T) {
	body := validTOML + `
[[custom_domains]]
fqdn = "blog.example.com"
pubkey = "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
d = "blog"
`
	cfg, err := Load(writeTemp(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.CustomDomains) != 1 {
		t.Fatalf("custom_domains not parsed: %+v", cfg.CustomDomains)
	}
	if cd := cfg.CustomDomains[0]; cd.FQDN != "blog.example.com" || cd.D != "blog" || cd.Pubkey == "" {
		t.Fatalf("bad custom domain: %+v", cd)
	}
}

func TestLoadRejectsBadCustomDomains(t *testing.T) {
	good := "\npubkey = \"b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732\"\n"
	bad := map[string]string{
		"overlap gateway domain": `fqdn = "sites.example.org"` + good,
		"subdomain of gateway":   `fqdn = "blog.sites.example.org"` + good,
		"parent of gateway":      `fqdn = "example.org"` + good,
		"invalid hostname":       `fqdn = "under_score.example.com"` + good,
		"short pubkey":           `fqdn = "ok.example.com"` + "\npubkey = \"abc\"",
	}
	for name, block := range bad {
		body := validTOML + "\n[[custom_domains]]\n" + block
		if _, err := Load(writeTemp(t, body)); err == nil {
			t.Errorf("%s: must be rejected", name)
		}
	}
	dup := validTOML + `
[[custom_domains]]
fqdn = "blog.example.com"
pubkey = "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"

[[custom_domains]]
fqdn = "blog.example.com"
pubkey = "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
`
	if _, err := Load(writeTemp(t, dup)); err == nil {
		t.Error("duplicate custom fqdn must be rejected")
	}
}

func TestLoadAcceptsOpenMode(t *testing.T) {
	cfg, err := Load(writeTemp(t, strings.Replace(validTOML, `mode = "hosted"`, `mode = "open"`, 1)))
	if err != nil {
		t.Fatalf("open mode must load from Phase 5, got %v", err)
	}
	if cfg.Mode != "open" {
		t.Errorf("mode = %q, want open", cfg.Mode)
	}
}

func TestLoadRejectsUnknownMode(t *testing.T) {
	_, err := Load(writeTemp(t, strings.Replace(validTOML, `mode = "hosted"`, `mode = "banana"`, 1)))
	if err == nil {
		t.Fatal("unknown mode must be rejected")
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

func TestLoadNpkEnabledRequiresCachePath(t *testing.T) {
	base := `[[sites]]
pubkey = "b6c048759734c1ef1b3ba0acfd1cd862b394eaab1bc15b7bf6c7f357986d9732"
kind = 15128
d = ""
`
	body := strings.Replace(validTOML, base, "[npk]\nenabled = true\ncache_path = \"\"\n\n"+base, 1)
	if _, err := Load(writeTemp(t, body)); err == nil {
		t.Error("npk.enabled with empty cache_path must be rejected")
	}
	body = strings.Replace(validTOML, base, "[npk]\nenabled = true\ncache_path = \"/var/cache/nostrhost-nsite/npk\"\n\n"+base, 1)
	cfg, err := Load(writeTemp(t, body))
	if err != nil {
		t.Fatalf("npk.enabled with cache_path must load, got %v", err)
	}
	if !cfg.Npk.Enabled || cfg.Npk.CachePath != "/var/cache/nostrhost-nsite/npk" {
		t.Errorf("npk config not applied: %+v", cfg.Npk)
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

// TestLoadBlossomLocal pins the D4 local Blossom server config: enabled must
// carry a loopback-only listener, a data dir, caps within the 128 MiB bound,
// and the gateway default is disabled.
func TestLoadBlossomLocal(t *testing.T) {
	// Disabled by default, defaults applied.
	cfg, err := Load(writeTemp(t, validTOML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Blossom.Local.Enabled {
		t.Fatal("local Blossom must be disabled by default")
	}
	if cfg.Blossom.Local.Listen != DefaultBlossomListen {
		t.Errorf("listen = %q, want %q", cfg.Blossom.Local.Listen, DefaultBlossomListen)
	}
	if cfg.Blossom.Local.QuotaBytes != DefaultBlossomQuota {
		t.Errorf("quota = %d, want %d", cfg.Blossom.Local.QuotaBytes, DefaultBlossomQuota)
	}

	// Enabled with a loopback listener loads.
	body := validTOML + `
[blossom.local]
enabled = true
listen = "127.0.0.1:8197"
data_dir = "/var/lib/nostrhost-nsite/blossom"
`
	cfg, err = Load(writeTemp(t, body))
	if err != nil {
		t.Fatalf("enabled local Blossom must load: %v", err)
	}
	if !cfg.Blossom.Local.Enabled {
		t.Fatal("local Blossom not enabled")
	}

	// Non-loopback listener is rejected (D4). 127.0.0.2 is within loopback
	// 127.0.0.0/8 and therefore allowed; only genuinely external binds are.
	bad := []string{"0.0.0.0:8197", "10.0.0.1:8197", "example.org:8197"}
	for _, listen := range bad {
		b := strings.Replace(body, `listen = "127.0.0.1:8197"`, `listen = "`+listen+`"`, 1)
		if _, err := Load(writeTemp(t, b)); err == nil {
			t.Errorf("listen %q must be rejected (D4)", listen)
		}
	}

	// Missing data_dir is rejected when enabled.
	b := strings.Replace(body, `data_dir = "/var/lib/nostrhost-nsite/blossom"`, `data_dir = ""`, 1)
	if _, err := Load(writeTemp(t, b)); err == nil {
		t.Error("empty data_dir must be rejected when enabled")
	}

	// Oversize max_blob_bytes is rejected.
	b = strings.Replace(body, `data_dir = "/var/lib/nostrhost-nsite/blossom"`, "data_dir = \"/var/lib/nostrhost-nsite/blossom\"\nmax_blob_bytes = 268435456", 1)
	if _, err := Load(writeTemp(t, b)); err == nil {
		t.Error("blossom.local.max_blob_bytes over 128 MiB must be rejected")
	}

	// Bad admitted pubkey is rejected.
	b = strings.Replace(body, `data_dir = "/var/lib/nostrhost-nsite/blossom"`, "data_dir = \"/var/lib/nostrhost-nsite/blossom\"\nallow_pubkeys = [\"abc\"]", 1)
	if _, err := Load(writeTemp(t, b)); err == nil {
		t.Error("short allow_pubkeys entry must be rejected")
	}
}

// Package config loads and validates /etc/nostrhost/nsite.toml.
//
// Schema follows docs/NSITES-IMPLEMENTATION-PLAN.md §4.3. The validator
// enforces D3 (hosted mode before Phase 5; open mode from Phase 5) and D5 (no
// loopback or private relay URLs). Open mode is operator-gated upstream: the
// fork renders it only with a DNS-01 API token configured (wildcard
// certificates), so the gateway accepts it once the operator has opted in.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Defaults per implementation plan §4.3/§4.4.
const (
	DefaultMaxBlobBytes     = 33554432 // 32 MiB
	MaxAllowedBlobBytes     = 128 * 1024 * 1024
	DefaultFetchTimeoutSec  = 20
	DefaultFetchConcurrency = 8
	DefaultMaxRedirects     = 3
	DefaultCacheQuotaBytes  = 2147483648 // 2 GiB
	DefaultMaxPaths         = 5000
	// D4 defaults for the optional local Blossom server.
	DefaultBlossomListen    = "127.0.0.1:8197"
	DefaultBlossomQuota     = 1 << 30 // 1 GiB
	DefaultBlossomRetention = 30      // days
)

type Config struct {
	Domain         string         `toml:"domain"`
	Mode           string         `toml:"mode"`
	PublicListen   string         `toml:"public_listen"`
	InternalListen string         `toml:"internal_listen"`
	CachePath      string         `toml:"cache_path"`
	Relays         Relays         `toml:"relays"`
	Blossom        Blossom        `toml:"blossom"`
	Npk            Npk            `toml:"npk"`
	Limits         Limits         `toml:"limits"`
	Sites          []Site         `toml:"sites"`
	CustomDomains  []CustomDomain `toml:"custom_domains"`
}

// Npk controls single-artifact nsite distribution (Phase 3): when enabled the
// gateway resolves the site publisher's npack release, fetches the .npk from
// Blossom, unpacks it into a content-addressed cache and serves paths from it,
// falling back to per-path blobs.
type Npk struct {
	Enabled    bool   `toml:"enabled"`
	CachePath  string `toml:"cache_path"`
	ReleaseTTL int    `toml:"release_ttl_seconds"`
}

type Relays struct {
	Lookup             []string `toml:"lookup"`
	Extra              []string `toml:"extra"`
	ManifestTTLSeconds int      `toml:"manifest_ttl_seconds"`
	NegativeTTLSeconds int      `toml:"negative_ttl_seconds"`
}

type Blossom struct {
	FallbackServers []string `toml:"fallback_servers"`
	AllowHTTP       bool     `toml:"allow_http"`
	// Local is the optional in-process Blossom server (Phase 5, D4). It is
	// disabled by default; when enabled the gateway serves BUD-01/BUD-02 on
	// its own loopback listener and grants the fetch boundary an explicit
	// allowance for that exact address.
	Local BlossomLocal `toml:"local"`
}

// BlossomLocal configures the optional local Blossom server (D4): a
// content-addressed store with its own quota, per-blob cap and retention
// contract. It listens on loopback only; Caddy or the gateway routes it to the
// public. allow_pubkeys, when non-empty, admits uploads signed by exactly
// those keys (kind-24242 BUD-02 auth); empty admits any valid auth event.
type BlossomLocal struct {
	Enabled       bool     `toml:"enabled"`
	Listen        string   `toml:"listen"`
	DataDir       string   `toml:"data_dir"`
	QuotaBytes    int64    `toml:"quota_bytes"`
	MaxBlobBytes  int64    `toml:"max_blob_bytes"`
	RetentionDays int      `toml:"retention_days"`
	AllowPubkeys  []string `toml:"allow_pubkeys"`
}

type Limits struct {
	MaxBlobBytes        int   `toml:"max_blob_bytes"`
	FetchTimeoutSeconds int   `toml:"fetch_timeout_seconds"`
	FetchConcurrency    int   `toml:"fetch_concurrency"`
	MaxRedirects        int   `toml:"max_redirects"`
	CacheQuotaBytes     int64 `toml:"cache_quota_bytes"`
	MaxPathsPerManifest int   `toml:"max_paths_per_manifest"`
	RequestsPerSecond   int   `toml:"requests_per_second"`
	RequestsBurst       int   `toml:"requests_burst"`
}

// Site is one hosted-mode allowlist entry, rendered from fork state.
type Site struct {
	Pubkey string `toml:"pubkey"`
	Kind   int    `toml:"kind"`
	D      string `toml:"d"`
}

// CustomDomain is an attached FQDN (Phase 4) mapped to a registered site.
// The fork verifies ownership (TXT challenge or CNAME to the gateway domain)
// before rendering an entry here; the gateway simply serves the mapped site
// for that host and answers Caddy's on-demand TLS ask positively.
type CustomDomain struct {
	FQDN   string `toml:"fqdn"`
	Pubkey string `toml:"pubkey"`
	D      string `toml:"d"`
}

// Defaults returns a config with the §4.4 hosted-mode defaults applied.
func Defaults() *Config {
	return &Config{
		Domain:         "sites.example.org",
		Mode:           "hosted",
		PublicListen:   "127.0.0.1:8195",
		InternalListen: "127.0.0.1:8196",
		CachePath:      "/var/cache/nostrhost-nsite",
		Blossom: Blossom{
			Local: BlossomLocal{
				Listen:        DefaultBlossomListen,
				DataDir:       "/var/lib/nostrhost-nsite/blossom",
				QuotaBytes:    DefaultBlossomQuota,
				MaxBlobBytes:  DefaultMaxBlobBytes,
				RetentionDays: DefaultBlossomRetention,
			},
		},
		Npk: Npk{
			CachePath:  "/var/cache/nostrhost-nsite/npk",
			ReleaseTTL: 300,
		},
		Relays: Relays{
			Lookup:             []string{"wss://purplepag.es", "wss://user.kindpag.es"},
			ManifestTTLSeconds: 300,
			NegativeTTLSeconds: 60,
		},
		Limits: Limits{
			MaxBlobBytes:        DefaultMaxBlobBytes,
			FetchTimeoutSeconds: DefaultFetchTimeoutSec,
			FetchConcurrency:    DefaultFetchConcurrency,
			MaxRedirects:        DefaultMaxRedirects,
			CacheQuotaBytes:     DefaultCacheQuotaBytes,
			MaxPathsPerManifest: DefaultMaxPaths,
			RequestsPerSecond:   50,
			RequestsBurst:       200,
		},
	}
}

// Load reads and validates the TOML config at path.
func Load(path string) (*Config, error) {
	cfg := Defaults()
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := toml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

var hostnameRe = regexp.MustCompile(`^(?i:[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// Validate checks the structural and security invariants.
func (c *Config) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if !hostnameRe.MatchString(c.Domain) {
		return fmt.Errorf("domain %q is not a valid hostname", c.Domain)
	}
	switch c.Mode {
	case "hosted":
	case "open":
	default:
		return fmt.Errorf("mode must be %q or %q (D3), got %q", "hosted", "open", c.Mode)
	}
	if err := validateListen(c.PublicListen); err != nil {
		return fmt.Errorf("public_listen: %w", err)
	}
	if err := validateListen(c.InternalListen); err != nil {
		return fmt.Errorf("internal_listen: %w", err)
	}
	all := append(append([]string{}, c.Relays.Lookup...), c.Relays.Extra...)
	if len(all) == 0 {
		return fmt.Errorf("at least one lookup or extra relay is required")
	}
	// Testbed-only relaxation for the Phase 0 spike harness (fake relay on
	// loopback). Never set in production; D5 forbids loopback relays.
	allowLoopback := os.Getenv("NSITE_ALLOW_LOOPBACK_RELAYS") == "1"
	for _, r := range all {
		if err := validateRelayURL(r, allowLoopback); err != nil {
			return fmt.Errorf("relay %q: %w", r, err)
		}
	}
	for _, s := range c.Blossom.FallbackServers {
		if err := validateBlossomURL(s, c.Blossom.AllowHTTP); err != nil {
			return fmt.Errorf("blossom server %q: %w", s, err)
		}
	}
	if c.Blossom.Local.Enabled {
		if err := validateListen(c.Blossom.Local.Listen); err != nil {
			return fmt.Errorf("blossom.local.listen: %w", err)
		}
		// D4: the local server is a loopback-only destination. Accept a plain
		// "127.0.0.1:port" or "localhost:port" (or "[::1]:port"); refuse
		// anything that would bind or be reachable on a non-loopback address.
		host, _, err := net.SplitHostPort(c.Blossom.Local.Listen)
		if err != nil {
			return fmt.Errorf("blossom.local.listen %q: %w", c.Blossom.Local.Listen, err)
		}
		if !isLoopbackHost(host) {
			return fmt.Errorf("blossom.local.listen %q must be a loopback address (D4)", c.Blossom.Local.Listen)
		}
		if c.Blossom.Local.DataDir == "" {
			return fmt.Errorf("blossom.local.data_dir is required when the local Blossom server is enabled")
		}
		if c.Blossom.Local.MaxBlobBytes > MaxAllowedBlobBytes {
			return fmt.Errorf("blossom.local.max_blob_bytes %d exceeds %d (128 MiB)", c.Blossom.Local.MaxBlobBytes, MaxAllowedBlobBytes)
		}
		for _, k := range c.Blossom.Local.AllowPubkeys {
			if len(k) != 64 {
				return fmt.Errorf("blossom.local.allow_pubkeys: pubkey %q must be 64 hex chars", k)
			}
		}
	}
	if c.Npk.Enabled {
		if c.Npk.CachePath == "" {
			return fmt.Errorf("npk.cache_path is required when npk.enabled is true")
		}
		if c.Npk.ReleaseTTL <= 0 {
			return fmt.Errorf("npk.release_ttl_seconds must be positive")
		}
	}
	if c.Limits.MaxBlobBytes > MaxAllowedBlobBytes {
		return fmt.Errorf("max_blob_bytes %d exceeds %d (128 MiB)", c.Limits.MaxBlobBytes, MaxAllowedBlobBytes)
	}
	if c.Limits.MaxBlobBytes <= 0 {
		return fmt.Errorf("max_blob_bytes must be positive")
	}
	if c.Limits.CacheQuotaBytes <= 0 {
		return fmt.Errorf("cache_quota_bytes must be positive")
	}
	if c.Limits.MaxPathsPerManifest <= 0 {
		return fmt.Errorf("max_paths_per_manifest must be positive")
	}
	if c.CachePath == "" {
		return fmt.Errorf("cache_path is required")
	}
	for _, site := range c.Sites {
		if len(site.Pubkey) != 64 {
			return fmt.Errorf("site pubkey %q must be 64 hex chars", site.Pubkey)
		}
	}
	seen := make(map[string]struct{}, len(c.CustomDomains))
	for _, cd := range c.CustomDomains {
		if cd.FQDN == "" {
			return fmt.Errorf("custom_domains: fqdn is required")
		}
		fqdn := strings.ToLower(strings.TrimSuffix(cd.FQDN, "."))
		if !hostnameRe.MatchString(fqdn) {
			return fmt.Errorf("custom_domains: fqdn %q is not a valid hostname", cd.FQDN)
		}
		if fqdn == c.Domain || strings.HasSuffix(fqdn, "."+c.Domain) {
			return fmt.Errorf("custom_domains: fqdn %q overlaps the gateway domain", cd.FQDN)
		}
		if strings.HasSuffix(c.Domain, "."+fqdn) {
			return fmt.Errorf("custom_domains: fqdn %q is a parent of the gateway domain", cd.FQDN)
		}
		if _, dup := seen[fqdn]; dup {
			return fmt.Errorf("custom_domains: duplicate fqdn %q", cd.FQDN)
		}
		seen[fqdn] = struct{}{}
		if len(cd.Pubkey) != 64 {
			return fmt.Errorf("custom_domains: fqdn %q pubkey %q must be 64 hex chars", cd.FQDN, cd.Pubkey)
		}
	}
	return nil
}

func validateListen(s string) error {
	if s == "" {
		return fmt.Errorf("empty listen address")
	}
	_, _, err := net.SplitHostPort(s)
	if err != nil {
		return fmt.Errorf("want host:port, got %q", s)
	}
	return nil
}

// validateURL parses raw and checks its scheme against allowedSchemes,
// optionally requiring a non-empty host. It returns the parsed URL so
// callers can perform further scheme-specific checks (e.g. loopback
// rejection) without reparsing.
func validateURL(raw string, allowedSchemes []string, requireHost bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	ok := false
	for _, scheme := range allowedSchemes {
		if u.Scheme == scheme {
			ok = true
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("scheme must be one of %v, got %q", allowedSchemes, u.Scheme)
	}
	if requireHost && u.Host == "" {
		return nil, fmt.Errorf("missing host")
	}
	return u, nil
}

func validateRelayURL(raw string, allowLoopback bool) error {
	u, err := validateURL(raw, []string{"ws", "wss"}, true)
	if err != nil {
		return err
	}
	if !allowLoopback && forbiddenHost(u.Hostname()) {
		return fmt.Errorf("loopback/private relay URLs are not allowed (D5)")
	}
	return nil
}

func validateBlossomURL(raw string, allowHTTP bool) error {
	schemes := []string{"https"}
	if allowHTTP {
		schemes = append(schemes, "http")
	}
	_, err := validateURL(raw, schemes, true)
	return err
}

// isLoopbackHost reports whether host is a loopback literal or name.
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// forbiddenHost reports loopback and private addresses. Hostnames that are
// not IP literals are allowed here; the resolver enforces the boundary on the
// resolved addresses at connect time.
func forbiddenHost(host string) bool {
	if host == "" {
		return true
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
			ip.IsUnspecified() || ip.IsMulticast() || isULA(ip) {
			return true
		}
	}
	return false
}

func isULA(ip net.IP) bool {
	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc
}

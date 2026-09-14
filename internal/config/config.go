// Package config loads and validates /etc/nostrhost/nsite.toml.
//
// Schema follows docs/NSITES-IMPLEMENTATION-PLAN.md §4.3. The validator
// enforces D3 (only "hosted" mode before Phase 5) and D5 (no loopback or
// private relay URLs).
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
)

type Config struct {
	Domain         string         `toml:"domain"`
	Mode           string         `toml:"mode"`
	PublicListen   string         `toml:"public_listen"`
	InternalListen string         `toml:"internal_listen"`
	CachePath      string         `toml:"cache_path"`
	Relays         Relays         `toml:"relays"`
	Blossom        Blossom        `toml:"blossom"`
	Limits         Limits         `toml:"limits"`
	Sites          []Site         `toml:"sites"`
	CustomDomains  []CustomDomain `toml:"custom_domains"`
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
		return fmt.Errorf("mode %q is deferred to Phase 5 (D3)", c.Mode)
	default:
		return fmt.Errorf("mode must be %q (D3), got %q", "hosted", c.Mode)
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

func validateRelayURL(raw string, allowLoopback bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return fmt.Errorf("scheme must be ws or wss, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("missing host")
	}
	if !allowLoopback && forbiddenHost(u.Hostname()) {
		return fmt.Errorf("loopback/private relay URLs are not allowed (D5)")
	}
	return nil
}

func validateBlossomURL(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme == "http" && !allowHTTP {
		return fmt.Errorf("http requires allow_http = true")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("scheme must be https (or http with allow_http), got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("missing host")
	}
	return nil
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

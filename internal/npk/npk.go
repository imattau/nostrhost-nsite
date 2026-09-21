// Package npk adds single-artifact nsite distribution: a site published as a
// signed npack release (kind-9900) whose .npk blob is served as one
// content-addressed bundle instead of per-path Blossom fetches.
//
// The site's kind-15128/35128 manifest remains the authoritative path index
// (labels, registration, allowlist and the per-path sha256 hashes); the npk
// release supplies the transport bundle. The gateway resolves the publisher's
// newest release, fetches the .npk, verifies its sha256, unpacks it into a
// content-addressed cache keyed by the archive hash, and serves individual
// paths from the unpacked tree. Per-path Blossom fetching remains the
// fallback for sites that have no npk release.
package npk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/nbd-wtf/go-nostr"
)

// KindRelease is the npack v1 package release event kind.
const KindRelease = 9900

// NameRoot is the conventional npack package name for a site's root manifest.
// A root site (one per pubkey) is published as publisher/root; named sites use
// their d tag as the package name.
const NameRoot = "root"

// Release is the subset of a kind-9900 release event the gateway needs.
type Release struct {
	Publisher string
	Name      string
	Version   string
	SHA256    string // artifact sha256 (x tag), lowercase hex
	EventID   string
}

// NewestRelease queries the given relays for the newest valid kind-9900
// release of publisher/name and returns its artifact sha256. A release is
// valid when it carries the required x/name/version tags and, if present, has
// not been revoked by a kind-9901 event from the same publisher. Returns
// (nil, nil) when no valid release is found.
func NewestRelease(ctx context.Context, relays []string, publisher, name string) (*Release, error) {
	if len(relays) == 0 {
		return nil, nil
	}
	pool := nostr.NewSimplePool(ctx)
	defer pool.Close("done")

	filter := nostr.Filter{Kinds: []int{KindRelease}, Authors: []string{publisher}}
	var best *nostr.Event
	for hit := range pool.SubManyEose(ctx, relays, nostr.Filters{filter}) {
		if hit.Event == nil {
			continue
		}
		if releaseName(hit.Event) != name {
			continue
		}
		if best != nil && hit.Event.CreatedAt <= best.CreatedAt {
			continue
		}
		best = hit.Event
	}
	if best == nil {
		return nil, nil
	}
	release := parseRelease(best)
	if release == nil {
		return nil, nil
	}
	revoked, err := isRevoked(ctx, relays, publisher, best)
	if err != nil {
		return nil, err
	}
	if revoked {
		return nil, nil
	}
	return release, nil
}

// ParseRelease validates a kind-9900 release event and returns its Release, or
// nil when it is not a release or lacks the core tags.
func ParseRelease(event *nostr.Event) *Release {
	return parseRelease(event)
}

func releaseName(event *nostr.Event) string {
	for _, t := range event.Tags {
		if len(t) >= 2 && t[0] == "name" {
			return t[1]
		}
	}
	return ""
}

func parseRelease(event *nostr.Event) *Release {
	if event == nil || event.Kind != KindRelease {
		return nil
	}
	rel := &Release{Publisher: event.PubKey, EventID: event.ID}
	for _, t := range event.Tags {
		if len(t) < 2 {
			continue
		}
		switch t[0] {
		case "name":
			rel.Name = t[1]
		case "version":
			rel.Version = t[1]
		case "x":
			if len(t[1]) == 64 && isHex(t[1]) {
				rel.SHA256 = strings.ToLower(t[1])
			}
		}
	}
	if rel.Name == "" || rel.Version == "" || !isSHA256(rel.SHA256) {
		return nil
	}
	return rel
}

// isRevoked reports whether the publisher has signed a kind-9901 revocation
// referencing the release event.
func isRevoked(ctx context.Context, relays []string, publisher string, release *nostr.Event) (bool, error) {
	pool := nostr.NewSimplePool(ctx)
	defer pool.Close("done")

	filter := nostr.Filter{Kinds: []int{9901}, Authors: []string{publisher}}
	for hit := range pool.SubManyEose(ctx, relays, nostr.Filters{filter}) {
		if hit.Event == nil {
			continue
		}
		for _, t := range hit.Event.Tags {
			if len(t) >= 2 && t[0] == "e" && t[1] == release.ID {
				return true, nil
			}
		}
	}
	return false, nil
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	return isHex(s)
}

func isHex(s string) bool {
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

// Bundle is one unpacked .npk archive held in the content-addressed store.
type Bundle struct {
	SHA256 string
	root   string
}

// BundleStore stores unpacked npk archives content-addressed by archive sha256
// under dir. A bundle dir is only created after the archive digest has been
// verified and every member has passed the path-traversal check.
type BundleStore struct {
	dir string
}

// NewBundleStore opens (creating if needed) an npk bundle cache under dir.
func NewBundleStore(dir string) (*BundleStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &BundleStore{dir: dir}, nil
}

// Has reports whether a verified bundle with this archive sha256 is unpacked.
func (s *BundleStore) Has(sha string) bool {
	info, err := os.Stat(s.path(sha))
	return err == nil && info.IsDir()
}

// Unpack verifies body's sha256 against sha and extracts it as a tar archive
// (optionally zstd- or gzip-compressed) into the store. Returns the Bundle.
func (s *BundleStore) Unpack(sha string, body []byte) (*Bundle, error) {
	if !isSHA256(sha) {
		return nil, fmt.Errorf("npk bundle sha256 is not 64 hex chars")
	}
	if got := sha256.Sum256(body); hex.EncodeToString(got[:]) != strings.ToLower(sha) {
		return nil, fmt.Errorf("npk archive hash mismatch: expected %s", sha)
	}
	tmp := s.path(sha + ".unpacking")
	if err := os.RemoveAll(tmp); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	reader, err := decompress(body)
	if err != nil {
		return nil, err
	}
	if err := extractTar(reader, tmp); err != nil {
		return nil, err
	}
	dest := s.path(sha)
	if err := os.RemoveAll(dest); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, dest); err != nil {
		return nil, err
	}
	return &Bundle{SHA256: sha, root: dest}, nil
}

// Open reads one file from an unpacked bundle. The path is validated against
// traversal and the .npack metadata directory is never exposed.
func (s *BundleStore) Open(sha, sitePath string) ([]byte, error) {
	bundle, err := s.ensure(sha)
	if err != nil {
		return nil, err
	}
	rel, ok := bundleRel(sitePath)
	if !ok {
		return nil, fmt.Errorf("npk path is not safe: %q", sitePath)
	}
	target := filepath.Join(bundle.root, filepath.FromSlash(rel))
	if err := within(bundle.root, target); err != nil {
		return nil, err
	}
	body, err := os.ReadFile(target)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (s *BundleStore) ensure(sha string) (*Bundle, error) {
	if !s.Has(sha) {
		return nil, fmt.Errorf("npk bundle not unpacked: %s", sha)
	}
	return &Bundle{SHA256: sha, root: s.path(sha)}, nil
}

func (s *BundleStore) path(sha string) string {
	return filepath.Join(s.dir, sha)
}

// bundleRel maps a site path ("/index.html") to the relative path inside the
// unpacked archive root ("index.html"), rejecting traversal and the .npack
// metadata directory.
func bundleRel(sitePath string) (string, bool) {
	if !strings.HasPrefix(sitePath, "/") || strings.Contains(sitePath, "\\") {
		return "", false
	}
	for _, seg := range strings.Split(sitePath, "/") {
		if seg == ".." {
			return "", false
		}
	}
	clean := filepath.Clean(filepath.FromSlash(sitePath))
	if strings.HasPrefix(clean, "..") {
		return "", false
	}
	rel := strings.TrimPrefix(clean, string(filepath.Separator))
	if rel == "" {
		return "", false
	}
	first := strings.SplitN(rel, string(filepath.Separator), 2)[0]
	if first == ".npack" {
		return "", false
	}
	return rel, true
}

func within(root, target string) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	if absTarget != absRoot && !strings.HasPrefix(absTarget, absRoot+string(filepath.Separator)) {
		return fmt.Errorf("npk member escapes bundle root")
	}
	return nil
}

func decompress(body []byte) (io.Reader, error) {
	// npack v1 is a tar archive compressed with zstd. Accept gzip for
	// fixtures and interop.
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		return gzip.NewReader(bytes.NewReader(body))
	}
	// zstd magic: 0x28 0xB5 0x2F 0xFD
	zr, err := zstd.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("npk is not zstd or gzip: %w", err)
	}
	return zr.IOReadCloser(), nil
}

func extractTar(reader io.Reader, dest string) error {
	tr := tar.NewReader(reader)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("npk tar read: %w", err)
		}
		name := filepath.Clean(filepath.FromSlash(hdr.Name))
		if strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			return fmt.Errorf("npk archive contains a path traversal entry: %s", hdr.Name)
		}
		target := filepath.Join(dest, name)
		if err := within(dest, target); err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode)&0o777)
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink, tar.TypeLink, tar.TypeChar, tar.TypeBlock, tar.TypeFifo:
			return fmt.Errorf("npk archive contains a link or special file: %s", hdr.Name)
		default:
			// skip hard-to-classify members (e.g. PAX headers)
		}
	}
	return nil
}

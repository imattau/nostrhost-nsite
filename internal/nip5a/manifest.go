package nip5a

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"

	"github.com/nbd-wtf/go-nostr"
)

// Manifest kinds (NIP-5A).
const (
	KindRoot     = 15128
	KindNamed    = 35128
	KindSnapshot = 5128
)

var (
	reSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reRef    = regexp.MustCompile(`^\d+:[0-9a-f]{64}:[A-Za-z0-9_-]*$`)
)

// Path is one `path` tag mapping an absolute path to a blob hash.
type Path struct {
	Path string
	Hash string
}

// Options tunes validation.
type Options struct {
	// ForbiddenPubkeys may never sign a user manifest (host keys).
	ForbiddenPubkeys map[string]struct{}
	// MaxPaths bounds the accepted `path` tag count (0 = 5000).
	MaxPaths int
}

// Verdict is the result of validating one manifest event.
type Verdict struct {
	Valid         bool
	Errors        []string
	SiteType      SiteType
	Pubkey        string
	EventID       string
	D             string
	Paths         []Path
	AggregateHash string
	Label         string
}

// IsSHA256Hex reports whether s is 64 lowercase hex characters.
func IsSHA256Hex(s string) bool { return reSHA256.MatchString(s) }

// AggregateHash computes the NIP-5A aggregate hash over the given paths.
func AggregateHash(paths []Path) string {
	lines := make([]string, 0, len(paths))
	for _, p := range paths {
		lines = append(lines, p.Hash+" "+p.Path+"\n")
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "")))
	return hex.EncodeToString(sum[:])
}

func tagName(t nostr.Tag) string {
	if len(t) == 0 {
		return ""
	}
	return t[0]
}

func tagValues(tags nostr.Tags, name string) []string {
	var out []string
	for _, t := range tags {
		if tagName(t) == name && len(t) > 1 {
			out = append(out, t[1])
		}
	}
	return out
}

func filterTags(tags nostr.Tags, name string) nostr.Tags {
	var out nostr.Tags
	for _, t := range tags {
		if tagName(t) == name {
			out = append(out, t)
		}
	}
	return out
}

func hasPathExtension(path string) bool {
	last := path
	if i := strings.LastIndex(path, "/"); i >= 0 {
		last = path[i+1:]
	}
	return strings.Contains(last, ".") && last != "." && !strings.HasPrefix(last, "..")
}

func badPathChars(path string) bool {
	for _, r := range path {
		if r < 0x20 || r == 0x7F || r == '\\' {
			return true
		}
	}
	for _, seg := range strings.Split(path, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// Validate checks a manifest event against the pinned NIP-5A rules. opts
// carries the forbidden host-key set and the path-count bound. Error codes are
// stable strings shared with the corpus `expect.errors` and the Python
// validator.
func Validate(ev *nostr.Event, opts Options) Verdict {
	maxPaths := opts.MaxPaths
	if maxPaths == 0 {
		maxPaths = 5000
	}
	v := Verdict{Pubkey: ev.PubKey, EventID: ev.ID}

	if !ev.CheckID() {
		v.Errors = []string{"bad_id"}
		return v
	}
	if ok, _ := ev.CheckSignature(); !ok {
		v.Errors = []string{"bad_signature"}
		return v
	}

	errors := []string{}
	if _, forbidden := opts.ForbiddenPubkeys[ev.PubKey]; forbidden {
		errors = append(errors, "forbidden_signer")
	}

	kind := int(ev.Kind)
	switch kind {
	case KindRoot, KindNamed, KindSnapshot:
	default:
		errors = append(errors, "bad_kind")
	}

	dValues := tagValues(ev.Tags, "d")
	if kind == KindNamed {
		if len(dValues) == 0 {
			errors = append(errors, "missing_d")
		} else if len(dValues) > 1 || !IsValidD(dValues[0]) {
			errors = append(errors, "bad_d")
		}
	} else if kind == KindRoot && len(dValues) > 0 {
		errors = append(errors, "d_on_root")
	}

	var pathTags nostr.Tags
	for _, t := range ev.Tags {
		if tagName(t) == "path" {
			pathTags = append(pathTags, t)
		}
	}
	if len(pathTags) == 0 {
		errors = append(errors, "no_paths")
	}

	seen := map[string]bool{}
	var validPaths []Path
	for _, t := range pathTags {
		if len(t) != 3 {
			errors = append(errors, "bad_path_shape")
			continue
		}
		path, blobHash := t[1], t[2]
		switch {
		case !strings.HasPrefix(path, "/"):
			errors = append(errors, "relative_path")
			continue
		case !hasPathExtension(path):
			errors = append(errors, "no_extension")
			continue
		case badPathChars(path):
			errors = append(errors, "bad_path_chars")
			continue
		case !IsSHA256Hex(blobHash):
			errors = append(errors, "bad_hash_hex")
			continue
		}
		if seen[path] {
			errors = append(errors, "duplicate_path")
		}
		seen[path] = true
		validPaths = append(validPaths, Path{Path: path, Hash: blobHash})
	}

	if len(pathTags) > maxPaths {
		errors = append(errors, "oversize_path_count")
	}

	computed := ""
	if len(validPaths) > 0 {
		computed = AggregateHash(validPaths)
	}

	xTags := filterTags(ev.Tags, "x")
	if kind == KindSnapshot {
		if len(xTags) == 0 {
			errors = append(errors, "missing_aggregate_x")
		} else if len(xTags) > 1 {
			errors = append(errors, "multiple_aggregate_x")
		}
	}
	for _, t := range xTags {
		if len(t) != 3 || t[2] != "aggregate" || !IsSHA256Hex(t[1]) {
			errors = append(errors, "bad_x_shape")
		} else if computed != "" && t[1] != computed {
			errors = append(errors, "bad_aggregate_x")
		}
	}

	// The "a" tag (self-reference) and "A" tag (root-of-snapshot reference)
	// are validated together: presence/count of each is checked once, then
	// each tag's shape is checked independently. missing_a covers both "no a
	// tag at all" and "A present without a" (the latter can only happen when
	// aTags is already empty, so it collapses into the same check); the
	// final error list is deduped below, so the two original code paths that
	// both produced missing_a for that case are equivalent to this single
	// check.
	aTags := filterTags(ev.Tags, "a")
	ATags := filterTags(ev.Tags, "A")
	if kind == KindSnapshot || len(aTags) > 0 || len(ATags) > 0 {
		switch {
		case len(aTags) == 0:
			errors = append(errors, "missing_a")
		case len(aTags) > 1:
			errors = append(errors, "multiple_a")
		}
		if len(ATags) > 1 {
			errors = append(errors, "multiple_A")
		}
		if len(aTags) > 0 && len(ATags) == 0 && kind != KindSnapshot {
			errors = append(errors, "missing_A")
		}
		for _, t := range aTags {
			if len(t) < 2 || !reRef.MatchString(t[1]) {
				errors = append(errors, "bad_a_shape")
			}
		}
		for _, t := range ATags {
			if len(t) < 2 || !reRef.MatchString(t[1]) {
				errors = append(errors, "bad_A_shape")
			}
		}
	}

	errors = dedupe(errors)

	v.Errors = errors
	v.Valid = len(errors) == 0
	v.Paths = validPaths
	v.AggregateHash = computed
	if len(dValues) > 0 {
		v.D = dValues[0]
	}

	switch kind {
	case KindRoot:
		v.SiteType = SiteRoot
		if npub, err := NPub(ev.PubKey); err == nil {
			v.Label = npub
		}
	case KindNamed:
		v.SiteType = SiteNamed
		if v.D != "" {
			if label, err := NamedLabel(ev.PubKey, v.D); err == nil {
				v.Label = label
			}
		}
	case KindSnapshot:
		v.SiteType = SiteSnapshot
		if label, err := SnapshotLabel(ev.ID); err == nil {
			v.Label = label
		}
	}
	return v
}

func dedupe(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

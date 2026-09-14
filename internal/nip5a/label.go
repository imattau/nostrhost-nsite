// Package nip5a implements the NIP-5A site manifest rules and the canonical
// host-label codec.
//
// Pinned revision: nostr-protocol/nips@5d6b4322 (5A.md, 2026-06-16). This is
// the Go side of the shared conformance corpus in the parent repo at
// tools/tests/nsites/corpus; the Python validator in
// forks/yunohost/src/nostrhost/nsites/manifest.py must agree with it.
package nip5a

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/nbd-wtf/go-nostr/nip19"
)

// SiteType identifies the three NIP-5A site forms.
type SiteType string

const (
	SiteRoot     SiteType = "root"
	SiteNamed    SiteType = "named"
	SiteSnapshot SiteType = "snapshot"
)

// LabelMaxLen is the DNS label limit; root and named labels both reach it.
const LabelMaxLen = 63

var (
	reB36Fifty = regexp.MustCompile(`^[0-9a-z]{50}$`)
	reNamed    = regexp.MustCompile(`^[0-9a-z]{50}[a-z0-9-]{1,13}$`)
	reD        = regexp.MustCompile(`^[a-z0-9-]{1,13}$`)
)

// Base36Encode32 encodes a 32-byte value (64 hex chars) as exactly 50
// lowercase base36 digits. Every 32-byte value is >= 36**49, so 50 digits
// always fit; leading zeros are padded defensively.
func Base36Encode32(hex32 string) (string, error) {
	b, err := hex.DecodeString(hex32)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("base36: want 64 hex chars (32 bytes), got %q", hex32)
	}
	n := new(big.Int).SetBytes(b)
	s := n.Text(36)
	if len(s) > 50 {
		return "", fmt.Errorf("base36: value exceeds 50 digits")
	}
	return strings.Repeat("0", 50-len(s)) + s, nil
}

// Base36Decode50 decodes exactly 50 lowercase base36 digits to 64 hex chars.
func Base36Decode50(s string) (string, error) {
	if !reB36Fifty.MatchString(s) {
		return "", fmt.Errorf("base36: want exactly 50 base36 chars")
	}
	n, ok := new(big.Int).SetString(s, 36)
	if !ok {
		return "", fmt.Errorf("base36: invalid digits")
	}
	if n.BitLen() > 256 {
		return "", fmt.Errorf("base36: value exceeds 32 bytes")
	}
	var buf [32]byte
	n.FillBytes(buf[:])
	return hex.EncodeToString(buf[:]), nil
}

// IsValidD reports whether a named-site identifier matches the NIP's rule.
func IsValidD(d string) bool {
	return reD.MatchString(d) && !strings.HasSuffix(d, "-")
}

// RootLabel returns the canonical root-site label (the author's npub).
func RootLabel(npub string) string { return npub }

// NamedLabel returns the canonical named-site label.
func NamedLabel(pubkeyHex, d string) (string, error) {
	b36, err := Base36Encode32(pubkeyHex)
	if err != nil {
		return "", err
	}
	return b36 + d, nil
}

// SnapshotLabel returns the canonical snapshot label.
func SnapshotLabel(eventIDHex string) (string, error) {
	b36, err := Base36Encode32(eventIDHex)
	if err != nil {
		return "", err
	}
	return "v" + b36, nil
}

// CanonicalSiteURL joins a label with the gateway domain.
func CanonicalSiteURL(label, gatewayDomain string) string {
	return label + "." + gatewayDomain
}

// DecodeLabel parses the left-most DNS label per NIP-5A "Address Formats":
// npub first, then v<50 base36>, then <50 base36><d>. ok is false when the
// label is not a valid site label (callers must treat that as not-found).
func DecodeLabel(label string) (siteType SiteType, hexID, d string, ok bool) {
	if strings.HasPrefix(label, "npub1") {
		prefix, v, err := nip19.Decode(label)
		if err != nil || prefix != "npub" {
			return "", "", "", false
		}
		pk, isStr := v.(string)
		if !isStr || len(pk) != 64 {
			return "", "", "", false
		}
		return SiteRoot, pk, "", true
	}
	if len(label) == 51 && label[0] == 'v' && reB36Fifty.MatchString(label[1:]) {
		id, err := Base36Decode50(label[1:])
		if err != nil {
			return "", "", "", false
		}
		return SiteSnapshot, id, "", true
	}
	if reNamed.MatchString(label) && !strings.HasSuffix(label, "-") {
		pk, err := Base36Decode50(label[:50])
		if err != nil {
			return "", "", "", false
		}
		return SiteNamed, pk, label[50:], true
	}
	return "", "", "", false
}

// NPub encodes a hex pubkey as an npub, for root labels.
func NPub(pubkeyHex string) (string, error) {
	return nip19.EncodePublicKey(pubkeyHex)
}

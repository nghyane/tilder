package identity

import (
	"bytes"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
)

// RootWraps is the root's own list of the wrapped copies of itself that the
// server keeps (ADR 0021), so a new browser can recover it with the
// recovery code or a synced passkey. The server stores a blob only if its
// digest is in a list the root signed: a device key or a script on the page
// cannot swap a blob for junk and break recovery. Seq only moves forward, so
// an old list (a recovery code since replaced) cannot be put back.
type RootWraps struct {
	Root  RootPublic
	Seq   uint64
	Wraps []RootWrap // sorted by lookup, no two with the same lookup
	At    time.Time
}

// RootWrap names one blob: the key a new browser finds it by, derived from
// the secret that opens it (never the secret), and the blob's SHA-256.
type RootWrap struct {
	Lookup [32]byte
	Digest [32]byte
}

// MaxRootWraps bounds a list: a recovery code and a few passkeys.
const MaxRootWraps = 16

// ErrRootWraps covers every way a list fails to check out.
var ErrRootWraps = errors.New("identity: root wraps list is invalid")

func (w RootWrap) text() string { return b64(w.Lookup[:]) + ":" + b64(w.Digest[:]) }

// Statement is what the root signs. Wraps must be sorted and unique.
func (r RootWraps) Statement() OwnerStatement {
	names := make([]string, len(r.Wraps))
	for i, w := range r.Wraps {
		names[i] = w.text()
	}
	return OwnerStatement{statement("root-wraps",
		[2]string{"user", UserID(r.Root)},
		[2]string{"seq", strconv.FormatUint(r.Seq, 10)},
		[2]string{"wraps", strings.Join(names, ",")},
		[2]string{"at", strconv.FormatInt(r.At.Unix(), 10)})}
}

// SortRootWraps orders wraps as a list carries them.
func SortRootWraps(wraps []RootWrap) []RootWrap {
	out := slices.Clone(wraps)
	slices.SortFunc(out, func(a, b RootWrap) int { return bytes.Compare(a.Lookup[:], b.Lookup[:]) })
	return out
}

// VerifyRootWraps checks a list off the wire against the root it must come
// from: exactly the canonical text (sorted, unique lookups, bounded), signed
// by root.
func VerifyRootWraps(text string, sig []byte, root RootPublic) (RootWraps, error) {
	if len(text) > 128+MaxRootWraps*90 || !strings.HasSuffix(text, "\n") {
		return RootWraps{}, ErrRootWraps
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	keys := []string{"user", "seq", "wraps", "at"}
	if len(lines) != len(keys)+1 || lines[0] != "tilder/root-wraps/v2" {
		return RootWraps{}, ErrRootWraps
	}
	v := make(map[string]string, len(keys))
	for i, key := range keys {
		k, val, ok := strings.Cut(lines[i+1], "=")
		if !ok || k != key {
			return RootWraps{}, ErrRootWraps
		}
		v[key] = val
	}
	seq, err1 := strconv.ParseUint(v["seq"], 10, 64)
	at, err2 := strconv.ParseInt(v["at"], 10, 64)
	if err1 != nil || err2 != nil || v["user"] != UserID(root) || v["wraps"] == "" {
		return RootWraps{}, ErrRootWraps
	}
	names := strings.Split(v["wraps"], ",")
	if len(names) > MaxRootWraps {
		return RootWraps{}, ErrRootWraps
	}
	r := RootWraps{Root: root, Seq: seq, At: time.Unix(at, 0), Wraps: make([]RootWrap, len(names))}
	for i, name := range names {
		lookup, digest, ok := strings.Cut(name, ":")
		l, lerr := base64.RawURLEncoding.Strict().DecodeString(lookup)
		d, derr := base64.RawURLEncoding.Strict().DecodeString(digest)
		if !ok || lerr != nil || derr != nil || len(l) != 32 || len(d) != 32 {
			return RootWraps{}, ErrRootWraps
		}
		copy(r.Wraps[i].Lookup[:], l)
		copy(r.Wraps[i].Digest[:], d)
		if i > 0 && bytes.Compare(r.Wraps[i-1].Lookup[:], r.Wraps[i].Lookup[:]) >= 0 {
			return RootWraps{}, ErrRootWraps
		}
	}
	if r.Statement().Text() != text || !root.Verify(r.Statement(), sig) {
		return RootWraps{}, ErrRootWraps
	}
	return r, nil
}

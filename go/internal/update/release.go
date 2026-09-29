// Package update is how an agent moves to a newer release on its own (ADR
// 0023, after Tailscale's clientupdate/distsign): the server only hosts the
// files; what counts is a signature by the release key, which the release
// root (kept offline) vouched for, and whose public half is built into the
// agent. A release is taken only if it is newer than the running one.
package update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MaxBinary bounds a download: an agent is a few tens of MB.
const MaxBinary = 200 << 20

// ErrRelease covers every way a release fails to check out.
var ErrRelease = errors.New("update: release is not signed by the release key")

// File is one binary of a release.
type File struct {
	Name   string
	SHA256 [32]byte
	Size   int64
}

// Release is a signed list of a version's binaries.
type Release struct {
	Version string
	Files   []File // sorted by name
}

// SigningKey is the root's word that a key may sign releases until NotAfter.
type SigningKey struct {
	Key      ed25519.PublicKey
	NotAfter time.Time
}

// Statement is what the root signs.
func (k SigningKey) Statement() string {
	return "tilder/release-key/v1\nkey=" + base64.RawURLEncoding.EncodeToString(k.Key) +
		"\nnot_after=" + strconv.FormatInt(k.NotAfter.Unix(), 10) + "\n"
}

// Statement is what the signing key signs. Files must be sorted by name.
func (r Release) Statement() string {
	var b strings.Builder
	b.WriteString("tilder/release/v1\nversion=" + r.Version + "\n")
	for _, f := range r.Files {
		b.WriteString("file=" + f.Name + ":" + hex.EncodeToString(f.SHA256[:]) + ":" + strconv.FormatInt(f.Size, 10) + "\n")
	}
	return b.String()
}

// Verify checks a release off the wire: the signing key's statement signed
// by root and unexpired at now, and the release's signed by that key. Both
// texts must be exactly their canonical form.
func Verify(root ed25519.PublicKey, keyText string, keySig []byte, releaseText string, releaseSig []byte, now time.Time) (Release, error) {
	if len(root) != ed25519.PublicKeySize || len(keyText) > 256 || len(releaseText) > 4096 {
		return Release{}, ErrRelease
	}
	if !ed25519.Verify(root, []byte(keyText), keySig) {
		return Release{}, ErrRelease
	}
	key, err := parseKey(keyText)
	if err != nil || !now.Before(key.NotAfter) || !ed25519.Verify(key.Key, []byte(releaseText), releaseSig) {
		return Release{}, ErrRelease
	}
	return parseRelease(releaseText)
}

func parseKey(text string) (SigningKey, error) {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 3 || lines[0] != "tilder/release-key/v1" {
		return SigningKey{}, ErrRelease
	}
	raw, ok1 := strings.CutPrefix(lines[1], "key=")
	unix, ok2 := strings.CutPrefix(lines[2], "not_after=")
	key, err1 := base64.RawURLEncoding.Strict().DecodeString(raw)
	sec, err2 := strconv.ParseInt(unix, 10, 64)
	if !ok1 || !ok2 || err1 != nil || err2 != nil || len(key) != ed25519.PublicKeySize {
		return SigningKey{}, ErrRelease
	}
	k := SigningKey{Key: key, NotAfter: time.Unix(sec, 0)}
	if k.Statement() != text {
		return SigningKey{}, ErrRelease
	}
	return k, nil
}

func parseRelease(text string) (Release, error) {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 2 || lines[0] != "tilder/release/v1" {
		return Release{}, ErrRelease
	}
	version, ok := strings.CutPrefix(lines[1], "version=")
	if !ok || !ValidVersion(version) {
		return Release{}, ErrRelease
	}
	r := Release{Version: version}
	for _, line := range lines[2:] {
		spec, ok := strings.CutPrefix(line, "file=")
		parts := strings.Split(spec, ":")
		if !ok || len(parts) != 3 {
			return Release{}, ErrRelease
		}
		sum, err1 := hex.DecodeString(parts[1])
		size, err2 := strconv.ParseInt(parts[2], 10, 64)
		if err1 != nil || err2 != nil || len(sum) != 32 || size <= 0 || size > MaxBinary || parts[0] == "" {
			return Release{}, ErrRelease
		}
		f := File{Name: parts[0], Size: size}
		copy(f.SHA256[:], sum)
		r.Files = append(r.Files, f)
	}
	if !slices.IsSortedFunc(r.Files, func(a, b File) int { return strings.Compare(a.Name, b.Name) }) || r.Statement() != text {
		return Release{}, ErrRelease
	}
	return r, nil
}

// File finds the binary for name.
func (r Release) File(name string) (File, bool) {
	i := slices.IndexFunc(r.Files, func(f File) bool { return f.Name == name })
	if i < 0 {
		return File{}, false
	}
	return r.Files[i], true
}

// ValidVersion is a release version: three numbers, as `make release` takes it.
func ValidVersion(v string) bool {
	_, ok := parseVersion(v)
	return ok
}

func parseVersion(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p != strconv.Itoa(n) {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// Newer reports whether candidate is a later version than running. A
// running version that is not a release (a dev build) is never updated.
func Newer(candidate, running string) bool {
	c, ok1 := parseVersion(candidate)
	r, ok2 := parseVersion(running)
	return ok1 && ok2 && slices.Compare(c[:], r[:]) > 0
}

// SameBytes reports whether data is the file the release names.
func (f File) SameBytes(sum [32]byte, size int64) bool {
	return size == f.Size && bytes.Equal(sum[:], f.SHA256[:])
}

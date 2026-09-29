package identity

import (
	"bytes"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Revocations is the root's list of removed devices (ADR 0004). It only
// grows: every validly signed list is merged into what a verifier already
// holds, so an old list replayed is harmless and a removed device never comes
// back. Devices are named by key, never by a certificate hash (Nebula's
// blocklist was bypassed through a re-encoded signature). Seq orders lists
// for syncing only; the set is what counts.
type Revocations struct {
	Root    RootPublic
	Seq     uint64
	Devices []DevicePublic // sorted, no duplicates
	At      time.Time
}

// MaxRevoked bounds a list (Tailscale caps its key authority at 512 keys);
// a longer one is refused before anything is allocated for it.
const MaxRevoked = 4096

// ErrRevocations covers every way a list fails to check out.
var ErrRevocations = errors.New("identity: revocations list is invalid")

// Statement is what the root signs. Devices must be sorted and unique.
func (r Revocations) Statement() OwnerStatement {
	names := make([]string, len(r.Devices))
	for i, d := range r.Devices {
		names[i] = b64(d.k[:])
	}
	return OwnerStatement{statement("revocations",
		[2]string{"user", UserID(r.Root)},
		[2]string{"seq", strconv.FormatUint(r.Seq, 10)},
		[2]string{"devices", strings.Join(names, ",")},
		[2]string{"at", strconv.FormatInt(r.At.Unix(), 10)})}
}

// SortDevices orders keys as a list carries them and drops duplicates.
func SortDevices(devices []DevicePublic) []DevicePublic {
	out := slices.Clone(devices)
	slices.SortFunc(out, func(a, b DevicePublic) int { return bytes.Compare(a.k[:], b.k[:]) })
	return slices.CompactFunc(out, func(a, b DevicePublic) bool { return a == b })
}

// Has reports whether d is in the list.
func (r Revocations) Has(d DevicePublic) bool {
	_, found := slices.BinarySearchFunc(r.Devices, d, func(a, b DevicePublic) int { return bytes.Compare(a.k[:], b.k[:]) })
	return found
}

// VerifyRevocations checks a list off the wire against the root it must come
// from: exactly the canonical text (sorted, unique, bounded), signed by root.
func VerifyRevocations(text string, sig []byte, root RootPublic) (Revocations, error) {
	if len(text) > 64+MaxRevoked*44 || !strings.HasSuffix(text, "\n") {
		return Revocations{}, ErrRevocations
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	keys := []string{"user", "seq", "devices", "at"}
	if len(lines) != len(keys)+1 || lines[0] != "tilder/revocations/v2" {
		return Revocations{}, ErrRevocations
	}
	v := make(map[string]string, len(keys))
	for i, key := range keys {
		k, val, ok := strings.Cut(lines[i+1], "=")
		if !ok || k != key {
			return Revocations{}, ErrRevocations
		}
		v[key] = val
	}
	seq, err1 := strconv.ParseUint(v["seq"], 10, 64)
	at, err2 := strconv.ParseInt(v["at"], 10, 64)
	if err1 != nil || err2 != nil {
		return Revocations{}, ErrRevocations
	}
	r := Revocations{Root: root, Seq: seq, At: time.Unix(at, 0)}
	if v["devices"] != "" {
		names := strings.Split(v["devices"], ",")
		if len(names) > MaxRevoked {
			return Revocations{}, ErrRevocations
		}
		for _, name := range names {
			raw, err := fromB64(name)
			if err != nil {
				return Revocations{}, ErrRevocations
			}
			d, err := DevicePublicFromBytes(raw)
			if err != nil {
				return Revocations{}, ErrRevocations
			}
			r.Devices = append(r.Devices, d)
		}
	}
	// Canonical: the list as sorted and deduplicated must be the text itself.
	canon := r
	canon.Devices = SortDevices(r.Devices)
	if canon.Statement().Text() != text || !root.Verify(OwnerStatement{text: []byte(text)}, sig) {
		return Revocations{}, ErrRevocations
	}
	return canon, nil
}

// Merge adds other's devices to r's (the set only grows) and keeps the higher
// seq, as the cursor to sync from.
func (r Revocations) Merge(other Revocations) Revocations {
	out := r
	out.Devices = SortDevices(append(slices.Clone(r.Devices), other.Devices...))
	if other.Seq > out.Seq {
		out.Seq, out.At = other.Seq, other.At
	}
	return out
}

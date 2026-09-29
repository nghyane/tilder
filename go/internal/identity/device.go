package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// DeviceStatement is signed by a device key (ADR 0004): the everyday
// signatures of a browser, each checked together with its device-cert.
type DeviceStatement struct{ text []byte }

// Text is the exact signed bytes, for vectors and debugging.
func (s DeviceStatement) Text() string { return string(s.text) }

// DevicePrivate is a device's signing key. Real devices are browsers whose
// keys never leave WebCrypto; Go holds one only to write test vectors.
type DevicePrivate struct {
	_ incomparable
	k ed25519.PrivateKey
}

// NewDevicePrivate draws a key from rand.
func NewDevicePrivate(rand io.Reader) (DevicePrivate, error) {
	_, k, err := ed25519.GenerateKey(rand)
	return DevicePrivate{k: k}, err
}

// DevicePrivateFromSeed restores a key from its 32-byte seed.
func DevicePrivateFromSeed(seed []byte) (DevicePrivate, error) {
	if len(seed) != ed25519.SeedSize {
		return DevicePrivate{}, errMalformedKey
	}
	return DevicePrivate{k: ed25519.NewKeyFromSeed(seed)}, nil
}

// Public returns the matching public key.
func (k DevicePrivate) Public() DevicePublic { return DevicePublic{k: publicHalf(k.k)} }

// Sign signs a statement; only a device key signs these kinds.
func (k DevicePrivate) Sign(s DeviceStatement) []byte { return ed25519.Sign(k.k, s.text) }

// Verify checks a device-signed statement against the key it must come from.
func (k DevicePublic) Verify(s DeviceStatement, sig []byte) bool {
	return ed25519.Verify(k.k[:], s.text, sig)
}

// DevicePublicFromBytes parses a raw key off the wire.
func DevicePublicFromBytes(b []byte) (DevicePublic, error) {
	k, err := publicFromBytes(b)
	return DevicePublic{k: k}, err
}

const (
	// MaxCertLifetime bounds a device-cert even when validly signed: a
	// longer one is refused (ADR 0004).
	MaxCertLifetime = 90 * 24 * time.Hour
	// ClockSkew is how far a verifier's clock may disagree with the
	// issuer's. The verifier's own clock is the reference, never a
	// server's.
	ClockSkew = 5 * time.Minute
)

// DeviceCert is the root's word that a device key belongs to the owner, for
// a bounded time (ADR 0004). The validity is inside the signature: a server
// cannot extend it (Tailscale's key expiry is set by control, unsigned).
type DeviceCert struct {
	Root   RootPublic
	Device DevicePublic
	// NameHash is the SHA-256 of the device's name: the name stays in the
	// owner's encrypted directory, the cert only binds to it.
	NameHash [32]byte
	// RevSeq is the newest revocations seq the issuer knew: a verifier that
	// knows less must catch up before it trusts new grants.
	RevSeq    uint64
	NotBefore time.Time
	NotAfter  time.Time
}

// User is the user the cert speaks for, derived from its root.
func (c DeviceCert) User() string { return UserID(c.Root) }

// Statement is what the root signs.
func (c DeviceCert) Statement() OwnerStatement {
	return OwnerStatement{statement("device-cert",
		[2]string{"user", c.User()},
		[2]string{"root", b64(c.Root.k[:])},
		[2]string{"device", b64(c.Device.k[:])},
		[2]string{"name_hash", b64(c.NameHash[:])},
		[2]string{"rev_seq", strconv.FormatUint(c.RevSeq, 10)},
		[2]string{"not_before", strconv.FormatInt(c.NotBefore.Unix(), 10)},
		[2]string{"not_after", strconv.FormatInt(c.NotAfter.Unix(), 10)})}
}

// NameHash hashes a device's name as a cert binds it.
func NameHash(name string) [32]byte { return sha256.Sum256([]byte("tilder/device-name/v2\n" + name)) }

// Errors a cert check returns; callers map them to one stable refusal.
var (
	ErrCertMalformed = errors.New("identity: device-cert is malformed")
	ErrCertSignature = errors.New("identity: device-cert is not signed by its root")
	ErrCertLifetime  = errors.New("identity: device-cert lasts longer than allowed")
	ErrCertNotYet    = errors.New("identity: device-cert is not valid yet")
	ErrCertExpired   = errors.New("identity: device-cert has expired")
)

// maxCertText bounds what is parsed: a cert is a few hundred bytes.
const maxCertText = 1024

// VerifyDeviceCert checks a cert off the wire at now (the verifier's clock):
// strictly formed, signed by the root it names, no longer than
// MaxCertLifetime, and valid at now within ClockSkew. The signature is
// checked over the received bytes, which must also be exactly the canonical
// form (Nebula verifies the raw details it received, not a re-encoding).
func VerifyDeviceCert(text string, sig []byte, now time.Time) (DeviceCert, error) {
	c, err := parseDeviceCert(text)
	if err != nil {
		return DeviceCert{}, err
	}
	if !c.Root.Verify(OwnerStatement{text: []byte(text)}, sig) {
		return DeviceCert{}, ErrCertSignature
	}
	switch life := c.NotAfter.Sub(c.NotBefore); {
	case life <= 0 || life > MaxCertLifetime:
		return DeviceCert{}, ErrCertLifetime
	case now.Add(ClockSkew).Before(c.NotBefore):
		return DeviceCert{}, ErrCertNotYet
	case now.Add(-ClockSkew).After(c.NotAfter):
		return DeviceCert{}, ErrCertExpired
	}
	return c, nil
}

// parseDeviceCert reads the exact canonical form: the kind line, then the
// seven fields in order, nothing else. Anything off is malformed.
func parseDeviceCert(text string) (DeviceCert, error) {
	if len(text) > maxCertText || !strings.HasSuffix(text, "\n") {
		return DeviceCert{}, ErrCertMalformed
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	keys := []string{"user", "root", "device", "name_hash", "rev_seq", "not_before", "not_after"}
	if len(lines) != len(keys)+1 || lines[0] != "tilder/device-cert/v2" {
		return DeviceCert{}, ErrCertMalformed
	}
	v := make(map[string]string, len(keys))
	for i, key := range keys {
		k, val, ok := strings.Cut(lines[i+1], "=")
		if !ok || k != key {
			return DeviceCert{}, ErrCertMalformed
		}
		v[key] = val
	}
	var c DeviceCert
	var err error
	if c.Root, err = parseKey(v["root"], RootPublicFromBytes); err != nil {
		return DeviceCert{}, err
	}
	if c.Device, err = parseKey(v["device"], DevicePublicFromBytes); err != nil {
		return DeviceCert{}, err
	}
	nameHash, err := fromB64(v["name_hash"])
	if err != nil || len(nameHash) != len(c.NameHash) {
		return DeviceCert{}, ErrCertMalformed
	}
	copy(c.NameHash[:], nameHash)
	if c.RevSeq, err = strconv.ParseUint(v["rev_seq"], 10, 64); err != nil {
		return DeviceCert{}, ErrCertMalformed
	}
	notBefore, err1 := strconv.ParseInt(v["not_before"], 10, 64)
	notAfter, err2 := strconv.ParseInt(v["not_after"], 10, 64)
	if err1 != nil || err2 != nil {
		return DeviceCert{}, ErrCertMalformed
	}
	c.NotBefore, c.NotAfter = time.Unix(notBefore, 0), time.Unix(notAfter, 0)
	// The canonical form, rebuilt, must be the received text: no leading
	// zeros, no "+1", no padding, and the user must be the root's.
	if c.Statement().Text() != text {
		return DeviceCert{}, ErrCertMalformed
	}
	return c, nil
}

func parseKey[K any](s string, from func([]byte) (K, error)) (K, error) {
	var zero K
	raw, err := fromB64(s)
	if err != nil {
		return zero, ErrCertMalformed
	}
	k, err := from(raw)
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrCertMalformed, err)
	}
	return k, nil
}

// fromB64 decodes one canonical spelling only (see parse in keys.go).
func fromB64(s string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != s {
		return nil, ErrCertMalformed
	}
	return raw, nil
}

package identity

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

// RootPrivate is the owner's signing key. In P1 the console holds it and it
// signs offers directly; from P3 it only certifies device keys (ADR 0004).
type RootPrivate struct {
	_ incomparable
	k ed25519.PrivateKey
}

// MachinePrivate is an agent's signing key.
type MachinePrivate struct {
	_ incomparable
	k ed25519.PrivateKey
}

// incomparable makes == on private keys a compile error: comparing secrets
// must be constant-time, and nothing here needs to compare them at all.
type incomparable [0]func()

// NewRootPrivate draws a key from rand (crypto/rand.Reader in production).
func NewRootPrivate(rand io.Reader) (RootPrivate, error) {
	_, k, err := ed25519.GenerateKey(rand)
	return RootPrivate{k: k}, err
}

// NewMachinePrivate draws a key from rand (crypto/rand.Reader in production).
func NewMachinePrivate(rand io.Reader) (MachinePrivate, error) {
	_, k, err := ed25519.GenerateKey(rand)
	return MachinePrivate{k: k}, err
}

// MachinePrivateFromSeed restores a key from its 32-byte seed (the file form).
func MachinePrivateFromSeed(seed []byte) (MachinePrivate, error) {
	if len(seed) != ed25519.SeedSize {
		return MachinePrivate{}, errMalformedKey
	}
	return MachinePrivate{k: ed25519.NewKeyFromSeed(seed)}, nil
}

// RootPrivateFromSeed restores a key from its 32-byte seed.
func RootPrivateFromSeed(seed []byte) (RootPrivate, error) {
	if len(seed) != ed25519.SeedSize {
		return RootPrivate{}, errMalformedKey
	}
	return RootPrivate{k: ed25519.NewKeyFromSeed(seed)}, nil
}

// Seed is the 32 bytes the key file stores.
func (k MachinePrivate) Seed() []byte { return k.k.Seed() }

// Public returns the matching public key.
func (k RootPrivate) Public() RootPublic { return RootPublic{k: publicHalf(k.k)} }

// Public returns the matching public key.
func (k MachinePrivate) Public() MachinePublic { return MachinePublic{k: publicHalf(k.k)} }

// publicHalf reads the public key an ed25519 private key carries in its
// second half (crypto/ed25519's documented layout), with no type assertion.
func publicHalf(k ed25519.PrivateKey) [publicKeySize]byte {
	var out [publicKeySize]byte
	copy(out[:], k[ed25519.SeedSize:])
	return out
}

// Sign signs a statement; only the owner key signs these kinds.
func (k RootPrivate) Sign(s OwnerStatement) []byte { return ed25519.Sign(k.k, s.text) }

// Sign signs a statement; only a machine key signs these kinds.
func (k MachinePrivate) Sign(s MachineStatement) []byte { return ed25519.Sign(k.k, s.text) }

// Verify checks an owner-signed statement against the key it must come from.
func (k RootPublic) Verify(s OwnerStatement, sig []byte) bool {
	return ed25519.Verify(k.k[:], s.text, sig)
}

// Verify checks a machine-signed statement against the key it must come from.
func (k MachinePublic) Verify(s MachineStatement, sig []byte) bool {
	return ed25519.Verify(k.k[:], s.text, sig)
}

// MachineID names a machine: derived from its key, so a registration can
// never claim an id that belongs to another key (headscale's
// machineKeyMismatch, THREAT_MODEL "machine id takeover").
func MachineID(k MachinePublic) string {
	sum := sha256.Sum256(append([]byte("tilder/machine-id/v2\n"), k.k[:]...))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// UserID names a user by their owner key, the same way.
func UserID(k RootPublic) string {
	sum := sha256.Sum256(append([]byte("tilder/user-id/v2\n"), k.k[:]...))
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// PublicFromBytes parses a raw 32-byte key off the wire.
func publicFromBytes(b []byte) ([publicKeySize]byte, error) {
	var out [publicKeySize]byte
	if len(b) != publicKeySize {
		return out, fmt.Errorf("identity: public key is %d bytes, want %d", len(b), publicKeySize)
	}
	copy(out[:], b)
	return out, nil
}

// RootPublicFromBytes parses a raw key off the wire.
func RootPublicFromBytes(b []byte) (RootPublic, error) {
	k, err := publicFromBytes(b)
	return RootPublic{k: k}, err
}

// MachinePublicFromBytes parses a raw key off the wire.
func MachinePublicFromBytes(b []byte) (MachinePublic, error) {
	k, err := publicFromBytes(b)
	return MachinePublic{k: k}, err
}

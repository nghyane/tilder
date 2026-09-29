// Package identity holds tilder's key types and the statements they sign.
//
// Each key kind is its own type over an unexported array, so a device key can
// never be passed where a root key is expected (the pattern of
// tailscale.com/types/key). The text form carries a kind prefix that parsing
// checks, and parse errors never echo their input: it might be a secret.
//
// This package is pure: no I/O, no network, no clock (depguard enforces it).
package identity

import (
	"encoding/base64"
	"errors"
	"strings"
)

const publicKeySize = 32

var errMalformedKey = errors.New("identity: malformed key")

// RootPublic is the public half of a user's root key: it signs device
// certificates and fleet changes, never day-to-day traffic.
type RootPublic struct{ k [publicKeySize]byte }

// DevicePublic is the public half of one browser's non-extractable key.
type DevicePublic struct{ k [publicKeySize]byte }

// MachinePublic is the public half of one agent's key.
type MachinePublic struct{ k [publicKeySize]byte }

const (
	rootPrefix    = "broot:"
	devicePrefix  = "bdev:"
	machinePrefix = "bmach:"
)

// RootPublicFromRaw32 wraps raw key bytes. Raw bytes enter only through these
// explicit constructors.
func RootPublicFromRaw32(raw [publicKeySize]byte) RootPublic { return RootPublic{k: raw} }

// DevicePublicFromRaw32 wraps raw key bytes.
func DevicePublicFromRaw32(raw [publicKeySize]byte) DevicePublic { return DevicePublic{k: raw} }

// MachinePublicFromRaw32 wraps raw key bytes.
func MachinePublicFromRaw32(raw [publicKeySize]byte) MachinePublic { return MachinePublic{k: raw} }

// Raw32 returns the key bytes.
func (k RootPublic) Raw32() [publicKeySize]byte { return k.k }

// Raw32 returns the key bytes.
func (k DevicePublic) Raw32() [publicKeySize]byte { return k.k }

// Raw32 returns the key bytes.
func (k MachinePublic) Raw32() [publicKeySize]byte { return k.k }

func (k RootPublic) String() string    { return format(rootPrefix, k.k) }
func (k DevicePublic) String() string  { return format(devicePrefix, k.k) }
func (k MachinePublic) String() string { return format(machinePrefix, k.k) }

// ParseRootPublic reads the form String writes.
func ParseRootPublic(s string) (RootPublic, error) {
	k, err := parse(rootPrefix, s)
	return RootPublic{k: k}, err
}

// ParseDevicePublic reads the form String writes.
func ParseDevicePublic(s string) (DevicePublic, error) {
	k, err := parse(devicePrefix, s)
	return DevicePublic{k: k}, err
}

// ParseMachinePublic reads the form String writes.
func ParseMachinePublic(s string) (MachinePublic, error) {
	k, err := parse(machinePrefix, s)
	return MachinePublic{k: k}, err
}

func format(prefix string, k [publicKeySize]byte) string {
	return prefix + base64.RawURLEncoding.EncodeToString(k[:])
}

func parse(prefix, s string) ([publicKeySize]byte, error) {
	var out [publicKeySize]byte
	body, ok := strings.CutPrefix(s, prefix)
	if !ok {
		return out, errMalformedKey
	}
	// Exactly one spelling per key: a second spelling of the same key would
	// be a second identity. The decoder skips \r and \n (the fuzzer found
	// it), so the input must equal its own re-encoding.
	raw, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil || len(raw) != publicKeySize ||
		base64.RawURLEncoding.EncodeToString(raw) != body {
		return out, errMalformedKey
	}
	copy(out[:], raw)
	return out, nil
}

// Package identitytest builds an owner and one of their devices for tests:
// a root, a device key, and the root's certificate for it (ADR 0004).
package identitytest

import (
	"bytes"
	"testing"
	"time"

	"github.com/nghyane/tilder/go/internal/identity"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// Device is one owner's device: its root, its key and its certificate.
type Device struct {
	Root identity.RootPrivate
	Key  identity.DevicePrivate
	Cert identity.DeviceCert
}

// NewDevice derives a root from rootSeed and a device from deviceSeed, and
// certifies the device for 30 days from an hour before now.
func NewDevice(tb testing.TB, rootSeed, deviceSeed byte, now time.Time) Device {
	tb.Helper()
	root, err := identity.RootPrivateFromSeed(bytes.Repeat([]byte{rootSeed}, 32))
	if err != nil {
		tb.Fatal(err)
	}
	key, err := identity.DevicePrivateFromSeed(bytes.Repeat([]byte{deviceSeed}, 32))
	if err != nil {
		tb.Fatal(err)
	}
	return Device{Root: root, Key: key, Cert: identity.DeviceCert{
		Root: root.Public(), Device: key.Public(), NameHash: identity.NameHash("test"),
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(30 * 24 * time.Hour),
	}}
}

// Certificate is the wire form of d's certificate, signed by d's root.
func (d Device) Certificate() *tilderv1.DeviceCertificate {
	s := d.Cert.Statement()
	return &tilderv1.DeviceCertificate{Statement: s.Text(), Signature: d.Root.Sign(s)}
}

// PublicKey is d's key as the wire carries it.
func (d Device) PublicKey() []byte {
	raw := d.Key.Public().Raw32()
	return raw[:]
}

// Hello is d's signed hello for a server nonce.
func (d Device) Hello(nonce []byte) *tilderv1.DeviceHello {
	return &tilderv1.DeviceHello{
		Hello: &tilderv1.Hello{Protocol: 1}, PublicKey: d.PublicKey(),
		Signature: d.Key.Sign(identity.DeviceHelloStatement(nonce, d.Key.Public())), DeviceCertificate: d.Certificate(),
	}
}

// User is d's user id.
func (d Device) User() string { return identity.UserID(d.Root.Public()) }

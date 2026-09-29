package identity_test

import (
	"testing"

	"go.uber.org/goleak"

	"github.com/nghyane/tilder/go/internal/identity"
	"github.com/nghyane/tilder/go/internal/testutil"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, testutil.GoleakOptions...)
}

func TestKeysRoundTripThroughTheirOwnPrefixOnly(t *testing.T) {
	t.Parallel()
	raw := [32]byte{1, 2, 3}
	device := identity.DevicePublicFromRaw32(raw)

	back, err := identity.ParseDevicePublic(device.String())
	if err != nil || back != device {
		t.Fatalf("device key did not round-trip: %v", err)
	}
	// A device key is not a root key, even with the same bytes.
	if _, err := identity.ParseRootPublic(device.String()); err == nil {
		t.Fatal("a device key parsed as a root key")
	}
}

func TestAParseErrorNeverEchoesItsInput(t *testing.T) {
	t.Parallel()
	input := "bdev:this-might-be-a-private-key"
	_, err := identity.ParseDevicePublic(input)
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := err.Error(); got != "identity: malformed key" {
		t.Fatalf("error leaks input: %q", got)
	}
}

func FuzzParseNeverPanicsAndOnlyAcceptsWhatItWrites(f *testing.F) {
	f.Add("broot:AQID")
	f.Add("bmach:" + identity.MachinePublicFromRaw32([32]byte{9}).String())
	f.Fuzz(func(t *testing.T, s string) {
		k, err := identity.ParseMachinePublic(s)
		if err == nil && k.String() != s {
			t.Fatalf("accepted a non-canonical form %q", s)
		}
	})
}

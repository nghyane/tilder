package identity_test

import (
	"bytes"
	"testing"

	"github.com/nghyane/tilder/go/internal/identity"
)

func keys(t *testing.T) (identity.RootPrivate, identity.MachinePrivate) {
	t.Helper()
	owner, err := identity.RootPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	machine, err := identity.MachinePrivateFromSeed(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return owner, machine
}

func TestAnOfferVerifiesOnlyAgainstTheDeviceThatSignedIt(t *testing.T) {
	t.Parallel()
	device, err := identity.DevicePrivateFromSeed(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := identity.DevicePrivateFromSeed(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	offer := identity.OfferStatement("m1", []byte("s1"), "v=0")
	sig := device.Sign(offer)
	if !device.Public().Verify(offer, sig) {
		t.Fatal("the device's own offer did not verify")
	}
	if stranger.Public().Verify(offer, sig) {
		t.Fatal("an offer verified against a stranger's key")
	}
}

func TestAnAnswerCannotBeMovedToAnotherOffer(t *testing.T) {
	t.Parallel()
	_, machine := keys(t)
	id := identity.MachineID(machine.Public())
	sig := machine.Sign(identity.AnswerStatement(id, []byte("s1"), "offer-a", "answer"))
	moved := identity.AnswerStatement(id, []byte("s1"), "offer-b", "answer")
	if machine.Public().Verify(moved, sig) {
		t.Fatal("an answer signed for offer-a verified for offer-b")
	}
}

func TestIdsAreDerivedFromKeysAndStable(t *testing.T) {
	t.Parallel()
	owner, machine := keys(t)
	_, again := keys(t)
	if identity.MachineID(machine.Public()) != identity.MachineID(again.Public()) {
		t.Fatal("the same key gave two machine ids")
	}
	if len(identity.UserID(owner.Public())) != 22 {
		t.Fatal("user id is not 16 bytes of base64url")
	}
}

package link

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/coder/quartz"

	"github.com/nghyane/tilder/go/internal/identity"
	"github.com/nghyane/tilder/go/internal/identity/identitytest"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// The agent trusts an offer only from a device its pinned root certified,
// valid on the agent's own clock, for the key that signed the offer: the
// server forwarding it proves nothing (ADR 0004).
func TestTheAgentTrustsOnlyItsOwnersCertifiedDevices(t *testing.T) {
	t.Parallel()
	clk := quartz.NewMock(t)
	now := clk.Now()
	machine, err := identity.MachinePrivateFromSeed(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	owner := identitytest.NewDevice(t, 1, 101, now)
	l := &Link{Key: machine, Owner: owner.Root.Public(), Clock: clk}
	machineID := identity.MachineID(machine.Public())

	offer := func(d identitytest.Device, cert *tilderv1.DeviceCertificate) *tilderv1.SignalDeliver {
		return &tilderv1.SignalDeliver{
			DevicePublicKey: d.PublicKey(), SessionId: []byte("s"), Sdp: "v=0",
			Signature:         d.Key.Sign(identity.OfferStatement(machineID, []byte("s"), "v=0")),
			DeviceCertificate: cert,
		}
	}
	if !l.trusted(offer(owner, owner.Certificate())) {
		t.Fatal("the owner's own device was refused")
	}

	stranger := identitytest.NewDevice(t, 9, 109, now) // another root, validly self-consistent
	expired := owner
	expired.Cert.NotBefore, expired.Cert.NotAfter = now.Add(-40*24*time.Hour), now.Add(-time.Hour)
	other := identitytest.NewDevice(t, 1, 102, now) // the owner's other device
	for name, d := range map[string]*tilderv1.SignalDeliver{
		"a device another root certified":     offer(stranger, stranger.Certificate()),
		"a certificate expired on this clock": offer(owner, expired.Certificate()),
		"a certificate for another key":       offer(owner, other.Certificate()),
		"no certificate":                      offer(owner, nil),
	} {
		if l.trusted(d) {
			t.Errorf("%s was trusted", name)
		}
	}
}

// memRevocations is a RevocationStore in memory; err makes Load fail.
type memRevocations struct {
	statement string
	sig       []byte
	err       error
	saves     int
}

func (m *memRevocations) Load() (string, []byte, bool, error) {
	return m.statement, m.sig, m.statement != "", m.err
}

func (m *memRevocations) Save(statement string, sig []byte) error {
	m.statement, m.sig = statement, sig
	m.saves++
	return nil
}

// A removed device is refused at once, the list is stored so a restarted
// agent still refuses it, and the device's live connections are cut
// (ADR 0004).
func TestTheAgentRefusesAndCutsOffARemovedDevice(t *testing.T) {
	t.Parallel()
	clk := quartz.NewMock(t)
	now := clk.Now()
	machine, err := identity.MachinePrivateFromSeed(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	phone := identitytest.NewDevice(t, 1, 150, now)
	store := &memRevocations{}
	var cut []identity.DevicePublic
	l := &Link{
		Key: machine, Owner: phone.Root.Public(), Clock: clk, Log: quietLog(),
		Revocations: store, OnRevoked: func(ds []identity.DevicePublic) { cut = append(cut, ds...) },
	}
	machineID := identity.MachineID(machine.Public())
	offer := &tilderv1.SignalDeliver{
		DevicePublicKey: phone.PublicKey(), SessionId: []byte("s"), Sdp: "v=0",
		Signature:         phone.Key.Sign(identity.OfferStatement(machineID, []byte("s"), "v=0")),
		DeviceCertificate: phone.Certificate(),
	}
	l.loadRevocations()
	if !l.trusted(offer) {
		t.Fatal("the phone was refused before it was removed")
	}

	list := identity.Revocations{Root: phone.Root.Public(), Seq: 1, At: now, Devices: []identity.DevicePublic{phone.Key.Public()}}
	s := list.Statement()
	l.applyRevocations(s.Text(), phone.Root.Sign(s))
	if l.trusted(offer) {
		t.Fatal("a removed device was trusted")
	}
	if len(cut) != 1 || cut[0] != phone.Key.Public() || store.saves != 1 {
		t.Fatalf("cut %v, saved %d times", cut, store.saves)
	}

	// A restart: the stored list refuses the phone before any server speaks.
	restarted := &Link{Key: machine, Owner: phone.Root.Public(), Clock: clk, Log: quietLog(), Revocations: store}
	restarted.loadRevocations()
	if restarted.trusted(offer) {
		t.Fatal("a restarted agent forgot a removed device")
	}

	// A list signed by another root is ignored.
	stranger := identitytest.NewDevice(t, 9, 190, now)
	forged := identity.Revocations{Root: phone.Root.Public(), Seq: 2, At: now}
	l.applyRevocations(forged.Statement().Text(), stranger.Root.Sign(forged.Statement()))
	if store.saves != 1 {
		t.Fatal("a forged list was stored")
	}
}

// A stored list that cannot be read refuses every device: a removed device
// must not get in through a broken file.
func TestAnUnreadableListRefusesEveryone(t *testing.T) {
	t.Parallel()
	clk := quartz.NewMock(t)
	machine, _ := identity.MachinePrivateFromSeed(bytes.Repeat([]byte{5}, 32))
	owner := identitytest.NewDevice(t, 1, 101, clk.Now())
	l := &Link{Key: machine, Owner: owner.Root.Public(), Clock: clk, Log: quietLog(), Revocations: &memRevocations{err: errors.New("disk")}}
	l.loadRevocations()
	offer := &tilderv1.SignalDeliver{
		DevicePublicKey: owner.PublicKey(), SessionId: []byte("s"), Sdp: "v=0",
		Signature:         owner.Key.Sign(identity.OfferStatement(identity.MachineID(machine.Public()), []byte("s"), "v=0")),
		DeviceCertificate: owner.Certificate(),
	}
	if l.trusted(offer) {
		t.Fatal("a device was trusted with the list unreadable")
	}
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

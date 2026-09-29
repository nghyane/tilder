package link

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/coder/quartz"

	"github.com/nghyane/tilder/go/internal/identity"
	"github.com/nghyane/tilder/go/internal/identity/identitytest"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

func machineKey(t *testing.T, seed byte) identity.MachinePrivate {
	t.Helper()
	k, err := identity.MachinePrivateFromSeed(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signedGrant(d identitytest.Device, src, dst string, notAfter time.Time) *tilderv1.TransferGrant {
	g := identity.Transfer{
		User: d.Cert.User(), Device: d.Key.Public(), Src: src, SrcPath: []byte("proj"), Dst: dst, DstPath: []byte("inbox"),
		NotAfter: notAfter, Nonce: bytes.Repeat([]byte{7}, 16),
	}
	return &tilderv1.TransferGrant{Statement: g.Statement().Text(), Signature: d.Key.Sign(g.Statement()), DeviceCertificate: d.Certificate()}
}

// The source machine answers another machine only for a copy one of its
// owner's devices allowed, from that machine to itself, and only when that
// machine signed the offer itself; the server forwarding it proves nothing
// (ADR 0035).
func TestASourceTrustsOnlyAMachineItsOwnerGrantedACopy(t *testing.T) {
	t.Parallel()
	clk := quartz.NewMock(t)
	now := clk.Now()
	src, dst, third := machineKey(t, 5), machineKey(t, 6), machineKey(t, 8)
	srcID, dstID := identity.MachineID(src.Public()), identity.MachineID(dst.Public())
	owner := identitytest.NewDevice(t, 1, 101, now)
	l := &Link{Key: src, Owner: owner.Root.Public(), Clock: clk}

	offer := func(from identity.MachinePrivate, g *tilderv1.TransferGrant) *tilderv1.SignalDeliver {
		pub := from.Public().Raw32()
		return &tilderv1.SignalDeliver{
			MachinePublicKey: pub[:], SessionId: []byte("s"), Sdp: "v=0", Grant: g,
			Signature: from.Sign(identity.MachineOfferStatement(srcID, identity.MachineID(from.Public()), []byte("s"), "v=0", g.GetStatement())),
		}
	}
	good := signedGrant(owner, srcID, dstID, now.Add(time.Hour))
	if got, ok := l.trustedMachine(offer(dst, good)); !ok || got.Dst != dstID || string(got.SrcPath) != "proj" {
		t.Fatalf("the granted machine was refused: %+v %v", got, ok)
	}

	stranger := identitytest.NewDevice(t, 9, 109, now)
	resigned := offer(dst, good)
	resigned.Sdp = "v=0 other" // the SDP carries the DTLS fingerprint
	otherGrant := offer(dst, good)
	otherGrant.Grant = signedGrant(owner, srcID, dstID, now.Add(2*time.Hour))
	// A third machine signing as if it were the destination: its key is not the one the grant names.
	impostor := offer(third, good)
	impostor.Signature = third.Sign(identity.MachineOfferStatement(srcID, dstID, []byte("s"), "v=0", good.GetStatement()))
	tampered := signedGrant(owner, srcID, dstID, now.Add(time.Hour))
	tampered.Signature = signedGrant(owner, srcID, dstID, now.Add(2*time.Hour)).GetSignature()
	for name, d := range map[string]*tilderv1.SignalDeliver{
		"a machine the grant does not name":       offer(third, good),
		"a grant from another owner's device":     offer(dst, signedGrant(stranger, srcID, dstID, now.Add(time.Hour))),
		"a grant for another source":              offer(dst, signedGrant(owner, "machine-z", dstID, now.Add(time.Hour))),
		"an expired grant":                        offer(dst, signedGrant(owner, srcID, dstID, now.Add(-time.Hour))),
		"a grant with another grant's signature":  offer(dst, tampered),
		"an offer whose SDP was swapped":          resigned,
		"an offer signed over another grant":      otherGrant,
		"a machine claiming the destination's id": impostor,
		"no grant": offer(dst, nil),
	} {
		if _, ok := l.trustedMachine(d); ok {
			t.Errorf("%s was trusted", name)
		}
	}

	// The grant's device removed: its copies stop too.
	rev := identity.Revocations{Root: owner.Root.Public(), Seq: 1, At: now, Devices: []identity.DevicePublic{owner.Key.Public()}}
	l.applyRevocations(rev.Statement().Text(), owner.Root.Sign(rev.Statement()))
	if _, ok := l.trustedMachine(offer(dst, good)); ok {
		t.Fatal("a removed device's grant was trusted")
	}
}

// The destination starts a copy only for a grant from its owner's device,
// not removed, naming itself as the destination (ADR 0035).
func TestADestinationPullsOnlyForItsOwnersGrantToIt(t *testing.T) {
	t.Parallel()
	clk := quartz.NewMock(t)
	now := clk.Now()
	dst := machineKey(t, 6)
	dstID := identity.MachineID(dst.Public())
	owner := identitytest.NewDevice(t, 1, 101, now)
	l := &Link{Key: dst, Owner: owner.Root.Public(), Clock: clk}

	// Before the list of removed devices is read, no grant is judged (ADR 0040).
	if _, err := l.VerifyPull(signedGrant(owner, "machine-a", dstID, now.Add(time.Hour))); !errors.Is(err, ErrStale) {
		t.Fatalf("a grant judged before the list was read: %v", err)
	}
	l.LoadRevocations()
	if _, err := l.VerifyPull(signedGrant(owner, "machine-a", dstID, now.Add(time.Hour))); err != nil {
		t.Fatalf("the owner's grant was refused: %v", err)
	}
	stranger := identitytest.NewDevice(t, 9, 109, now)
	for name, g := range map[string]*tilderv1.TransferGrant{
		"a grant to another machine":          signedGrant(owner, "machine-a", "machine-z", now.Add(time.Hour)),
		"a grant from another owner's device": signedGrant(stranger, "machine-a", dstID, now.Add(time.Hour)),
		"an expired grant":                    signedGrant(owner, "machine-a", dstID, now.Add(-time.Hour)),
		"no grant":                            nil,
	} {
		if _, err := l.VerifyPull(g); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	rev := identity.Revocations{Root: owner.Root.Public(), Seq: 1, At: now, Devices: []identity.DevicePublic{owner.Key.Public()}}
	l.applyRevocations(rev.Statement().Text(), owner.Root.Sign(rev.Statement()))
	if _, err := l.VerifyPull(signedGrant(owner, "machine-a", dstID, now.Add(time.Hour))); err == nil {
		t.Fatal("a removed device's grant was accepted")
	}
}

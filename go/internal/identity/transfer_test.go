package identity_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nghyane/tilder/go/internal/identity"
	"github.com/nghyane/tilder/go/internal/identity/identitytest"
)

func grant(d identitytest.Device, now time.Time) identity.Transfer {
	return identity.Transfer{
		User: d.Cert.User(), Device: d.Key.Public(),
		Src: "machine-a", SrcPath: []byte("src/proj"),
		Dst: "machine-b", DstPath: []byte("inbox"),
		NotAfter: now.Add(time.Hour), Nonce: bytes.Repeat([]byte{7}, 16),
	}
}

// ADR 0035: a device's grant for one copy, checked by both machines.
func TestATransferGrantVerifiesForItsDeviceAndTime(t *testing.T) {
	t.Parallel()
	d := identitytest.NewDevice(t, 1, 2, epoch)
	g := grant(d, epoch)
	text := g.Statement().Text()
	got, err := identity.VerifyTransfer(text, d.Key.Sign(g.Statement()), d.Cert, epoch)
	if err != nil {
		t.Fatal(err)
	}
	if got.Src != "machine-a" || string(got.DstPath) != "inbox" || got.ID() != g.ID() {
		t.Fatalf("got %+v", got)
	}
}

func TestATransferGrantIsRefused(t *testing.T) {
	t.Parallel()
	d := identitytest.NewDevice(t, 1, 2, epoch)
	other := identitytest.NewDevice(t, 1, 3, epoch)
	stranger := identitytest.NewDevice(t, 9, 4, epoch)
	sign := func(g identity.Transfer) (string, []byte) {
		return g.Statement().Text(), d.Key.Sign(g.Statement())
	}
	cases := map[string]func() (string, []byte, identity.DeviceCert, time.Time){
		"signed by another device of the owner": func() (string, []byte, identity.DeviceCert, time.Time) {
			g := grant(d, epoch)
			return g.Statement().Text(), other.Key.Sign(g.Statement()), d.Cert, epoch
		},
		"presented with another device's cert": func() (string, []byte, identity.DeviceCert, time.Time) {
			text, sig := sign(grant(d, epoch))
			return text, sig, other.Cert, epoch
		},
		"for another owner": func() (string, []byte, identity.DeviceCert, time.Time) {
			g := grant(d, epoch)
			g.User = stranger.Cert.User()
			text, sig := sign(g)
			return text, sig, d.Cert, epoch
		},
		"tampered": func() (string, []byte, identity.DeviceCert, time.Time) {
			text, sig := sign(grant(d, epoch))
			return strings.Replace(text, "src_path=", "src_path=Lw", 1), sig, d.Cert, epoch
		},
		"expired": func() (string, []byte, identity.DeviceCert, time.Time) {
			text, sig := sign(grant(d, epoch))
			return text, sig, d.Cert, epoch.Add(2 * time.Hour)
		},
		"longer than a day": func() (string, []byte, identity.DeviceCert, time.Time) {
			g := grant(d, epoch)
			g.NotAfter = epoch.Add(25 * time.Hour)
			text, sig := sign(g)
			return text, sig, d.Cert, epoch
		},
		"a short nonce": func() (string, []byte, identity.DeviceCert, time.Time) {
			g := grant(d, epoch)
			g.Nonce = []byte{1, 2, 3}
			text, sig := sign(g)
			return text, sig, d.Cert, epoch
		},
		"to the machine it copies from": func() (string, []byte, identity.DeviceCert, time.Time) {
			g := grant(d, epoch)
			g.Dst = g.Src
			text, sig := sign(g)
			return text, sig, d.Cert, epoch
		},
		"not in the canonical form": func() (string, []byte, identity.DeviceCert, time.Time) {
			g := grant(d, epoch)
			text := strings.Replace(g.Statement().Text(), "not_after=", "not_after=0", 1)
			return text, d.Key.Sign(identity.DeviceStatementForTest(text)), d.Cert, epoch
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			text, sig, cert, now := build()
			if _, err := identity.VerifyTransfer(text, sig, cert, now); !errors.Is(err, identity.ErrTransferInvalid) {
				t.Fatalf("got %v, want ErrTransferInvalid", err)
			}
		})
	}
}

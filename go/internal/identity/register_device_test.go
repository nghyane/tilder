package identity_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nghyane/tilder/go/internal/identity"
)

// ADR 0053: a device registers a machine with its own key, checked against
// its certificate from the root.
func deviceRegistrationFixture(t *testing.T) (identity.DevicePrivate, identity.DeviceCert, identity.DeviceRegistration) {
	t.Helper()
	_, cert := certFixture(t)
	dev, err := identity.DevicePrivateFromSeed(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	machine, err := identity.MachinePrivateFromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return dev, cert, identity.DeviceRegistration{Root: cert.Root, Device: cert.Device, Machine: machine.Public(), At: epoch.Add(time.Hour)}
}

func TestADeviceRegistrationVerifiesAgainstItsCertificate(t *testing.T) {
	t.Parallel()
	dev, cert, r := deviceRegistrationFixture(t)
	s := r.Statement()
	got, err := identity.VerifyDeviceRegistration(s.Text(), dev.Sign(s), cert, epoch.Add(2*time.Hour))
	if err != nil || got.Machine != r.Machine || !got.At.Equal(r.At) || got.Device != cert.Device {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestADeviceRegistrationIsRefused(t *testing.T) {
	t.Parallel()
	dev, cert, r := deviceRegistrationFixture(t)
	other, _ := identity.DevicePrivateFromSeed(bytes.Repeat([]byte{9}, 32))
	otherRoot, _ := identity.RootPrivateFromSeed(bytes.Repeat([]byte{8}, 32))
	now := epoch.Add(2 * time.Hour)
	signed := func(r identity.DeviceRegistration, by identity.DevicePrivate) (string, []byte) {
		return r.Statement().Text(), by.Sign(r.Statement())
	}
	cases := []struct {
		name string
		text string
		sig  []byte
		now  time.Time
	}{}
	add := func(name string, text string, sig []byte, at time.Time) {
		cases = append(cases, struct {
			name string
			text string
			sig  []byte
			now  time.Time
		}{name, text, sig, at})
	}
	text, sig := signed(r, other)
	add("signed by another device", text, sig, now)
	moved := r
	moved.Device = other.Public()
	text, sig = signed(moved, other)
	add("for another device than the cert's", text, sig, now)
	foreign := r
	foreign.Root = otherRoot.Public()
	text, sig = signed(foreign, dev)
	add("for another user", text, sig, now)
	early := r
	early.At = epoch.Add(-time.Hour)
	text, sig = signed(early, dev)
	add("before the cert", text, sig, now)
	late := r
	late.At = epoch.Add(40 * 24 * time.Hour)
	text, sig = signed(late, dev)
	add("after the cert", text, sig, late.At)
	text, sig = signed(r, dev)
	add("dated after now", text, sig, epoch)
	add("not canonical", strings.Replace(text, "at=", "at=+", 1), sig, now)
	add("a root registration's kind", strings.Replace(text, "register-by-device", "register", 1), sig, now)
	for _, c := range cases {
		if _, err := identity.VerifyDeviceRegistration(c.text, c.sig, cert, c.now); !errors.Is(err, identity.ErrDeviceRegistration) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// The text the console builds (web/src/model/register.ts) is these bytes.
func TestADeviceRegistrationIsTheTextTheConsoleBuilds(t *testing.T) {
	t.Parallel()
	_, _, r := deviceRegistrationFixture(t)
	// Seeds 1 (root), 2 (device), 7 (machine); the console's test pins the same bytes.
	want := "tilder/register-by-device/v2\n" +
		"user=qm1SYqBJ_JD_ffZkQwZJ1w\n" +
		"machine=VuC1TDda8CdfuMDPNj2BUQ\n" +
		"machine_pub=6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw\n" +
		"device=gTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5Q\n" +
		"at=1790003600\n"
	if got := r.Statement().Text(); got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

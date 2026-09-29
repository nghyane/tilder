package identity_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/nghyane/tilder/go/internal/identity"
)

func devicesFixture(t *testing.T, seeds ...byte) []identity.DevicePublic {
	t.Helper()
	out := make([]identity.DevicePublic, 0, len(seeds))
	for _, s := range seeds {
		d, err := identity.DevicePrivateFromSeed(bytes.Repeat([]byte{s}, 32))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, d.Public())
	}
	return out
}

func TestARevocationListVerifiesAndOnlyGrows(t *testing.T) {
	t.Parallel()
	root, err := identity.RootPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	devs := devicesFixture(t, 3, 4, 5)
	first := identity.Revocations{Root: root.Public(), Seq: 1, Devices: identity.SortDevices(devs[:1]), At: epoch}
	second := identity.Revocations{Root: root.Public(), Seq: 2, Devices: identity.SortDevices(devs[1:]), At: epoch}

	got, err := identity.VerifyRevocations(second.Statement().Text(), root.Sign(second.Statement()), root.Public())
	if err != nil || len(got.Devices) != 2 {
		t.Fatalf("got %+v, %v", got, err)
	}
	// Two owners' browsers removing different devices at once both count:
	// merging never drops one (a "strictly higher seq wins" rule would).
	merged := first.Merge(got)
	for _, d := range devs {
		if !merged.Has(d) {
			t.Fatal("a removed device fell out of the merged list")
		}
	}
	if merged.Seq != 2 {
		t.Fatalf("seq %d", merged.Seq)
	}
	// An old list replayed changes nothing.
	if again := merged.Merge(first); len(again.Devices) != 3 || again.Seq != 2 {
		t.Fatalf("a replayed list changed the set: %+v", again)
	}
}

func TestARevocationListIsRefused(t *testing.T) {
	t.Parallel()
	root, _ := identity.RootPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	other, _ := identity.RootPrivateFromSeed(bytes.Repeat([]byte{9}, 32))
	devs := identity.SortDevices(devicesFixture(t, 3, 4))
	r := identity.Revocations{Root: root.Public(), Seq: 1, Devices: devs, At: epoch}
	s := r.Statement()
	names := strings.Split(strings.Split(s.Text(), "devices=")[1], "\n")[0]
	parts := strings.Split(names, ",")
	for name, tc := range map[string]struct {
		text string
		sig  []byte
	}{
		"signed by another root": {s.Text(), other.Sign(s)},
		"unsorted":               {strings.Replace(s.Text(), names, parts[1]+","+parts[0], 1), nil},
		"a duplicate":            {strings.Replace(s.Text(), names, parts[0]+","+parts[0], 1), nil},
		"not a key":              {strings.Replace(s.Text(), names, "AAAA", 1), nil},
		"an extra line":          {s.Text() + "x=y\n", nil},
	} {
		if _, err := identity.VerifyRevocations(tc.text, tc.sig, root.Public()); !errors.Is(err, identity.ErrRevocations) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	empty := identity.Revocations{Root: root.Public(), Seq: 0, At: epoch}
	if _, err := identity.VerifyRevocations(empty.Statement().Text(), root.Sign(empty.Statement()), root.Public()); err != nil {
		t.Fatalf("an empty list: %v", err)
	}
}

func FuzzVerifyRevocations(f *testing.F) {
	f.Add("tilder/revocations/v2\nuser=x\nseq=1\ndevices=\nat=1\n", []byte{1})
	root, _ := identity.RootPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	f.Fuzz(func(t *testing.T, text string, sig []byte) {
		_, _ = identity.VerifyRevocations(text, sig, root.Public()) // must not panic
	})
}

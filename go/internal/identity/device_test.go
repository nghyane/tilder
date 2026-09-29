package identity_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nghyane/tilder/go/internal/identity"
)

var epoch = time.Unix(1_790_000_000, 0)

func certFixture(t *testing.T) (identity.RootPrivate, identity.DeviceCert) {
	t.Helper()
	root, err := identity.RootPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	dev, err := identity.DevicePrivateFromSeed(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return root, identity.DeviceCert{
		Root: root.Public(), Device: dev.Public(), NameHash: identity.NameHash("laptop"),
		RevSeq: 3, NotBefore: epoch, NotAfter: epoch.Add(30 * 24 * time.Hour),
	}
}

func TestADeviceCertVerifiesWithinItsTime(t *testing.T) {
	t.Parallel()
	root, c := certFixture(t)
	s := c.Statement()
	got, err := identity.VerifyDeviceCert(s.Text(), root.Sign(s), epoch.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if got.Device != c.Device || got.User() != identity.UserID(root.Public()) || got.RevSeq != 3 {
		t.Fatalf("got %+v", got)
	}
}

func TestADeviceCertIsRefused(t *testing.T) {
	t.Parallel()
	root, c := certFixture(t)
	other, err := identity.RootPrivateFromSeed(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	long := c
	long.NotAfter = c.NotBefore.Add(identity.MaxCertLifetime + time.Second)
	for _, tc := range []struct {
		name string
		text string
		sig  []byte
		now  time.Time
		want error
	}{
		{"signed by another root", c.Statement().Text(), other.Sign(c.Statement()), epoch, identity.ErrCertSignature},
		{"longer than 90 days, even validly signed", long.Statement().Text(), root.Sign(long.Statement()), epoch, identity.ErrCertLifetime},
		{"before its time", c.Statement().Text(), root.Sign(c.Statement()), epoch.Add(-identity.ClockSkew - time.Second), identity.ErrCertNotYet},
		{"after its time", c.Statement().Text(), root.Sign(c.Statement()), c.NotAfter.Add(identity.ClockSkew + time.Second), identity.ErrCertExpired},
		{"a field out of order", strings.Replace(c.Statement().Text(), "rev_seq=3\nnot_before", "not_before", 1), nil, epoch, identity.ErrCertMalformed},
		{"a leading zero", strings.Replace(c.Statement().Text(), "rev_seq=3", "rev_seq=03", 1), nil, epoch, identity.ErrCertMalformed},
		{"an extra line", c.Statement().Text() + "caps=admin\n", nil, epoch, identity.ErrCertMalformed},
		{"a user that is not the root's", strings.Replace(c.Statement().Text(), "user="+c.User(), "user=AAAAAAAAAAAAAAAAAAAAAA", 1), nil, epoch, identity.ErrCertMalformed},
		{"no final newline", strings.TrimSuffix(c.Statement().Text(), "\n"), nil, epoch, identity.ErrCertMalformed},
		{"huge", strings.Repeat("x", 4096), nil, epoch, identity.ErrCertMalformed},
		// ADR 0029: the old product's kind line is not this one.
		{"a byo cert", strings.Replace(c.Statement().Text(), "tilder/device-cert/", "byo/device-cert/", 1), nil, epoch, identity.ErrCertMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := identity.VerifyDeviceCert(tc.text, tc.sig, tc.now); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func FuzzVerifyDeviceCert(f *testing.F) {
	f.Add("tilder/device-cert/v2\nuser=x\n", []byte{1})
	f.Fuzz(func(t *testing.T, text string, sig []byte) {
		_, _ = identity.VerifyDeviceCert(text, sig, epoch) // must not panic
	})
}

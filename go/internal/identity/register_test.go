package identity_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nghyane/tilder/go/internal/identity"
)

func registrationFixture(t *testing.T) (identity.RootPrivate, identity.Registration) {
	t.Helper()
	root, err := identity.RootPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	machine, err := identity.MachinePrivateFromSeed(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return root, identity.Registration{Root: root.Public(), Machine: machine.Public(), At: epoch}
}

func TestARegistrationVerifiesAgainstItsRootOnly(t *testing.T) {
	t.Parallel()
	root, r := registrationFixture(t)
	s := r.Statement()
	got, err := identity.VerifyRegistration(s.Text(), root.Sign(s), root.Public(), epoch)
	if err != nil || got.Machine != r.Machine {
		t.Fatalf("got %+v, %v", got, err)
	}
	other, err := identity.RootPrivateFromSeed(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		text string
		sig  []byte
		root identity.RootPublic
		now  time.Time
	}{
		"signed by another root":     {s.Text(), other.Sign(s), root.Public(), epoch},
		"checked against another":    {s.Text(), root.Sign(s), other.Public(), epoch},
		"dated in the future":        {s.Text(), root.Sign(s), root.Public(), epoch.Add(-identity.ClockSkew - time.Second)},
		"a machine id not its key's": {strings.Replace(s.Text(), "machine="+identity.MachineID(r.Machine), "machine=AAAAAAAAAAAAAAAAAAAAAA", 1), nil, root.Public(), epoch},
		"an extra line":              {s.Text() + "x=y\n", nil, root.Public(), epoch},
	} {
		if _, err := identity.VerifyRegistration(tc.text, tc.sig, tc.root, tc.now); !errors.Is(err, identity.ErrRegistration) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

// The proof ties a machine key to the join secret's private half: another
// key, or another secret, gives another proof.
func TestAJoinProofBindsTheKeyToTheSecret(t *testing.T) {
	t.Parallel()
	secret := make([]byte, identity.JoinSecretSize)
	for i := range secret {
		secret[i] = byte(i)
	}
	lookup, auth, err := identity.SplitJoinSecret(secret)
	if err != nil || !bytes.Equal(lookup, secret[:16]) || !bytes.Equal(auth, secret[16:]) {
		t.Fatalf("split %v %v %v", lookup, auth, err)
	}
	_, r := registrationFixture(t)
	proof := identity.JoinProof(auth, r.Machine)
	other, _ := identity.MachinePrivateFromSeed(bytes.Repeat([]byte{6}, 32))
	if bytes.Equal(proof, identity.JoinProof(auth, other.Public())) {
		t.Fatal("two keys gave one proof")
	}
	if bytes.Equal(proof, identity.JoinProof(lookup, r.Machine)) {
		t.Fatal("the server's half gave the same proof")
	}
	if _, _, err := identity.SplitJoinSecret(secret[:31]); !errors.Is(err, identity.ErrJoinSecret) {
		t.Fatal("a short secret split")
	}
}

func FuzzVerifyRegistration(f *testing.F) {
	f.Add("tilder/register/v2\nuser=x\n", []byte{1})
	root, _ := identity.RootPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	f.Fuzz(func(t *testing.T, text string, sig []byte) {
		_, _ = identity.VerifyRegistration(text, sig, root.Public(), epoch) // must not panic
	})
}

package identity_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/nghyane/tilder/go/internal/identity"
)

func tokenFixture(t testing.TB) identity.JoinToken {
	t.Helper()
	root, err := identity.RootPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	var tok identity.JoinToken
	for i := range tok.Secret {
		tok.Secret[i] = byte(i)
	}
	tok.Root = root.Public()
	return tok
}

func TestAJoinTokenReadsBackAsWritten(t *testing.T) {
	t.Parallel()
	tok := tokenFixture(t)
	got, err := identity.ParseJoinToken(tok.String())
	if err != nil || got != tok {
		t.Fatalf("got %v, %v", got, err)
	}
}

// A token pasted short, altered, or of another version never parses: the
// agent says so before it tries anything.
func TestAJoinTokenRefusesDamage(t *testing.T) {
	t.Parallel()
	good := tokenFixture(t).String()
	flip := func(i int) string {
		b := []byte(good)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}
	for name, s := range map[string]string{
		"empty":         "",
		"no prefix":     strings.TrimPrefix(good, "tilder1_"),
		"other version": "tilder2_" + strings.TrimPrefix(good, "tilder1_"),
		"cut short":     good[:len(good)-1],
		"one extra":     good + "A",
		"secret typo":   flip(10),
		"root typo":     flip(60),
		"check typo":    flip(len(good) - 2),
		"padding":       good + "==",
		"not base64url": good[:20] + "+" + good[21:],
	} {
		if _, err := identity.ParseJoinToken(s); !errors.Is(err, identity.ErrJoinToken) {
			t.Errorf("%s: parsed (%v)", name, err)
		}
	}
}

func FuzzParseJoinToken(f *testing.F) {
	f.Add(tokenFixture(f).String())
	f.Add("tilder1_")
	f.Fuzz(func(t *testing.T, s string) {
		tok, err := identity.ParseJoinToken(s)
		if err == nil && tok.String() != s {
			t.Fatalf("%q parsed but writes back as %q", s, tok.String())
		}
	})
}

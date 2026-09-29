package identity_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nghyane/tilder/go/internal/identity"
)

func wrapsFixture(t testing.TB) (identity.RootPrivate, identity.RootWraps) {
	t.Helper()
	root, err := identity.RootPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	a := identity.RootWrap{Lookup: [32]byte{2}, Digest: [32]byte{3}}
	b := identity.RootWrap{Lookup: [32]byte{1}, Digest: [32]byte{4}}
	return root, identity.RootWraps{Root: root.Public(), Seq: 2, Wraps: identity.SortRootWraps([]identity.RootWrap{a, b}), At: time.Unix(1_790_000_000, 0)}
}

func TestARootWrapsListReadsBackWhenTheRootSignedIt(t *testing.T) {
	t.Parallel()
	root, list := wrapsFixture(t)
	text := list.Statement().Text()
	got, err := identity.VerifyRootWraps(text, root.Sign(list.Statement()), root.Public())
	if err != nil || got.Seq != 2 || len(got.Wraps) != 2 || got.Wraps[0].Lookup[0] != 1 {
		t.Fatalf("got %+v, %v", got, err)
	}
}

// Only the root decides which blobs the server keeps (ADR 0021): another
// key's signature, an edited list, or one out of canonical order fails.
func TestARootWrapsListRefusesAnythingTheRootDidNotSign(t *testing.T) {
	t.Parallel()
	root, list := wrapsFixture(t)
	other, err := identity.RootPrivateFromSeed(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	text := list.Statement().Text()
	sig := root.Sign(list.Statement())
	unsorted := list
	unsorted.Wraps = []identity.RootWrap{list.Wraps[1], list.Wraps[0]}
	duplicate := list
	duplicate.Wraps = []identity.RootWrap{list.Wraps[0], list.Wraps[0]}
	for name, c := range map[string]struct {
		text string
		sig  []byte
		root identity.RootPublic
	}{
		"another root's signature": {text, other.Sign(list.Statement()), root.Public()},
		"checked against another":  {text, sig, other.Public()},
		"edited":                   {strings.Replace(text, "seq=2", "seq=3", 1), sig, root.Public()},
		"unsorted":                 {unsorted.Statement().Text(), root.Sign(unsorted.Statement()), root.Public()},
		"duplicate lookup":         {duplicate.Statement().Text(), root.Sign(duplicate.Statement()), root.Public()},
		"empty":                    {strings.Replace(text, text[strings.Index(text, "wraps="):strings.Index(text, "\nat=")], "wraps=", 1), sig, root.Public()},
	} {
		if _, err := identity.VerifyRootWraps(c.text, c.sig, c.root); !errors.Is(err, identity.ErrRootWraps) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func FuzzVerifyRootWraps(f *testing.F) {
	root, list := wrapsFixture(f)
	f.Add(list.Statement().Text(), root.Sign(list.Statement()))
	f.Fuzz(func(t *testing.T, text string, sig []byte) {
		_, _ = identity.VerifyRootWraps(text, sig, root.Public()) // must not panic
	})
}

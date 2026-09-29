package update_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/nghyane/tilder/go/internal/testutil"
	"github.com/nghyane/tilder/go/internal/update"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m, testutil.GoleakOptions...) }

var now = time.Unix(1_790_000_000, 0)

// pub is a private key's public half (the second 32 bytes of an Ed25519 private key).
func pub(k ed25519.PrivateKey) ed25519.PublicKey { return ed25519.PublicKey(k[ed25519.SeedSize:]) }

type keys struct {
	root, signing ed25519.PrivateKey
	keyText       string
	keySig        []byte
}

func newKeys(t testing.TB, seed byte) keys {
	t.Helper()
	root := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	signing := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed + 1}, 32))
	k := update.SigningKey{Key: pub(signing), NotAfter: now.Add(365 * 24 * time.Hour)}
	return keys{root: root, signing: signing, keyText: k.Statement(), keySig: ed25519.Sign(root, []byte(k.Statement()))}
}

func release(version string) update.Release {
	return update.Release{Version: version, Files: []update.File{
		{Name: "tilder-darwin-arm64", SHA256: sha256.Sum256([]byte("mac")), Size: 3},
		{Name: "tilder-linux-amd64", SHA256: sha256.Sum256([]byte("linux")), Size: 5},
	}}
}

func (k keys) sign(r update.Release) (string, []byte) {
	return r.Statement(), ed25519.Sign(k.signing, []byte(r.Statement()))
}

func TestAReleaseSignedThroughTheRootIsTaken(t *testing.T) {
	t.Parallel()
	k := newKeys(t, 1)
	text, sig := k.sign(release("0.5.0"))
	got, err := update.Verify(pub(k.root), k.keyText, k.keySig, text, sig, now)
	if err != nil || got.Version != "0.5.0" {
		t.Fatalf("got %+v, %v", got, err)
	}
	if f, ok := got.File("tilder-linux-amd64"); !ok || !f.SameBytes(sha256.Sum256([]byte("linux")), 5) {
		t.Fatalf("file %+v %v", f, ok)
	}
}

// The server hosts the files but cannot make one the agent takes (ADR 0023).
func TestAReleaseNotSignedThroughTheRootIsRefused(t *testing.T) {
	t.Parallel()
	k := newKeys(t, 1)
	stranger := newKeys(t, 9)
	root := pub(k.root)
	text, sig := k.sign(release("0.5.0"))
	otherText, otherSig := stranger.sign(release("0.5.0"))
	for name, c := range map[string]struct {
		keyText     string
		keySig      []byte
		releaseText string
		releaseSig  []byte
		at          time.Time
	}{
		"a key another root vouched for": {stranger.keyText, stranger.keySig, otherText, otherSig, now},
		"a release another key signed":   {k.keyText, k.keySig, otherText, otherSig, now},
		"an edited release":              {k.keyText, k.keySig, strings.Replace(text, "0.5.0", "9.9.9", 1), sig, now},
		"a signing key past its date":    {k.keyText, k.keySig, text, sig, now.Add(400 * 24 * time.Hour)},
	} {
		if _, err := update.Verify(root, c.keyText, c.keySig, c.releaseText, c.releaseSig, c.at); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

func TestOnlyNewerReleasesAreTaken(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		candidate, running string
		want               bool
	}{
		{"0.5.0", "0.4.0", true},
		{"0.10.0", "0.9.9", true},
		{"0.4.0", "0.4.0", false},
		{"0.3.9", "0.4.0", false}, // no going back: an old release with a fixed bug
		{"0.5.0", "dev", false},   // a dev build is left alone
		{"0.5.0-rc", "0.4.0", false},
	} {
		if got := update.Newer(c.candidate, c.running); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.candidate, c.running, got)
		}
	}
}

func FuzzVerify(f *testing.F) {
	k := newKeys(f, 1)
	text, sig := k.sign(release("0.5.0"))
	f.Add(k.keyText, text)
	root := pub(k.root)
	f.Fuzz(func(t *testing.T, keyText, releaseText string) {
		_, _ = update.Verify(root, keyText, k.keySig, releaseText, sig, now) // must not panic
	})
}

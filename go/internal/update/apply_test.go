package update_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/coder/quartz"

	"github.com/nghyane/tilder/go/internal/update"
)

// server hosts a release of the agent as `make release` lays it out, with
// the bytes served for the binary chosen by the test.
func server(t *testing.T, k keys, version string, signed, served []byte) *httptest.Server {
	t.Helper()
	rel := update.Release{Version: version, Files: []update.File{{Name: "tilder-test", SHA256: sha256.Sum256(signed), Size: int64(len(signed))}}}
	text, sig := k.sign(rel)
	files := map[string][]byte{
		"/dist/current":                     []byte(version + "\n"),
		"/dist/" + version + "/signing.txt": []byte(k.keyText),
		"/dist/" + version + "/signing.sig": []byte(base64.RawURLEncoding.EncodeToString(k.keySig)),
		"/dist/" + version + "/release.txt": []byte(text),
		"/dist/" + version + "/release.sig": []byte(base64.RawURLEncoding.EncodeToString(sig)),
		"/dist/" + version + "/tilder-test": served,
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func updater(t *testing.T, s *httptest.Server, root ed25519.PublicKey, running string) (*update.Updater, string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "tilder")
	if err := os.WriteFile(bin, []byte("old agent"), 0o700); err != nil { //nolint:gosec // G306: an executable
		t.Fatal(err)
	}
	return &update.Updater{
		Base: s.URL, Root: root, Running: running, Binary: bin, Asset: "tilder-test",
		Home: dir, Client: s.Client(), Clock: quartz.NewMock(t),
	}, bin
}

func contents(t *testing.T, path string) string {
	t.Helper()
	b, _ := os.ReadFile(path) //nolint:gosec // G304: the test's temp dir
	return string(b)
}

func TestANewerSignedReleaseIsInstalledBesideTheOld(t *testing.T) {
	t.Parallel()
	k := newKeys(t, 1)
	u, bin := updater(t, server(t, k, "0.5.0", []byte("new agent"), []byte("new agent")), pub(k.root), "0.4.0")
	got, err := u.Install(context.Background())
	if err != nil || got != "0.5.0" {
		t.Fatalf("got %q, %v", got, err)
	}
	if contents(t, bin) != "new agent" || contents(t, bin+".prev") != "old agent" {
		t.Fatalf("binary %q, prev %q", contents(t, bin), contents(t, bin+".prev"))
	}
	if !update.Pending(u.Home, "0.5.0") {
		t.Fatal("no marker: a new binary that never connects would stay")
	}
	// It never reached the server: the old one comes back.
	if err := update.RollBack(u.Home, bin); err != nil || contents(t, bin) != "old agent" || update.Pending(u.Home, "0.5.0") {
		t.Fatalf("roll back: %v, binary %q", err, contents(t, bin))
	}
}

// Whatever the server serves, the agent installs only the bytes the release
// key signed, and only a version newer than its own.
func TestTheServerCannotMakeTheAgentInstallAnythingElse(t *testing.T) {
	t.Parallel()
	k := newKeys(t, 1)
	root := pub(k.root)
	for name, c := range map[string]struct {
		s       *httptest.Server
		root    ed25519.PublicKey
		running string
	}{
		"bytes other than the signed ones":   {server(t, k, "0.5.0", []byte("new agent"), []byte("backdoor!")), root, "0.4.0"},
		"a release another root vouched for": {server(t, newKeys(t, 9), "0.5.0", []byte("new agent"), []byte("new agent")), root, "0.4.0"},
		"an older release":                   {server(t, k, "0.3.0", []byte("old!"), []byte("old!")), root, "0.4.0"},
		"the same release":                   {server(t, k, "0.4.0", []byte("same"), []byte("same")), root, "0.4.0"},
	} {
		u, bin := updater(t, c.s, c.root, c.running)
		if _, err := u.Install(context.Background()); err == nil {
			t.Errorf("%s: installed", name)
		}
		if contents(t, bin) != "old agent" {
			t.Errorf("%s: the binary changed", name)
		}
		if _, err := os.Stat(bin + ".unverified"); !os.IsNotExist(err) {
			t.Errorf("%s: left the unverified download", name)
		}
	}
}

// ADR 0041: a new release that dies at every start, before its proving timer
// is set (a config it cannot read, a crash within the minute), comes back to
// the previous one after a few starts instead of leaving the machine offline
// once systemd gives up.
func TestAReleaseThatNeverStartsGoesBack(t *testing.T) {
	t.Parallel()
	k := newKeys(t, 1)
	u, bin := updater(t, server(t, k, "0.5.0", []byte("new agent"), []byte("new agent")), pub(k.root), "0.4.0")
	if _, err := u.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	for start := range 3 {
		if back, err := update.Started(u.Home, "0.5.0", bin, 3); back || err != nil {
			t.Fatalf("start %d: back=%v, %v", start+1, back, err)
		}
	}
	if contents(t, bin) != "new agent" {
		t.Fatal("went back too soon")
	}
	back, err := update.Started(u.Home, "0.5.0", bin, 3)
	if !back || err != nil {
		t.Fatalf("fourth start: back=%v, %v", back, err)
	}
	if contents(t, bin) != "old agent" || update.Pending(u.Home, "0.5.0") {
		t.Fatalf("binary %q after going back", contents(t, bin))
	}
	// The old release starting again is not counted: nothing to prove.
	if back, err := update.Started(u.Home, "0.4.0", bin, 3); back || err != nil {
		t.Fatalf("old release: back=%v, %v", back, err)
	}
}

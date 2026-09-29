package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/nghyane/tilder/go/internal/agent/state"
	"github.com/nghyane/tilder/go/internal/identity"
	"github.com/nghyane/tilder/go/internal/testutil"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, testutil.GoleakOptions...)
}

func TestRendezvousURL(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"https://tilder.example":       "wss://tilder.example/ws",
		"https://tilder.example/":      "wss://tilder.example/ws",
		"http://localhost:8787":        "ws://localhost:8787/ws",
		"wss://tilder.example/ws":      "wss://tilder.example/ws",
		"ftp://tilder.example":         "",
		"tilder.example":               "",
		"https://u:p@tilder.example":   "",
		"https://tilder.example/?x=1":  "",
		"https://tilder.example/#frag": "",
	} {
		got, err := rendezvousURL(in)
		if (want == "") != (err != nil) || got != want {
			t.Errorf("%q: got %q, %v", in, got, err)
		}
	}
}

// The token is the only way in: the key the agent pins is the one in it.
func TestJoinPinsTheTokensRoot(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	root, err := identity.RootPrivateFromSeed(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	tok := identity.JoinToken{Root: root.Public()}
	if _, err = join(home, []string{"https://tilder.example"}, tok.String()); err != nil {
		t.Fatal(err)
	}
	cfg, err := state.LoadConfig(home)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := cfg.OwnerKey(); got != root.Public() || cfg.Server != "wss://tilder.example/ws" {
		t.Fatalf("config %+v", cfg)
	}
	for _, bad := range []string{"", tok.String()[:40], strings.Replace(tok.String(), "tilder1_", "tilder2_", 1)} {
		if _, err := join(t.TempDir(), []string{"https://tilder.example"}, bad); err == nil {
			t.Errorf("joined with %q", bad)
		}
	}
}

// A home holding another install's key file (tilder v1 used ~/.tilder too) is
// refused before anything is written, so no service is installed that
// would fail at every start.
func TestJoinRefusesAHomeThatIsNotItsOwn(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	v1 := []byte(`{"secret_key":"from tilder v1"}`)
	if err := os.WriteFile(filepath.Join(home, "identity.json"), v1, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := identity.RootPrivateFromSeed(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	_, err = join(home, []string{"https://tilder.example"}, identity.JoinToken{Root: root.Public()}.String())
	if err == nil || !strings.Contains(err.Error(), "another tilder install") {
		t.Fatalf("joined over another install: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(home, "config.json")); !os.IsNotExist(serr) {
		t.Fatal("wrote a config anyway")
	}
	if got, _ := os.ReadFile(filepath.Join(home, "identity.json")); !bytes.Equal(got, v1) { //nolint:gosec // G304: the test's own temp dir
		t.Fatal("touched the other install's key file")
	}
}

// `join` records and returns: the install script runs it before installing
// anything and waits on it (found when it served forever and the script hung).
func TestJoinReturnsInsteadOfServing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TILDER_HOME", home)
	root, err := identity.RootPrivateFromSeed(bytes.Repeat([]byte{3}, 32))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- run([]string{"join", "https://tilder.example"}, identity.JoinToken{Root: root.Public()}.String())
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-testutil.Context(t, testutil.WaitShort).Done():
		t.Fatal("join kept running")
	}
}

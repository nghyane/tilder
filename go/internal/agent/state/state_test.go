package state_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nghyane/tilder/go/internal/agent/state"
)

func TestTheMachineKeyIsCreatedOnceAndKeptPrivate(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	first, err := state.MachineKey(home)
	if err != nil {
		t.Fatal(err)
	}
	again, err := state.MachineKey(home)
	if err != nil || again.Public() != first.Public() {
		t.Fatal("a restart made a new machine key")
	}
	info, err := os.Stat(filepath.Join(home, "identity.json"))
	// Windows has no mode bits: the key is private by the profile's ACL.
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Fatalf("identity.json mode %v", info.Mode().Perm())
	}
}

func TestAConfigRoundTripsAndDropsTheSecretWhenCleared(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	c := state.Config{Server: "wss://tilder.example/ws", Owner: "broot:x", JoinSecret: "s3cret"}
	if err := state.SaveConfig(home, c); err != nil {
		t.Fatal(err)
	}
	c.JoinSecret = ""
	if err := state.SaveConfig(home, c); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(home, "config.json")) //nolint:gosec // G304: the test's own temp dir
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := state.LoadConfig(home); got != c || string(raw) == "" || strings.Contains(string(raw), "s3cret") {
		t.Fatalf("config %q", raw)
	}
}

//go:build unix

package files_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coder/quartz"

	"github.com/nghyane/tilder/go/internal/agent/files"
)

// The agent's directory itself is never removed or moved: its parent is the
// home, which every check passed. Moved, a check by name no longer found it
// and the machine key was read at its new place.
func TestTheAgentsDirectoryIsNeverRemovedOrMoved(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		do   func(*files.Tree) error
	}{
		{"remove it", func(tr *files.Tree) error { return tr.Remove(".tilder", true) }},
		{"rename it", func(tr *files.Tree) error { return tr.Rename(".tilder", "proj/x", false) }},
		{"rename it, keeping any there", func(tr *files.Tree) error { return tr.Rename(".tilder", "proj/x", true) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			tree, h := home(t)
			if err := c.do(tree); code(err) != files.Denied {
				t.Fatalf("%s: %v, want Denied", c.name, err)
			}
			if b, err := os.ReadFile(filepath.Join(h, ".tilder/identity.json")); err != nil || string(b) != secret { //nolint:gosec // G304: the test's temp dir
				t.Fatalf("the machine key is gone: %q, %v", b, err)
			}
			if got, err := read(t, tree, "proj/x/identity.json"); err == nil {
				t.Fatalf("read the machine key through the tree: %q", got)
			}
		})
	}
}

// A directory above the agent's (TILDER_HOME set deeper) takes the agent's
// directory with it: it is not removed or moved either.
func TestNoDirectoryAboveTheAgentsMoves(t *testing.T) {
	t.Parallel()
	h := t.TempDir()
	if err := os.MkdirAll(filepath.Join(h, "apps/tilder"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h, "apps/tilder/identity.json"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	tree := files.New(h, filepath.Join(h, "apps/tilder"), quartz.NewMock(t))
	if err := tree.Remove("apps", true); code(err) != files.Denied {
		t.Fatalf("Remove(apps) = %v, want Denied", err)
	}
	if err := tree.Rename("apps", "gone", false); code(err) != files.Denied {
		t.Fatalf("Rename(apps) = %v, want Denied", err)
	}
	if _, err := os.Stat(filepath.Join(h, "apps/tilder/identity.json")); err != nil {
		t.Fatal(err)
	}
}

// Once the agent's directory is gone from its place (moved by hand while the
// agent runs), nothing is served rather than everything: the check never
// passes because what it guards is missing.
func TestAMissingAgentDirectoryRefusesEverything(t *testing.T) {
	t.Parallel()
	tree, h := home(t)
	if err := os.Rename(filepath.Join(h, ".tilder"), filepath.Join(h, "proj/moved")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"proj/moved/identity.json", "proj/hard", "proj/a.txt"} {
		if got, err := read(t, tree, p); code(err) != files.Denied {
			t.Errorf("read %s = %q, %v; want Denied", p, got, err)
		}
	}
}

// Renaming still works for everything else, both ways, and keeps what is there.
func TestARenameMovesOrdinaryFilesAndKeepsWhatIsThere(t *testing.T) {
	t.Parallel()
	tree, h := home(t)
	if err := tree.Rename("proj/a.txt", "proj/sub/a.txt", false); err != nil {
		t.Fatal(err)
	}
	if err := tree.Rename("proj/sub/a.txt", "proj/sub/b.txt", true); code(err) != files.Exists {
		t.Fatalf("noReplace over a file = %v, want Exists", err)
	}
	if err := tree.Rename("proj/sub", "proj/moved", true); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(h, "proj/moved/a.txt")); err != nil || string(b) != "hello" { //nolint:gosec // G304: the test's temp dir
		t.Fatalf("moved file = %q, %v", b, err)
	}
}

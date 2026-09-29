//go:build unix

package ptychan_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coder/quartz"

	"github.com/nghyane/tilder/go/internal/agent/files"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// A home with a project, a file, a link that leaves it, and the agent's own
// directory, as the files tree sees it.
func homeTree(t *testing.T) (string, *files.Tree) {
	t.Helper()
	home, outside := t.TempDir(), t.TempDir()
	for _, d := range []string{"src/api", ".tilder"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, "notes.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "away")); err != nil {
		t.Fatal(err)
	}
	return home, files.New(home, filepath.Join(home, ".tilder"), quartz.NewReal())
}

func attachIn(dir string) *tilderv1.PtyClient {
	return &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{
		ShellId: "s-" + strings.ReplaceAll(dir, "/", "-"), Cols: 80, Rows: 24, Dir: []byte(dir),
	}}}
}

// "Open in Terminal" on a folder starts the shell in it (ADR 0024).
func TestAShellStartsInTheFolderAskedFor(t *testing.T) {
	t.Parallel()
	home, tree := homeTree(t)
	c := serveIn(t, shellManager(t), tree.DirPath)
	send(t, c, attachIn("src/api"))
	send(t, c, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Input{Input: &tilderv1.PtyInput{Data: []byte("pwd -P\n")}}})
	want, err := filepath.EvalSymlinks(filepath.Join(home, "src", "api"))
	if err != nil {
		t.Fatal(err)
	}
	buf, seen := make([]byte, 64*1024), ""
	for !strings.Contains(seen, want+"\r\n") {
		msg := receive(t, c, buf)
		seen += string(msg.GetOutput().GetData()) + string(msg.GetScreen().GetData())
	}
}

// A folder that is not one under the home is refused with a code the
// console can say, never swapped for the home: typing into a shell that
// started somewhere else is worse than no shell.
func TestAShellIsRefusedAFolderOutsideTheHomeOrNotAFolder(t *testing.T) {
	t.Parallel()
	_, tree := homeTree(t)
	for dir, want := range map[string]tilderv1.PtyRefused_Code{
		"away":      tilderv1.PtyRefused_CODE_DENIED,    // a link out of the home
		"src/../..": tilderv1.PtyRefused_CODE_INVALID,   // climbing
		".tilder":   tilderv1.PtyRefused_CODE_DENIED,    // the agent's own directory
		"notes.txt": tilderv1.PtyRefused_CODE_NOT_DIR,   // a file
		"gone":      tilderv1.PtyRefused_CODE_NOT_FOUND, // nothing there
	} {
		c := serveIn(t, shellManager(t), tree.DirPath)
		send(t, c, attachIn(dir))
		if got := receive(t, c, make([]byte, 4096)).GetRefused().GetCode(); got != want {
			t.Errorf("%q: %v, want %v", dir, got, want)
		}
	}
}

// Reattaching to a running shell never looks at the folder again: a folder
// deleted since must not cut the owner off their shell.
func TestReattachingIgnoresTheFolder(t *testing.T) {
	t.Parallel()
	home, tree := homeTree(t)
	shells := shellManager(t)
	first := serveIn(t, shells, tree.DirPath)
	send(t, first, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{ShellId: "kept", Cols: 80, Rows: 24, Dir: []byte("src/api")}}})
	receive(t, first, make([]byte, 64*1024))
	if err := os.RemoveAll(filepath.Join(home, "src")); err != nil {
		t.Fatal(err)
	}
	again := serveIn(t, shells, tree.DirPath)
	send(t, again, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{ShellId: "kept", Cols: 80, Rows: 24, Dir: []byte("src/api")}}})
	if msg := receive(t, again, make([]byte, 64*1024)); msg.GetRefused() != nil {
		t.Fatalf("the running shell was refused: %v", msg)
	}
}

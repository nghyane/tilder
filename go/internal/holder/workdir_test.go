//go:build unix

package holder_test

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nghyane/tilder/go/internal/holder"
)

// A process started in a folder is read as being there, as the shell a
// terminal runs will be.
func TestTheFolderOfAProcessIsItsWorkingDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cmd := exec.CommandContext(t.Context(), "/bin/sh", "-c", "read x")
	cmd.Dir = dir
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	got, err := holder.WorkingDir(t.Context(), cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(dir)
	if got != want {
		t.Fatalf("%s, want %s", got, want)
	}
	if _, err := holder.WorkingDir(t.Context(), 1<<30); err == nil {
		t.Error("a process that does not exist has a folder")
	}
}

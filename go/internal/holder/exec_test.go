//go:build unix

package holder_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/coder/quartz"

	"github.com/nghyane/tilder/go/internal/holder"
	"github.com/nghyane/tilder/go/internal/testutil"
)

// The real thing: `tilder hold` started detached by the agent's spawner.
// The agent's side closes (as when it crashes or upgrades), and a new one
// finds the very same shell process, still running.
func TestADetachedHolderKeepsItsShellAcrossAgents(t *testing.T) {
	t.Parallel()
	bin := filepath.Join(t.TempDir(), "tilder")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd/tilder") //nolint:gosec // G204: the test's own temp path
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	runDir := shortDir(t)

	first := holder.NewHolders(runDir, holder.ExecSpawnerFor(bin, runDir, false), quartz.NewReal())
	s, err := first.Open("real", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, v := s.Attach(0)
	if err = s.Input([]byte("echo pid=$$=\n")); err != nil {
		t.Fatal(err)
	}
	pid := pidFrom(t, v)
	holderPid := parentOf(t, pid)
	t.Cleanup(func() { _ = syscall.Kill(holderPid, syscall.SIGTERM) })
	first.Close()

	<-time.After(300 * time.Millisecond) //nolint:forbidigo // a real process needs real time
	if err = syscall.Kill(pid, 0); err != nil {
		t.Fatalf("the shell %d died with the agent: %v", pid, err)
	}
	second := holder.NewHolders(runDir, func(string, uint16, uint16, string) error {
		t.Error("a living holder was started again")
		return nil
	}, quartz.NewReal())
	defer second.Close()
	again, err := second.Open("real", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, v2 := again.Attach(0)
	if err := again.Input([]byte("echo again=$$=\n")); err != nil {
		t.Fatal(err)
	}
	var more strings.Builder
	readUntil(t, v2, &more, "again="+strconv.Itoa(pid)+"=")

	// What the shell runs gets the default hangup: a holder that ignored
	// SIGHUP passed the ignore down (Go resets only handled signals at exec),
	// so a hangup never ended /bin/sh or its jobs. The quotes keep the typed
	// command's echo from containing the word.
	if err := again.Input([]byte("sh -c 'kill -HUP $$; echo sur''vived'; echo hup-$((6*7))\n")); err != nil {
		t.Fatal(err)
	}
	readUntil(t, v2, &more, "hup-42")
	if strings.Contains(more.String(), "survived") {
		t.Fatalf("a hangup did not end the shell's child: SIGHUP is inherited as ignored")
	}

	again.Kill()
	deadline := time.After(testutil.WaitShort) //nolint:forbidigo // a real process needs real time
	for {
		select {
		case e, ok := <-v2.Events():
			if !ok || e.Exited {
				return
			}
		case <-deadline:
			t.Fatal("no exit after Kill")
		}
	}
}

// pidFrom reads until the shell printed "pid=<n>=" on a line of its own (the
// echoed command has "$$" there, and the owner's prompt may be anything).
func pidFrom(t *testing.T, v *holder.Viewer) int {
	t.Helper()
	// Digits only in the shell's answer: the typed command reads pid=$$=. Not
	// anchored at a line start: typed before the first prompt, the answer
	// can follow that prompt on its line ("# pid=1622=", as root in Docker).
	line := regexp.MustCompile(`pid=(\d+)=`)
	var seen strings.Builder
	deadline := time.After(testutil.WaitShort) //nolint:forbidigo // a real process needs real time
	for {
		if m := line.FindStringSubmatch(seen.String()); m != nil {
			n, err := strconv.Atoi(m[1])
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
		select {
		case e, ok := <-v.Events():
			if !ok {
				t.Fatalf("stream ended; saw %q", seen.String())
			}
			seen.Write(e.Data)
		case <-deadline:
			t.Fatalf("no pid within %s; saw %q", testutil.WaitShort, seen.String())
		}
	}
}

// parentOf is the holder: the shell's parent process.
func parentOf(t *testing.T, pid int) int {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "ps", "-o", "ppid=", "-p", strconv.Itoa(pid)).Output() //nolint:gosec // G204: a pid the test read
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil || n <= 1 || n == os.Getpid() {
		t.Fatalf("parent of %d is %q: not a holder", pid, out)
	}
	return n
}

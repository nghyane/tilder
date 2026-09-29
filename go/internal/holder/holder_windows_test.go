//go:build windows

package holder_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/quartz"
	"go.uber.org/goleak"

	"github.com/nghyane/tilder/go/internal/holder"
	"github.com/nghyane/tilder/go/internal/testutil"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m, testutil.GoleakOptions...) }

// runDirWin is a short socket directory: AF_UNIX paths are bounded on
// Windows too, and a t.TempDir() path carries the test's name.
func runDirWin(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "th") //nolint:usetesting // t.TempDir() can pass the socket path limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// inProcessWin runs holders as goroutines of the test with cmd.exe, over
// real AF_UNIX sockets: the pseudoconsole and the socket are under test.
func inProcessWin(t *testing.T, runDir string) holder.Spawner {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	cfg := holder.Config{
		Shell: os.Getenv("COMSPEC"), Env: os.Environ(), //nolint:forbidigo // the runner's own cmd.exe
		Dir: t.TempDir(), RingSize: 1 << 16, Clock: quartz.NewReal(), ExitedTTL: 20 * time.Millisecond,
	}
	return func(id string, cols, rows uint16, _ string) error {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = holder.RunHolder(ctx, cfg, runDir, id, cols, rows)
		}()
		return nil
	}
}

func readUntilWin(t *testing.T, v *holder.Viewer, seen *strings.Builder, want string) {
	t.Helper()
	deadline := time.After(testutil.WaitMedium) //nolint:forbidigo // a real shell needs real time
	for !strings.Contains(seen.String(), want) {
		select {
		case e, ok := <-v.Events():
			if !ok {
				t.Fatalf("stream ended before %q; saw %q", want, seen.String())
			}
			seen.Write(e.Data)
		case <-deadline:
			t.Fatalf("no %q within %s; saw %q", want, testutil.WaitMedium, seen.String())
		}
	}
}

// ADR 0044: a shell runs in a pseudoconsole: what is typed reaches it, its
// output comes back, a resize is taken, and Kill ends it with the stream
// saying so.
func TestAWindowsShellRunsInAPseudoconsole(t *testing.T) {
	t.Parallel()
	runDir := runDirWin(t)
	h := holder.NewHolders(runDir, inProcessWin(t, runDir), quartz.NewReal())
	defer h.Close()
	s, err := h.Open("con", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, v := s.Attach(0)
	if err := s.Input([]byte("echo tilder-%OS%\r\n")); err != nil {
		t.Fatal(err)
	}
	var seen strings.Builder
	readUntilWin(t, v, &seen, "tilder-Windows_NT")
	if err := s.Resize(100, 30); err != nil {
		t.Fatalf("resize: %v", err)
	}
	s.Kill()
	deadline := time.After(testutil.WaitMedium) //nolint:forbidigo // a real shell needs real time
	for {
		select {
		case e, ok := <-v.Events():
			if !ok || e.Exited {
				return
			}
		case <-deadline:
			t.Fatal("the shell did not end after Kill")
		}
	}
}

// ADR 0044's first risk: the holder, started detached and out of the
// agent's job, keeps its shell when the agent goes, and the next agent finds
// that very shell (a variable set in it is still set).
func TestADetachedHolderKeepsItsShellAcrossAgentsOnWindows(t *testing.T) {
	t.Parallel()
	bin := filepath.Join(t.TempDir(), "tilder.exe")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd/tilder") //nolint:gosec // G204: the test's own temp path
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	runDir := runDirWin(t)

	first := holder.NewHolders(runDir, holder.ExecSpawnerFor(bin, runDir, false), quartz.NewReal())
	s, err := first.Open("kept", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, v := s.Attach(0)
	if err = s.Input([]byte("$env:TILDER_MARK = 'kept-' + (6*7)\r\n")); err != nil {
		t.Fatal(err)
	}
	if err = s.Input([]byte("echo \"set $env:TILDER_MARK\"\r\n")); err != nil {
		t.Fatal(err)
	}
	var seen strings.Builder
	readUntilWin(t, v, &seen, "set kept-42")
	first.Close()

	<-time.After(500 * time.Millisecond) //nolint:forbidigo // a real process needs real time
	second := holder.NewHolders(runDir, func(string, uint16, uint16, string) error {
		t.Error("a living holder was started again")
		return nil
	}, quartz.NewReal())
	defer second.Close()
	again, err := second.Open("kept", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, v2 := again.Attach(0)
	if err := again.Input([]byte("echo \"again $env:TILDER_MARK\"\r\n")); err != nil {
		t.Fatal(err)
	}
	var more strings.Builder
	readUntilWin(t, v2, &more, "again kept-42")
	again.Kill()
}

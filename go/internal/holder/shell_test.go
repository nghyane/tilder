//go:build unix

package holder_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/quartz"
	"go.uber.org/goleak"

	"github.com/nghyane/tilder/go/internal/holder"
	"github.com/nghyane/tilder/go/internal/testutil"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m, testutil.GoleakOptions...) }

func manager(t *testing.T) *holder.Manager {
	t.Helper()
	m := holder.NewManager(holder.Config{
		// A clean, non-login shell with a UTF-8 locale: without LANG the line
		// discipline dropped the "à" of the first run (the agent passes the
		// owner's environment, locale included).
		Shell: "/bin/sh", Env: []string{"TERM=xterm-256color", "PS1=$ ", "LANG=en_US.UTF-8", "HISTFILE=/dev/null", "HOME=" + t.TempDir()},
		Dir:      t.TempDir(),
		RingSize: 1 << 20, Clock: quartz.NewReal(),
	})
	t.Cleanup(m.Close)
	return m
}

// until reads events until the collected output contains want, or fails.
func until(t *testing.T, v *holder.Viewer, seen *strings.Builder, want string) {
	t.Helper()
	deadline := time.After(testutil.WaitShort) //nolint:forbidigo // real processes need real time here
	for !strings.Contains(seen.String(), want) {
		select {
		case e, ok := <-v.Events():
			if !ok {
				t.Fatalf("viewer closed before %q; saw %q", want, seen.String())
			}
			seen.Write(e.Data)
		case <-deadline:
			t.Fatalf("no %q within %s; saw %q", want, testutil.WaitShort, seen.String())
		}
	}
}

func TestAShellRunsAndReplaysByOffset(t *testing.T) {
	t.Parallel()
	shell, err := manager(t).Open("s1", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, v := shell.Attach(0)
	var seen strings.Builder
	if err := shell.Input([]byte("echo xin-chào-$((40+2))\n")); err != nil {
		t.Fatal(err)
	}
	until(t, v, &seen, "xin-chào-42")

	// A second viewer attaching from the start gets the same bytes, replayed.
	replay, second := shell.Attach(0)
	if !strings.Contains(string(replay.Data), "xin-chào-42") || replay.From != 0 || replay.Lost != 0 {
		t.Fatalf("replay %q from %d lost %d", replay.Data, replay.From, replay.Lost)
	}
	shell.Detach(second)
}

func TestOpenAttachesToTheSameShell(t *testing.T) {
	t.Parallel()
	m := manager(t)
	a, err := m.Open("same", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Open("same", 80, 24)
	if err != nil || a != b {
		t.Fatal("a second open started a new shell")
	}
}

func TestExitIsReportedWithItsCode(t *testing.T) {
	t.Parallel()
	shell, err := manager(t).Open("exits", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, v := shell.Attach(0)
	if err := shell.Input([]byte("exit 7\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(testutil.WaitShort) //nolint:forbidigo // real processes need real time here
	for {
		select {
		case e, ok := <-v.Events():
			if !ok {
				t.Fatal("closed without an exit event")
			}
			if e.Exited {
				if e.Code != 7 {
					t.Fatalf("exit code %d", e.Code)
				}
				return
			}
		case <-deadline:
			t.Fatal("no exit event")
		}
	}
}

func TestKillTakesTheWholeProcessGroup(t *testing.T) {
	t.Parallel()
	shell, err := manager(t).Open("group", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	pidFile := t.TempDir() + "/pid"
	_, v := shell.Attach(0)
	var seen strings.Builder
	// A background job that ignores nothing: it must die with the shell's group.
	// The marker is computed, so the terminal echoing the typed command does not contain it.
	if ierr := shell.Input([]byte("sleep 300 & echo $! > " + pidFile + "; echo started-$((6*7))\n")); ierr != nil {
		t.Fatal(ierr)
	}
	until(t, v, &seen, "started-42")
	raw, err := os.ReadFile(pidFile) //nolint:gosec // G304: a file this test just created
	if err != nil {
		t.Fatal(err)
	}
	shell.Kill()
	// The exit must be prompt, and the job must then be gone too (polled
	// below): the exit is reported when the shell ends, whatever still holds
	// its terminal. (Without these deadlines the Linux run once "passed" after
	// the job's natural 300 s.)
	exitBy := time.After(testutil.WaitShort) //nolint:forbidigo // real processes need real time here
	for exited := false; !exited; {
		select {
		case e, ok := <-v.Events():
			exited = !ok || e.Exited
		case <-exitBy:
			t.Fatal("the shell did not exit: something in its session survived the kill")
		}
	}
	proc, err := os.FindProcess(atoi(t, strings.TrimSpace(string(raw))))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(testutil.WaitShort) //nolint:forbidigo // real processes need real time here
	for proc.Signal(syscallZero()) == nil {
		if time.Now().After(deadline) { //nolint:forbidigo // real processes need real time here
			t.Fatal("the background job outlived its shell")
		}
		time.Sleep(20 * time.Millisecond) //nolint:forbidigo // polling a real process
	}
}

// Every tab has its own shell now, so an exited one must not stay in memory
// for the agent's life (ADR 0014); until the TTL it still reports its exit.
func TestAnExitedShellIsForgottenAfterItsTTL(t *testing.T) {
	t.Parallel()
	m := holder.NewManager(holder.Config{
		Shell: "/bin/sh", Env: []string{"TERM=xterm-256color", "PS1=$ ", "HISTFILE=/dev/null", "HOME=" + t.TempDir()},
		Dir: t.TempDir(), RingSize: 1 << 16, Clock: quartz.NewReal(), ExitedTTL: 50 * time.Millisecond,
	})
	t.Cleanup(m.Close)
	first, err := m.Open("brief", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Input([]byte("exit 0\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(testutil.WaitShort) //nolint:forbidigo // real processes need real time here
	for {
		again, err := m.Open("brief", 80, 24)
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			return // forgotten: the id starts a new shell
		}
		select {
		case <-deadline:
			t.Fatal("the exited shell was never forgotten")
		case <-time.After(20 * time.Millisecond): //nolint:forbidigo // polling a real process
		}
	}
}

// Close returns once its shells have exited, not merely been sent a kill: a
// leak check after it found a shell still dying (goleak, under load).
func TestCloseWaitsForItsShellsToExit(t *testing.T) {
	t.Parallel()
	m := manager(t)
	var shells []*holder.Shell
	for _, id := range []string{"a", "b", "c"} {
		s, err := m.Open(id, 80, 24)
		if err != nil {
			t.Fatal(err)
		}
		shell, ok := s.(*holder.Shell)
		if !ok {
			t.Fatalf("Open gave %T, want *holder.Shell", s)
		}
		shells = append(shells, shell)
	}
	m.Close()
	for _, s := range shells {
		select {
		case <-s.Done():
		default:
			t.Fatalf("shell %s had not exited when Close returned", s.ID)
		}
	}
	m.Close() // idempotent
}

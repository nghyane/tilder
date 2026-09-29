//go:build unix

package holder_test

import (
	"bytes"
	"context"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/coder/quartz"

	"github.com/nghyane/tilder/go/internal/holder"
	"github.com/nghyane/tilder/go/internal/testutil"
)

// waitExit reads until the exit event and returns its code.
func waitExit(t *testing.T, v *holder.Viewer, within time.Duration, seen *strings.Builder) int {
	t.Helper()
	deadline := time.After(within) //nolint:forbidigo // a real shell needs real time
	for {
		select {
		case e, ok := <-v.Events():
			if !ok {
				t.Fatalf("stream ended without an exit; saw %q", seen.String())
			}
			if e.Exited {
				return e.Code
			}
			seen.Write(e.Data)
		case <-deadline:
			t.Fatalf("no exit within %s; saw %q", within, seen.String())
		}
	}
}

// A holder is a process per shell: once its shell has gone (and the linger
// is over) it must go too, even though the agent still holds its control
// connection. It used to wait for the agent to hang up, so every closed tab
// left a holder process behind until the agent restarted.
func TestAHolderEndsWithItsShellWhileTheAgentStaysConnected(t *testing.T) {
	t.Parallel()
	runDir := shortDir(t)
	ended := make(chan error, 1)
	cfg := holder.Config{
		Shell: "/bin/sh", Env: []string{"TERM=xterm-256color", "PS1=$ ", "HISTFILE=/dev/null", "HOME=" + t.TempDir()},
		Dir: t.TempDir(), RingSize: 1 << 16, Clock: quartz.NewReal(), ExitedTTL: 20 * time.Millisecond,
	}
	spawn := func(id string, cols, rows uint16, _ string) error {
		go func() { ended <- holder.RunHolder(context.Background(), cfg, runDir, id, cols, rows) }()
		return nil
	}
	h := holder.NewHolders(runDir, spawn, quartz.NewReal())
	defer h.Close() // after the check: the agent stays connected throughout
	s, err := h.Open("closing", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, v := s.Attach(0)
	if err := s.Input([]byte("exit 0\n")); err != nil { // opens the control connection
		t.Fatal(err)
	}
	var seen strings.Builder
	waitExit(t, v, testutil.WaitShort, &seen)
	select {
	case err := <-ended:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(testutil.WaitShort): //nolint:forbidigo // a real shell needs real time
		t.Fatal("the holder outlived its shell while the agent was connected")
	}
}

var bgPid = regexp.MustCompile(`bg=(\d+)=`)

// The exit comes from the shell's process ending, not from its terminal
// closing: a background job still holding the terminal kept the tab alive
// with no shell in it (Linux; macOS revokes the terminal on exit).
func TestAnExitIsSeenWhileABackgroundJobHoldsTheTerminal(t *testing.T) {
	t.Parallel()
	shell, err := manager(t).Open("bg", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, v := shell.Attach(0)
	if err := shell.Input([]byte("sleep 60 & echo bg=$!=; exit 3\n")); err != nil {
		t.Fatal(err)
	}
	var seen strings.Builder
	code := waitExit(t, v, testutil.WaitShort, &seen)
	if m := bgPid.FindStringSubmatch(seen.String()); m != nil {
		_ = syscall.Kill(atoi(t, m[1]), syscall.SIGKILL)
	}
	if code != 3 {
		t.Fatalf("exit code %d, want 3", code)
	}
}

// Kill reaches the shell even while a big paste is stuck behind a program
// that reads nothing: requests on a connection are handled in order, so a
// kill queued behind the blocked write never arrived.
func TestKillIsNotStuckBehindAPasteNobodyReads(t *testing.T) {
	t.Parallel()
	runDir := shortDir(t)
	h := holder.NewHolders(runDir, inProcess(t, runDir), quartz.NewReal())
	defer h.Close()
	s, err := h.Open("paste", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, v := s.Attach(0)
	if err := s.Input([]byte("stty raw -echo; echo ready-$((6*7)); sleep 60\n")); err != nil {
		t.Fatal(err)
	}
	var seen strings.Builder
	readUntil(t, v, &seen, "ready-42")
	pasted := make(chan struct{})
	go func() {
		defer close(pasted)
		_ = s.Input(bytes.Repeat([]byte("x"), 900*1024)) // fills the terminal, then blocks
	}()
	<-time.After(300 * time.Millisecond) //nolint:forbidigo // let the paste fill the terminal
	s.Kill()
	waitExit(t, v, testutil.WaitShort, &seen)
	<-pasted
}

// A resize is not held up behind a paste the program never reads: it went
// on the same control connection as the paste's pieces, so it was applied
// only once the paste was read, and the agent's size arbiter, every other
// client of the shell and the tab's Kill waited on it.
func TestAResizeIsNotStuckBehindAPasteNobodyReads(t *testing.T) {
	t.Parallel()
	runDir := shortDir(t)
	h := holder.NewHolders(runDir, inProcess(t, runDir), quartz.NewReal())
	defer h.Close()
	s, err := h.Open("paste-resize", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, v := s.Attach(0)
	if err := s.Input([]byte("stty raw -echo; echo ready-$((6*7)); sleep 60\n")); err != nil {
		t.Fatal(err)
	}
	var seen strings.Builder
	readUntil(t, v, &seen, "ready-42")
	pasted := make(chan struct{})
	go func() {
		defer close(pasted)
		// As the console pastes: 16 KiB pieces, the first filling the
		// terminal, the rest filling the connection behind it.
		for range 64 {
			if s.Input(bytes.Repeat([]byte("x"), 16*1024)) != nil {
				return
			}
		}
	}()
	<-time.After(300 * time.Millisecond) //nolint:forbidigo // let the paste fill the terminal
	resized := make(chan error, 1)
	go func() { resized <- s.Resize(100, 30) }()
	deadline := time.After(testutil.WaitShort) //nolint:forbidigo // a real shell
	for applied := false; !applied; {
		select {
		case <-deadline:
			s.Kill() // frees the paste, so the test ends red rather than hangs
			t.Fatal("the resize waited behind the paste")
		case <-time.After(20 * time.Millisecond): //nolint:forbidigo // polling the holder
			replay, w := s.Attach(0)
			s.Detach(w)
			applied = replay.Cols == 100 && replay.Rows == 30
		}
	}
	s.Kill()
	waitExit(t, v, testutil.WaitShort, &seen)
	<-pasted
	<-resized
}

// Only a socket nobody listens on is stale. One that answers but will not
// talk to us (a holder of another contract version, one still starting) is
// left alone: removing it orphaned a living shell, unreachable for good.
func TestASocketSomeoneListensOnIsNeverTakenOver(t *testing.T) {
	t.Parallel()
	runDir := shortDir(t)
	path := holder.SocketPath(runDir, "taken")
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close() // listens, says nothing
		}
	}()

	h := holder.NewHolders(runDir, func(string, uint16, uint16, string) error {
		t.Error("a holder was started over a socket in use")
		return nil
	}, quartz.NewReal())
	defer h.Close()
	if _, err := h.Open("taken", 80, 24); err == nil {
		t.Error("opened a shell through a socket that does not speak our contract")
	}
	cfg := holder.Config{Shell: "/bin/sh", Dir: t.TempDir(), RingSize: 1 << 10, Clock: quartz.NewReal()}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second) // a holder that took over would run on
	defer cancel()
	if err := holder.RunHolder(ctx, cfg, runDir, "taken", 80, 24); err == nil {
		t.Error("a holder took over a socket in use")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the socket in use was removed: %v", err)
	}
}

// A shell that has printed more than its ring holds is reopened like any
// other: the replay of a full ring (plus its screen) outgrew the frame limit
// on the holder socket, and the agent took the unreadable answer for a dead
// shell.
func TestAShellWithAFullRingCanBeReopened(t *testing.T) {
	t.Parallel()
	runDir := shortDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() { cancel(); <-done })
	cfg := holder.Config{
		Shell: "/bin/sh", Env: []string{"TERM=xterm-256color", "PS1=$ ", "HISTFILE=/dev/null", "HOME=" + t.TempDir()},
		Dir: t.TempDir(), RingSize: 1 << 20, Clock: quartz.NewReal(),
	}
	spawn := func(id string, cols, rows uint16, _ string) error {
		go func() { defer close(done); _ = holder.RunHolder(ctx, cfg, runDir, id, cols, rows) }()
		return nil
	}
	h := holder.NewHolders(runDir, spawn, quartz.NewReal())
	defer h.Close()
	s, err := h.Open("full", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, v := s.Attach(0)
	if err := s.Input([]byte("head -c 1300000 /dev/zero | tr '\\\\0' x; echo; echo full-$((6*7))\n")); err != nil {
		t.Fatal(err)
	}
	// The burst can outrun this reader (one CPU, -race): the holder then drops
	// the viewer as too slow, by design, and a client attaches again from
	// its offset, as the console does.
	var seen strings.Builder
	var next uint64
	deadline := time.After(testutil.WaitShort) //nolint:forbidigo // a real shell needs real time
	for !strings.Contains(seen.String(), "full-42") {
		select {
		case e, ok := <-v.Events():
			if !ok {
				var again holder.Replay
				again, v = s.Attach(next)
				seen.Write(again.Data)
				next = again.From + uint64(len(again.Data))
				continue
			}
			seen.Write(e.Data)
			next = e.Seq + uint64(len(e.Data))
		case <-deadline:
			t.Fatalf("no full-42 within %s", testutil.WaitShort)
		}
	}
	replay, _ := s.Attach(0)
	if replay.Exited {
		t.Fatalf("a living shell with a full ring was reported gone (code %d)", replay.Code)
	}
}

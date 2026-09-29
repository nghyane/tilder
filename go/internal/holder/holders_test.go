//go:build unix

package holder_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/quartz"

	"github.com/nghyane/tilder/go/internal/holder"
	"github.com/nghyane/tilder/go/internal/testutil"
)

// shortDir is a socket directory under /tmp: a t.TempDir() path can pass the
// ~104-byte unix socket limit on macOS.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "tilder-h") //nolint:usetesting // t.TempDir() can pass the socket path limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// inProcess runs holders as goroutines of the test, over real sockets: the
// protocol and the reattach are what is under test, not exec.
func inProcess(t *testing.T, runDir string) holder.Spawner {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel() // kills every shell still held
		wg.Wait()
	})
	cfg := holder.Config{
		Shell: "/bin/sh", Env: []string{"TERM=xterm-256color", "PS1=$ ", "HISTFILE=/dev/null", "HOME=" + t.TempDir()},
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

func readUntil(t *testing.T, v *holder.Viewer, seen *strings.Builder, want string) {
	t.Helper()
	deadline := time.After(testutil.WaitShort) //nolint:forbidigo // a real shell needs real time
	for !strings.Contains(seen.String(), want) {
		select {
		case e, ok := <-v.Events():
			if !ok {
				t.Fatalf("stream ended before %q; saw %q", want, seen.String())
			}
			seen.Write(e.Data)
		case <-deadline:
			t.Fatalf("no %q within %s; saw %q", want, testutil.WaitShort, seen.String())
		}
	}
}

// K8: the agent restarts and the shell is still there, history and all.
func TestAShellOutlivesTheAgentThatStartedIt(t *testing.T) {
	t.Parallel()
	runDir := shortDir(t)
	spawn := inProcess(t, runDir)

	first := holder.NewHolders(runDir, spawn, quartz.NewReal())
	s, err := first.Open("kept", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, v := s.Attach(0)
	if err = s.Input([]byte("echo before-$$\n")); err != nil {
		t.Fatal(err)
	}
	var seen strings.Builder
	readUntil(t, v, &seen, "before-")
	first.Close() // the agent goes away; the holder must not notice
	// Long enough for a kill to have landed (a hangup takes a few ms): a shell
	// ended by the agent's exit would be gone by now.
	<-time.After(300 * time.Millisecond) //nolint:forbidigo // a real shell needs real time

	second := holder.NewHolders(runDir, func(string, uint16, uint16, string) error {
		t.Error("a living holder was started again")
		return nil
	}, quartz.NewReal())
	defer second.Close()
	again, err := second.Open("kept", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	replay, v2 := again.Attach(0)
	if replay.Exited {
		t.Fatalf("the shell ended with the agent (code %d)", replay.Code)
	}
	if !strings.Contains(string(replay.Data), "before-") {
		t.Fatalf("the replay lost the history: %q", replay.Data)
	}
	pid := strings.TrimSpace(strings.SplitN(strings.SplitN(string(replay.Data), "before-", 3)[2], "\r", 2)[0])
	if err := again.Input([]byte("echo after-$$\n")); err != nil {
		t.Fatal(err)
	}
	var more strings.Builder
	readUntil(t, v2, &more, "after-"+pid)
}

func TestKillEndsAHeldShellAndTheStreamSaysSo(t *testing.T) {
	t.Parallel()
	runDir := shortDir(t)
	h := holder.NewHolders(runDir, inProcess(t, runDir), quartz.NewReal())
	defer h.Close()
	s, err := h.Open("doomed", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, v := s.Attach(0)
	s.Kill()
	deadline := time.After(testutil.WaitShort) //nolint:forbidigo // a real shell needs real time
	for {
		select {
		case e, ok := <-v.Events():
			if !ok || e.Exited {
				return
			}
		case <-deadline:
			t.Fatal("no exit after Kill")
		}
	}
}

// Shell ids come from the network: they name sockets only through a hash.
func TestAShellIDNeverBecomesAPath(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"../../etc/passwd", "/abs", "a/b", strings.Repeat("x", 4096)} {
		p := holder.SocketPath("/run/dir", id)
		if filepath.Dir(p) != "/run/dir" || len(filepath.Base(p)) != len("0123456789abcdef.sock") {
			t.Errorf("id %.20q gave %q", id, p)
		}
	}
}

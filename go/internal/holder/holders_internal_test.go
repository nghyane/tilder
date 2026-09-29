//go:build unix

package holder

import (
	"context"
	"os/exec"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/nghyane/tilder/go/internal/testutil"
)

// Under systemd a holder must leave the agent's cgroup, or stopping the
// agent's unit takes every shell with it.
func TestUnderSystemdAHolderStartsInAScopeOfItsOwn(t *testing.T) {
	t.Parallel()
	name, args := holderCommand("/bin/tilder", "/run/d", "s1", 80, 24, "", true)
	want := []string{"--user", "--scope", "--collect", "--quiet", "--", "/bin/tilder", "hold", "--run", "/run/d", "--id", "s1", "--cols", "80", "--rows", "24"}
	if name != "systemd-run" || !slices.Equal(args, want) {
		t.Fatalf("%s %q", name, args)
	}
	if name, _ := holderCommand("/bin/tilder", "/run/d", "s1", 80, 24, "", false); name != "/bin/tilder" {
		t.Fatalf("outside systemd, started through %s", name)
	}
}

// A shell opened on a folder starts there: the holder is told where (ADR 0024).
func TestAHolderIsToldWhereItsShellStarts(t *testing.T) {
	t.Parallel()
	_, args := holderCommand("/bin/tilder", "/run/d", "s1", 80, 24, "/home/me/src/api", false)
	if i := slices.Index(args, "--dir"); i < 0 || i+1 >= len(args) || args[i+1] != "/home/me/src/api" {
		t.Fatalf("no --dir in %q", args)
	}
	if _, args := holderCommand("/bin/tilder", "/run/d", "s1", 80, 24, "", false); slices.Contains(args, "--dir") {
		t.Fatalf("--dir with no folder: %q", args)
	}
}

// A holder that ended is reaped: the agent waits for its children, or each
// shell ever closed stays in the process table as a zombie until the agent
// exits.
func TestAnEndedHolderLeavesNoZombie(t *testing.T) {
	t.Parallel()
	cmd := exec.CommandContext(context.Background(), "/bin/sh", "-c", "exit 0")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := startDetached(cmd); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	// A zombie still answers signal 0; a reaped process is gone (ESRCH).
	deadline := time.After(testutil.WaitShort) //nolint:forbidigo // a real process exits in real time
	for syscall.Kill(pid, 0) == nil {
		select {
		case <-deadline:
			t.Fatalf("pid %d is still in the process table: not reaped", pid)
		case <-time.After(10 * time.Millisecond): //nolint:forbidigo // polling a real process
		}
	}
}

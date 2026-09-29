//go:build windows

package holder

import (
	"errors"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// detach starts the holder with no console of its own, in a process group of
// its own, and out of the agent's job (ADR 0044): Task Scheduler runs the
// agent in a job, and a holder left in it would end with the agent, as
// tailscale's s4u and OpenSSH for Windows break their sessions away.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP | windows.CREATE_BREAKAWAY_FROM_JOB,
		HideWindow:    true,
	}
}

// refused: nobody listens on the socket (a stale one); Winsock's own error,
// which syscall.ECONNREFUSED never matches on Windows.
func refused(err error) bool { return errors.Is(err, windows.WSAECONNREFUSED) }

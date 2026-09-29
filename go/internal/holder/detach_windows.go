//go:build windows

package holder

import (
	"context"
	"errors"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// startHolder starts the holder with no console of its own, in a process
// group of its own, and out of the agent's job when it can (ADR 0044), as
// tailscale's s4u and OpenSSH for Windows break their sessions away. A job
// without JOB_OBJECT_LIMIT_BREAKAWAY_OK fails CreateProcess with
// ERROR_ACCESS_DENIED (CreateProcess's documentation; a CI runner's job does);
// the holder then starts inside that job and lives as long as it lets it.
// Its life is its own, not a request's: no context to cancel it.
func startHolder(name string, args []string) error {
	const flags = windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP
	err := startDetached(holderCmd(name, args, flags|windows.CREATE_BREAKAWAY_FROM_JOB))
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return startDetached(holderCmd(name, args, flags))
	}
	return err
}

// holderCmd is a fresh command each try: an exec.Cmd is not started twice.
func holderCmd(name string, args []string, flags uint32) *exec.Cmd {
	cmd := exec.CommandContext(context.Background(), name, args...) //nolint:gosec // G204: this binary, re-run as a holder
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags, HideWindow: true}
	return cmd
}

// refused: nobody listens on the socket (a stale one); Winsock's own error,
// which syscall.ECONNREFUSED never matches on Windows.
func refused(err error) bool { return errors.Is(err, windows.WSAECONNREFUSED) }

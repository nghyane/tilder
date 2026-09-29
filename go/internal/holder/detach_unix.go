//go:build unix

package holder

import (
	"errors"
	"os/exec"
	"syscall"
)

// detach starts the holder in its own session: setsid spares it the agent's
// hangup.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

// refused: nobody listens on the socket (a stale one).
func refused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

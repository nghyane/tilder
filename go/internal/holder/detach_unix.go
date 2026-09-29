//go:build unix

package holder

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
)

// startHolder starts the holder in its own session: setsid spares it the
// agent's hangup. Its life is its own, not a request's: no context to cancel
// it.
func startHolder(name string, args []string) error {
	cmd := exec.CommandContext(context.Background(), name, args...) //nolint:gosec // G204: this binary, re-run as a holder
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return startDetached(cmd)
}

// refused: nobody listens on the socket (a stale one).
func refused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

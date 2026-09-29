package holder

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
)

// RunHolder is the holder process (ADR 0005): it starts shell id, serves it on
// its socket, and returns once the shell has exited and the exit has been
// kept ExitedTTL for a late attach. Cancelling ctx kills the shell.
func RunHolder(ctx context.Context, cfg Config, runDir, id string, cols, rows uint16) error {
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(runDir, 0o700); err != nil { //nolint:gosec // G302: a directory needs x to be entered; 0700 is owner-only
		return err
	}
	path := SocketPath(runDir, id)
	switch state, probeErr := probe(path); state {
	case holderAbsent:
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err // a stale socket from a holder that died
		}
	case holderAlive:
		return fmt.Errorf("shell %q is already held", id)
	default:
		return fmt.Errorf("socket for shell %q is in use: %w", id, probeErr)
	}
	shell, err := NewManager(cfg).Start(id, cols, rows)
	if err != nil {
		return err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		shell.Kill()
		return err
	}
	ln.SetUnlinkOnClose(true)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		shell.Kill()
		return err
	}
	served := make(chan error, 1)
	go func() { served <- Serve(ln, shell, id) }()

	select {
	case <-shell.Done():
		// Linger so an agent reconnecting just now hears the exit.
		ttl := cfg.ExitedTTL
		if ttl <= 0 {
			ttl = DefaultExitedTTL
		}
		select {
		case <-cfg.Clock.NewTimer(ttl, "holder-linger").C:
		case <-ctx.Done(): // told to stop while lingering: go now
		}
	case <-ctx.Done():
		shell.Kill() // told to stop: end the shell and go
		<-shell.Done()
	}
	_ = ln.Close()
	return <-served
}

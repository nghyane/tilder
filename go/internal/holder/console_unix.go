//go:build unix

package holder

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
)

// unixConsole is a PTY whose shell leads its own session.
type unixConsole struct {
	cmd *exec.Cmd
	pty *os.File
}

func startConsole(cfg Config, dir string, cols, rows uint16) (console, error) {
	// The owner's own shell, chosen by cmd/ from $SHELL: running it is the
	// point. Its life is its own, not a request's, hence no context to cancel.
	cmd := exec.CommandContext(context.Background(), cfg.Shell, cfg.Args...) //nolint:gosec // G204: the owner's shell, by design
	cmd.Env = cfg.Env
	cmd.Dir = dir
	// StartWithSize sets Setsid and Setctty: the shell leads its own session
	// and process group, which Kill signals as a whole.
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: cols, Rows: rows})
	if err != nil {
		return nil, fmt.Errorf("start shell: %w", err)
	}
	polled, err := pollable(f)
	if err != nil {
		_ = f.Close()
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("start shell: %w", err)
	}
	return &unixConsole{cmd: cmd, pty: polled}, nil
}

func (c *unixConsole) Read(p []byte) (int, error)  { return c.pty.Read(p) }
func (c *unixConsole) Write(p []byte) (int, error) { return c.pty.Write(p) }
func (c *unixConsole) resize(cols, rows uint16) error {
	return setSize(c.pty, cols, rows)
}
func (c *unixConsole) pid() int { return c.cmd.Process.Pid }

func (c *unixConsole) wait() int {
	var exit *exec.ExitError
	if err := c.cmd.Wait(); errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return 0
}

// The shell leads its session (Setsid): its pid is the session's id.
func (c *unixConsole) hangup()      { signalSession(c.pid(), syscall.SIGHUP) }
func (c *unixConsole) killAll()     { signalSession(c.pid(), syscall.SIGKILL) }
func (c *unixConsole) closeOutput() { _ = c.pty.Close() }

// signalSession signals every process group in the shell's session — the
// shell and each of its jobs. The v1 agent signalled one pid, and a first
// version here signalled only the shell's group: on Linux an interactive
// shell's background jobs have groups of their own and survived (the Linux
// gate caught it).
func signalSession(sid int, sig syscall.Signal) {
	groups := append(sessionGroups(sid), sid)
	for _, pgrp := range groups {
		_ = syscall.Kill(-pgrp, sig)
	}
}

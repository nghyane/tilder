//go:build windows

package service

import (
	"context"
	"os"
	"os/exec"
)

// Respawn starts binary with args and this process's console, for an
// agent run by hand to hand over to its new release: Windows has no exec
// (ADR 0044). The caller then exits.
func Respawn(ctx context.Context, binary string, args []string) error {
	cmd := exec.CommandContext(context.WithoutCancel(ctx), binary, args...) //nolint:gosec // G204: our own binary, just verified
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	return cmd.Start()
}

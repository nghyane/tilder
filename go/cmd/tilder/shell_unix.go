//go:build unix

package main

import (
	"os"

	"github.com/nghyane/tilder/go/internal/clock"
	"github.com/nghyane/tilder/go/internal/holder"
)

// shellConfig is how shells start, from the owner's environment.
func shellConfig() holder.Config {
	return holder.Config{
		Shell: envOr("SHELL", "/bin/sh"), Args: []string{"-l"},
		Env:      append(os.Environ(), "TERM=xterm-256color"),
		Dir:      envOr("HOME", "/"),
		RingSize: 1 << 20, Clock: clock.Real(),
	}
}

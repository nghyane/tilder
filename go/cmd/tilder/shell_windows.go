//go:build windows

package main

import (
	"os"

	"github.com/nghyane/tilder/go/internal/clock"
	"github.com/nghyane/tilder/go/internal/holder"
)

// shellConfig is how shells start on Windows (ADR 0044): the shell
// holder.DefaultShell finds, in the user's profile folder.
func shellConfig() holder.Config {
	shell, args := holder.DefaultShell(envOr("COMSPEC", `C:\Windows\System32\cmd.exe`))
	return holder.Config{
		Shell: shell, Args: args,
		Env:      append(os.Environ(), "TERM=xterm-256color"),
		Dir:      envOr("USERPROFILE", `C:\`),
		RingSize: 1 << 20, Clock: clock.Real(),
	}
}

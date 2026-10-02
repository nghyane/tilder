//go:build !windows

package main

import (
	"os"
	"syscall"
)

// replaceSelf runs binary in this process's place, with the same arguments.
func replaceSelf(binary string) error {
	return syscall.Exec(binary, os.Args, os.Environ()) //nolint:gosec // G204: our own binary, just verified
}

//go:build windows

package main

import (
	"context"
	"os"

	"github.com/nghyane/tilder/go/internal/service"
)

// replaceSelf starts binary with the same arguments and lets this process
// end: Windows has no exec.
func replaceSelf(binary string) error {
	return service.Respawn(context.Background(), binary, os.Args[1:])
}

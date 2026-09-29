//go:build windows

package holder

import (
	"context"
	"errors"
)

// WorkingDir is not read on Windows yet (ADR 0044): there is no /proc, and
// the shell reporting its folder (OSC 7) is a small ADR of its own. A tab
// keeps the folder it opened in.
func WorkingDir(context.Context, int) (string, error) {
	return "", errors.New("holder: the shell's folder is not known on Windows")
}

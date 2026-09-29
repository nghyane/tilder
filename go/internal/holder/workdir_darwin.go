package holder

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
)

// WorkingDir is process pid's working directory: the folder a shell is in,
// which cd really changes (ADR 0024); asking the system needs nothing from
// the shell, whichever it is. macOS has no /proc; lsof, on every
// Mac, reads it from the kernel (proc_pidinfo) without cgo here. -Fn prints
// one field per line: "p<pid>", "fcwd", "n<path>".
func WorkingDir(ctx context.Context, pid int) (string, error) {
	out, err := exec.CommandContext(ctx, "/usr/sbin/lsof", "-a", "-p", strconv.Itoa(pid), "-d", "cwd", "-Fn").Output() //nolint:gosec // G204: a fixed program, a number
	if err != nil {
		return "", err
	}
	lines := bufio.NewScanner(bytes.NewReader(out))
	for lines.Scan() {
		if path, ok := strings.CutPrefix(lines.Text(), "n"); ok && path != "" {
			return path, nil
		}
	}
	return "", errors.New("holder: lsof named no working directory")
}

//go:build unix

package holder

import (
	"os"

	"golang.org/x/sys/unix"
)

// setSize sets a PTY's size without Fd(): Fd() puts the file back in
// blocking mode (undoing pollable) and races with Close.
func setSize(f *os.File, cols, rows uint16) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ioctlErr error
	if err := raw.Control(func(fd uintptr) {
		ioctlErr = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols}) //nolint:gosec // G115: fds fit in int
	}); err != nil {
		return err
	}
	return ioctlErr
}

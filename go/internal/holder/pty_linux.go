package holder

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// pollable swaps f, the PTY master creack/pty returns in blocking mode, for
// a non-blocking copy the runtime polls (tmux keeps the pane non-blocking):
// a blocking write to a program that reads nothing never returns, not even
// after the shell is killed, and would pin the holder for good. A polled
// write ends when the file closes.
func pollable(f *os.File) (*os.File, error) {
	raw, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd, dupErr := -1, error(nil)
	if err := raw.Control(func(old uintptr) {
		fd, dupErr = unix.FcntlInt(old, unix.F_DUPFD_CLOEXEC, 0)
	}); err != nil {
		return nil, err
	}
	if dupErr != nil {
		return nil, fmt.Errorf("duplicate pty: %w", dupErr)
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	p := os.NewFile(uintptr(fd), f.Name())
	_ = f.Close()
	return p, nil
}

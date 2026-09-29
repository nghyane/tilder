//go:build windows

package files

import (
	"errors"

	"golang.org/x/sys/windows"
)

// platformCode maps the Windows errors mapErr's POSIX names never match:
// on Windows syscall.ENOTDIR and its kin are invented values no call returns.
func platformCode(err error) Code {
	switch {
	case errors.Is(err, windows.ERROR_DIRECTORY):
		return NotDir
	case errors.Is(err, windows.ERROR_DIR_NOT_EMPTY):
		return Exists
	case errors.Is(err, windows.ERROR_DISK_FULL), errors.Is(err, windows.ERROR_HANDLE_DISK_FULL):
		return NoSpace
	default:
		return 0
	}
}

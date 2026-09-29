//go:build unix

package files

import "syscall"

// openNonblock keeps an open from blocking on a FIFO or a device.
const openNonblock = syscall.O_NONBLOCK

//go:build unix

package transfer

import "syscall"

// syscallNoFollow refuses a link as the last name of what a copy opens.
const syscallNoFollow = syscall.O_NOFOLLOW

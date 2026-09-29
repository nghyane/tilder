//go:build unix

package holder_test

import (
	"os"
	"strconv"
	"syscall"
	"testing"
)

func atoi(t *testing.T, s string) int {
	t.Helper()
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// syscallZero is signal 0: it checks a process exists without touching it.
func syscallZero() os.Signal { return syscall.Signal(0) }

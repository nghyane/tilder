package holder

import (
	"context"
	"os"
	"strconv"
)

// WorkingDir is process pid's working directory: the folder a shell is in,
// which cd really changes (ADR 0024); asking the system needs nothing from
// the shell, whichever it is.
func WorkingDir(_ context.Context, pid int) (string, error) {
	return os.Readlink("/proc/" + strconv.Itoa(pid) + "/cwd")
}

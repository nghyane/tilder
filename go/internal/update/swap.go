package update

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// renameRunning says the running binary must be renamed to make way for a
// new one (ADR 0044): Windows renames a running executable but neither
// deletes it nor lets another file take its name. Elsewhere a hard link
// keeps the old binary and it never leaves its path.
var renameRunning = runtime.GOOS == "windows"

// keepPrevious keeps the running binary as binary.prev, to roll back to.
func keepPrevious(binary string, byRename bool) error {
	prev := binary + ".prev"
	if err := clearName(prev); err != nil {
		return fmt.Errorf("make way for the previous binary: %w", err)
	}
	if byRename {
		return os.Rename(binary, prev)
	}
	return os.Link(binary, prev)
}

// putNew renames the checked download into the binary's place. Renamed
// away, the old binary comes back if the new one cannot take its place:
// the path is never left empty for the service to find.
func putNew(binary, unverified string, byRename bool) error {
	err := os.Rename(unverified, binary)
	if err != nil && byRename {
		_ = os.Rename(binary+".prev", binary)
	}
	return err
}

// putBack puts binary.prev in the binary's place. Renamed away first, the
// binary that failed may still be running.
func putBack(binary string, byRename bool) error {
	if byRename {
		if err := aside(binary); err != nil {
			return fmt.Errorf("move the failed release aside: %w", err)
		}
	}
	return os.Rename(binary+".prev", binary)
}

// clearName frees path for a new file: removed, or, still running (a
// holder or the Windows monitor started from it), renamed aside to be
// removed later by CleanOld.
func clearName(path string) error {
	err := os.Remove(path)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return aside(path)
}

// aside renames path to a unique *.old name beside it.
func aside(path string) error {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	return os.Rename(path, path+"."+hex.EncodeToString(b)+".old")
}

// CleanOld removes the binaries moved aside by earlier updates that nothing
// runs any more; one still running stays until a later start.
func CleanOld(binary string) {
	old, _ := filepath.Glob(binary + "*.old")
	for _, f := range old {
		_ = os.Remove(f)
	}
}

//go:build windows

package update

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// secImage is SEC_IMAGE (winnt.h), which x/sys/windows does not name.
const secImage = 0x1000000

// runningImage maps path as an executable image, the way Windows' loader
// maps a running program: renaming it works, deleting it does not. It
// stands in for a holder or the monitor still running the previous agent.
func runningImage(t *testing.T, path string) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	f, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_EXECUTE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(f) }()
	m, err := windows.CreateFileMapping(f, nil, windows.PAGE_EXECUTE_READ|secImage, 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(m) })
}

// The previous binary still runs: Windows will not delete it, so it is
// moved aside and the update goes on (ADR 0044).
func TestAPreviousBinaryStillRunningIsMovedAside(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bin := filepath.Join(dir, "tilder.exe")
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(self) //nolint:gosec // G304: this test binary, a real executable image
	if err != nil {
		t.Fatal(err)
	}
	write(t, bin+".prev", string(data))
	runningImage(t, bin+".prev")
	if err := os.Remove(bin + ".prev"); err == nil {
		t.Fatal("the stand-in for a running binary could be deleted: it stands in for nothing")
	}
	write(t, bin, "old")

	if err := keepPrevious(bin, true); err != nil {
		t.Fatalf("keepPrevious with the previous binary running: %v", err)
	}
	if got := read(t, bin+".prev"); got != "old" {
		t.Fatalf("prev = %q, want old", got)
	}
	if old, _ := filepath.Glob(bin + ".prev.*.old"); len(old) != 1 {
		t.Fatalf("the running previous binary was not moved aside: %v", old)
	}
}

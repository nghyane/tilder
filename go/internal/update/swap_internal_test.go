package update

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o700); err != nil { //nolint:gosec // G306: a stand-in executable
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: the test's temp dir
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

// Both ways run everywhere: by hard link (Unix) and by rename (Windows,
// ADR 0044), so the Windows one is tested on every machine, not only on
// the public repo's Windows runner.
var ways = []struct {
	name     string
	byRename bool
}{{"by link", false}, {"by rename", true}}

func TestASwapKeepsTheOldBinaryAndPutsTheNewOneInItsPlace(t *testing.T) {
	t.Parallel()
	for _, w := range ways {
		t.Run(w.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			bin := filepath.Join(dir, "tilder")
			write(t, bin, "old")
			write(t, bin+".prev", "older") // from the update before
			write(t, bin+".unverified", "new")
			if err := keepPrevious(bin, w.byRename); err != nil {
				t.Fatal(err)
			}
			if err := putNew(bin, bin+".unverified", w.byRename); err != nil {
				t.Fatal(err)
			}
			if got := read(t, bin); got != "new" {
				t.Fatalf("binary = %q, want new", got)
			}
			if got := read(t, bin+".prev"); got != "old" {
				t.Fatalf("prev = %q, want old", got)
			}
		})
	}
}

// The path the service starts is never left empty: a new binary that
// cannot take the place gives it back to the old one.
func TestARenamedBinaryComesBackWhenTheNewOneCannotTakeItsPlace(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bin := filepath.Join(dir, "tilder")
	write(t, bin, "old")
	if err := keepPrevious(bin, true); err != nil {
		t.Fatal(err)
	}
	if err := putNew(bin, bin+".missing", true); err == nil {
		t.Fatal("putNew of a missing download succeeded")
	}
	if got := read(t, bin); got != "old" {
		t.Fatalf("binary = %q, want the old one back", got)
	}
}

func TestPuttingBackRestoresThePreviousBinary(t *testing.T) {
	t.Parallel()
	for _, w := range ways {
		t.Run(w.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			bin := filepath.Join(dir, "tilder")
			write(t, bin, "failed")
			write(t, bin+".prev", "good")
			if err := putBack(bin, w.byRename); err != nil {
				t.Fatal(err)
			}
			if got := read(t, bin); got != "good" {
				t.Fatalf("binary = %q, want good", got)
			}
			// By rename, the failed one waits aside until nothing runs it.
			CleanOld(bin)
			left, _ := filepath.Glob(filepath.Join(dir, "*"))
			if len(left) != 1 {
				t.Fatalf("left behind: %v", left)
			}
		})
	}
}

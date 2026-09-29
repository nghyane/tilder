//go:build unix

package files_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/coder/quartz"
	"go.uber.org/goleak"

	"github.com/nghyane/tilder/go/internal/agent/files"
	"github.com/nghyane/tilder/go/internal/testutil"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m, testutil.GoleakOptions...) }

const secret = "machine key"

// home is a home directory with the agent's own inside and every trap the
// research found: links up and out, a link into the agent's directory, a
// hard link to its key, a FIFO.
func home(t *testing.T) (*files.Tree, string) {
	t.Helper()
	h := t.TempDir()
	mk := func(p, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(h, p)), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(h, p), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ln := func(target, p string) {
		t.Helper()
		if err := os.Symlink(target, filepath.Join(h, p)); err != nil {
			t.Fatal(err)
		}
	}
	mk(".tilder/identity.json", secret)
	mk("proj/a.txt", "hello")
	mk("proj/sub/b.txt", "below")
	ln("../.tilder/identity.json", "proj/key")
	ln("/etc/hosts", "proj/abs")
	ln("sub/b.txt", "proj/down")
	ln("..", "proj/up")
	ln(".tilder", "agent") // at the top: points down, into the agent's directory
	if err := os.Link(filepath.Join(h, ".tilder/identity.json"), filepath.Join(h, "proj/hard")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(h, "proj/fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	return files.New(h, filepath.Join(h, ".tilder"), quartz.NewMock(t)), h
}

func read(t *testing.T, tree *files.Tree, path string) (string, error) {
	t.Helper()
	f, _, err := tree.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	return string(b), err
}

func code(err error) files.Code {
	if err == nil {
		return 0
	}
	return files.CodeOf(err)
}

// No path reaches the agent's key: not through a link up, a link down into
// its directory, a hard link, another case, or ".." (ADR 0022).
func TestNothingReachesTheAgentsDirectory(t *testing.T) {
	t.Parallel()
	tree, h := home(t)
	for path, want := range map[string]files.Code{
		".tilder/identity.json":         files.Denied,
		"agent/identity.json":           files.Denied,
		"agent":                         files.NotRegular, // the directory itself, opened as a file
		"proj/key":                      files.Denied,
		"proj/up/.tilder/identity.json": files.Denied,
		"proj/hard":                     files.Denied,
		"proj/abs":                      files.Denied,
		"proj/../.tilder/identity.json": files.Invalid,
		"/etc/hosts":                    files.Invalid,
		"proj//a.txt":                   files.Invalid,
		"proj/./a.txt":                  files.Invalid,
		"proj/a\x00.txt":                files.Invalid,
	} {
		got, err := read(t, tree, path)
		if got == secret || code(err) != want {
			t.Errorf("%q: got %q, code %v, want code %v", path, got, code(err), want)
		}
	}
	// A case-insensitive disk (APFS) reaches the same directory by another name.
	if _, err := os.Stat(filepath.Join(h, ".TILDER")); err == nil {
		if got, err := read(t, tree, ".TILDER/identity.json"); got == secret || code(err) != files.Denied {
			t.Errorf(".TILDER: got %q, %v", got, err)
		}
	}
	for _, list := range []string{".tilder", "agent", "proj/up/.tilder"} {
		if _, _, _, err := tree.List(list, "", 100); code(err) != files.Denied {
			t.Errorf("listed %q: %v", list, err)
		}
	}
	if _, err := tree.BeginWrite(".tilder/identity.json", nil, false); code(err) != files.Denied {
		t.Errorf("began a write into the agent's directory: %v", err)
	}
	if err := tree.Rename("proj/a.txt", ".tilder/x", false); code(err) != files.Denied {
		t.Errorf("renamed into the agent's directory: %v", err)
	}
}

func TestLinksBelowAreFollowedAndLinksAboveAreShown(t *testing.T) {
	t.Parallel()
	tree, _ := home(t)
	if got, err := read(t, tree, "proj/down"); err != nil || got != "below" {
		t.Fatalf("a link below: %q, %v", got, err)
	}
	entries, _, _, err := tree.List("proj", "", 100)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]files.Entry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	if e := byName["key"]; e.Kind != files.Symlink || !e.Dangling || e.LinkTarget != "../.tilder/identity.json" {
		t.Errorf("the link up: %+v", e)
	}
	if e := byName["down"]; e.Kind != files.Symlink || e.Dangling || e.LinkKind != files.File {
		t.Errorf("the link down: %+v", e)
	}
	if e := byName["fifo"]; e.Kind != files.Other {
		t.Errorf("the fifo: %+v", e)
	}
}

// A FIFO (or device) is refused at once; opening it plainly would block.
func TestAFIFOIsRefusedWithoutBlocking(t *testing.T) {
	t.Parallel()
	tree, _ := home(t)
	done := make(chan error, 1)
	go func() {
		_, err := read(t, tree, "proj/fifo")
		done <- err
	}()
	select {
	case err := <-done:
		if code(err) != files.NotRegular {
			t.Fatalf("got %v", err)
		}
	case <-testutil.Context(t, testutil.WaitShort).Done():
		t.Fatal("opening the fifo blocked")
	}
}

func write(t *testing.T, tree *files.Tree, path, body string, etag []byte, createOnly bool) (files.Entry, error) {
	t.Helper()
	w, err := tree.BeginWrite(path, etag, createOnly)
	if err != nil {
		return files.Entry{}, err
	}
	if _, err := w.Write([]byte(body)); err != nil {
		w.Abort()
		return files.Entry{}, err
	}
	return w.Commit()
}

// A write lands whole or not at all, only over the version the writer read.
func TestWritesAreAtomicAndCheckTheVersion(t *testing.T) {
	t.Parallel()
	tree, h := home(t)
	if err := os.Chmod(filepath.Join(h, "proj/a.txt"), 0o400); err != nil {
		t.Fatal(err)
	}
	f, opened, err := tree.Open("proj/a.txt")
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	// Someone else rewrites it since (vim, another device): refused, their file intact.
	if err = os.WriteFile(filepath.Join(h, "proj/theirs"), []byte("theirs!"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(filepath.Join(h, "proj/theirs"), filepath.Join(h, "proj/a.txt")); err != nil {
		t.Fatal(err)
	}
	if _, err = write(t, tree, "proj/a.txt", "mine", opened.ETag, false); code(err) != files.Conflict {
		t.Fatalf("stale etag: %v", err)
	}
	if got, _ := read(t, tree, "proj/a.txt"); got != "theirs!" {
		t.Fatalf("a refused write changed the file: %q", got)
	}
	current, _ := tree.Stat("proj/a.txt")
	written, err := write(t, tree, "proj/a.txt", "mine", current.ETag, false)
	if err != nil || written.Perm != 0o400 {
		t.Fatalf("write: %+v, %v", written, err)
	}
	if got, _ := read(t, tree, "proj/a.txt"); got != "mine" {
		t.Fatalf("got %q", got)
	}
	if _, err := write(t, tree, "proj/a.txt", "x", nil, true); code(err) != files.Exists {
		t.Fatalf("create-only over a file: %v", err)
	}
	if _, err := write(t, tree, "proj/down", "x", nil, false); code(err) != files.NotRegular {
		t.Fatalf("wrote through a link: %v", err)
	}
	if _, err := write(t, tree, "proj/new.txt", "fresh", nil, true); err != nil {
		t.Fatalf("create-only: %v", err)
	}
}

// Two writers of one file never share a temp file, and temps never show.
func TestConcurrentWritesDoNotCollideAndTempsStayHidden(t *testing.T) {
	t.Parallel()
	tree, _ := home(t)
	a, err := tree.BeginWrite("proj/a.txt", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := tree.BeginWrite("proj/a.txt", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.Write([]byte("from a"))
	_, _ = b.Write([]byte("from b"))
	entries, _, _, _ := tree.List("proj", "", 100)
	for _, e := range entries {
		if e.Name != "a.txt" && len(e.Name) > 5 && e.Name[:5] == ".tilder." {
			t.Errorf("a temp file shows: %q", e.Name)
		}
	}
	if _, err := a.Commit(); err != nil {
		t.Fatal(err)
	}
	b.Abort()
	if got, _ := read(t, tree, "proj/a.txt"); got != "from a" {
		t.Fatalf("got %q", got)
	}
}

// Copies still arriving from another machine are hidden, in lists and
// watch events alike (ADR 0035).
func TestCopiesStillArrivingStayHidden(t *testing.T) {
	t.Parallel()
	h := t.TempDir()
	if err := os.MkdirAll(filepath.Join(h, "inbox", files.PartDir, "id"), 0o700); err != nil {
		t.Fatal(err)
	}
	tree := files.New(h, filepath.Join(h, ".tilder"), quartz.NewMock(t))
	entries, _, _, err := tree.List("inbox", "", 100)
	if err != nil || len(entries) != 0 {
		t.Fatalf("list = %v, %v; want nothing", entries, err)
	}
	if !files.IsTemp(files.PartDir) {
		t.Fatal("watch events for the part directory are not hidden")
	}
}

func TestListPagesAreStableAndSorted(t *testing.T) {
	t.Parallel()
	tree, h := home(t)
	for _, n := range []string{"c", "a", "b", "e", "d"} {
		if err := os.WriteFile(filepath.Join(h, "proj/sub", n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var names []string
	after := ""
	for {
		page, next, _, err := tree.List("proj/sub", after, 2)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range page {
			names = append(names, e.Name)
		}
		if next == "" {
			break
		}
		after = next
	}
	if !slices.Equal(names, []string{"a", "b", "b.txt", "c", "d", "e"}) {
		t.Fatalf("pages: %v", names)
	}
}

// A recursive remove takes the link, never what it points at.
func TestRemovingFollowsNoLink(t *testing.T) {
	t.Parallel()
	tree, h := home(t)
	if err := tree.Remove("proj", true); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(h, ".tilder/identity.json")); err != nil || string(b) != secret { //nolint:gosec // G304: the test's own temp dir
		t.Fatalf("the agent's key went with it: %q, %v", b, err)
	}
}

func TestRenameWithoutReplacingKeepsTheTarget(t *testing.T) {
	t.Parallel()
	tree, _ := home(t)
	if err := tree.Rename("proj/a.txt", "proj/sub/b.txt", true); code(err) != files.Exists {
		t.Fatalf("got %v", err)
	}
	if got, _ := read(t, tree, "proj/sub/b.txt"); got != "below" {
		t.Fatalf("the target changed: %q", got)
	}
	if err := tree.Rename("proj/a.txt", "proj/sub/moved.txt", true); err != nil {
		t.Fatal(err)
	}
	if got, _ := read(t, tree, "proj/sub/moved.txt"); got != "hello" {
		t.Fatalf("got %q", got)
	}
	var e *files.Error
	if err := tree.Mkdir("proj/sub"); !errors.As(err, &e) || e.Code != files.Exists {
		t.Fatalf("mkdir over a directory: %v", err)
	}
}

// A temp file left by a write that never finished is cleared after a day.
func TestStaleTempsAreCleared(t *testing.T) {
	t.Parallel()
	h := t.TempDir()
	clk := quartz.NewMock(t)
	tree := files.New(h, filepath.Join(h, ".tilder"), clk)
	stale := filepath.Join(h, ".tilder.a.txt.deadbeef.tmp")
	if err := os.WriteFile(stale, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	old := clk.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(stale, old, old); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := tree.List("", "", 10); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("the stale temp is still there")
	}
}

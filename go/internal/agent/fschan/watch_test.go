package fschan_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// quiet reports whether nothing arrives for a moment.
func (c *client) quiet(d time.Duration) bool {
	ctx, cancel := context.WithTimeout(c.t.Context(), d)
	defer cancel()
	select {
	case <-c.inbox:
		return false
	case <-ctx.Done():
		return true
	}
}

func (c *client) watch(id uint32, path string) *tilderv1.FsServer {
	c.t.Helper()
	c.send(id, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Watch{Watch: &tilderv1.FsWatch{Path: []byte(path)}}})
	return c.recv()
}

func TestAWatchedDirectoryReportsChangedNamesTogether(t *testing.T) {
	t.Parallel()
	c, h := serve(t)
	dir := filepath.Join(h, "proj")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if c.watch(1, "proj").GetOk() == nil {
		t.Fatal("no watch")
	}
	for _, n := range []string{"a.txt", "b.txt", ".tilder.a.txt.0000.tmp"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The names are gathered on the real clock: under load the writes can
	// straddle two gatherings, so read batches until both names are in. The
	// console's own temporary file never shows, and nothing asks for a rescan.
	names := map[string]bool{}
	for !names["a.txt"] || !names["b.txt"] {
		changed := c.recv().GetChanged()
		for _, n := range changed.GetNames() {
			names[string(n)] = true
		}
		if names[".tilder.a.txt.0000.tmp"] || changed.GetRescan() {
			t.Fatalf("got %v", changed)
		}
	}
	// A change of permissions alone is not news.
	if err := os.Chmod(filepath.Join(dir, "a.txt"), 0o400); err != nil {
		t.Fatal(err)
	}
	if !c.quiet(600 * time.Millisecond) {
		t.Fatal("a chmod was reported")
	}
	// After Unwatch, nothing more.
	c.send(1, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Unwatch{Unwatch: &tilderv1.FsUnwatch{}}})
	if err := os.WriteFile(filepath.Join(dir, "c.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !c.quiet(600 * time.Millisecond) {
		t.Fatal("a change after unwatch was reported")
	}
}

func TestManyChangesAskForAFullLook(t *testing.T) {
	t.Parallel()
	c, h := serve(t)
	dir := filepath.Join(h, "burst")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	c.watch(1, "burst")
	for i := range 200 {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprint(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The console hears of every change: named, or asked to look again. A
	// batch past perDir asks; on a busy machine the burst spreads over
	// several gathering windows under perDir each, and every name comes
	// (waiting for a rescan alone then hung: the push hook's load did it).
	named := map[string]bool{}
	for len(named) < 200 {
		changed := c.recv().GetChanged()
		if changed.GetRescan() {
			return
		}
		for _, n := range changed.GetNames() {
			named[string(n)] = true
		}
	}
}

// The agent's directory cannot be watched either: its file names and
// changes are not the console's to see.
func TestTheAgentsDirectoryCannotBeWatched(t *testing.T) {
	t.Parallel()
	c, h := serve(t)
	if err := os.Symlink(".tilder", filepath.Join(h, "agent")); err != nil {
		t.Fatal(err)
	}
	for i, path := range []string{".tilder", "agent"} {
		if got := c.watch(uint32(i+1), path).GetError().GetCode(); got != tilderv1.FsError_CODE_DENIED {
			t.Errorf("%s: got %v", path, got)
		}
	}
}

func TestWatchesAreBoundedPerChannel(t *testing.T) {
	t.Parallel()
	c, h := serve(t)
	for i := range 17 {
		name := fmt.Sprintf("d%02d", i)
		if err := os.MkdirAll(filepath.Join(h, name), 0o700); err != nil {
			t.Fatal(err)
		}
		reply := c.watch(uint32(i+1), name)
		if i < 16 && reply.GetOk() == nil {
			t.Fatalf("watch %d: %v", i, reply)
		}
		if i == 16 && reply.GetError().GetCode() != tilderv1.FsError_CODE_WATCH_LIMIT {
			t.Fatalf("one too many: %v", reply)
		}
	}
}

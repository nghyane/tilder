package transfer_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nghyane/tilder/go/internal/agent/xferchan"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// A folder arrives whole and as it was: every file byte for byte, links as
// links, permissions and times, and nothing left of the part.
func TestAFolderArrivesWholeAndAsItWas(t *testing.T) {
	t.Parallel()
	s := newSetup(t, "proj", "inbox/proj")
	write(t, s.src, "proj/a.txt", []byte("alpha"))
	write(t, s.src, "proj/lib/big.bin", big(5*xferchan.ChunkSize/2))
	write(t, s.src, "proj/lib/empty", nil)
	if err := os.Symlink("a.txt", filepath.Join(s.src, "proj/link")); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // G302: the mode is what is copied
	if err := os.Chmod(filepath.Join(s.src, "proj/a.txt"), 0o751); err != nil {
		t.Fatal(err)
	}
	when := time.Unix(1_700_000_000, 0)
	if err := os.Chtimes(filepath.Join(s.src, "proj/lib/big.bin"), when, when); err != nil {
		t.Fatal(err)
	}
	write(t, s.dst, "inbox/.keep", nil)

	p := s.run(context.Background(), t, s.job(t))
	if !p.Ended || p.Code != tilderv1.XferFailed_CODE_UNSPECIFIED || p.FilesDone != 3 || p.Bytes != p.Total {
		t.Fatalf("copy ended %+v", p)
	}
	for _, f := range []string{"a.txt", "lib/big.bin", "lib/empty"} {
		if sum(t, filepath.Join(s.src, "proj", f)) != sum(t, filepath.Join(s.dst, "inbox/proj", f)) {
			t.Fatalf("%s differs", f)
		}
	}
	if target, err := os.Readlink(filepath.Join(s.dst, "inbox/proj/link")); err != nil || target != "a.txt" {
		t.Fatalf("link = %q, %v", target, err)
	}
	if info, _ := os.Stat(filepath.Join(s.dst, "inbox/proj/a.txt")); info.Mode().Perm() != 0o751 {
		t.Fatalf("perm = %v", info.Mode().Perm())
	}
	if info, _ := os.Stat(filepath.Join(s.dst, "inbox/proj/lib/big.bin")); !info.ModTime().Equal(when) {
		t.Fatalf("mtime = %v", info.ModTime())
	}
	noPart(t, filepath.Join(s.dst, "inbox"))
}

// A cut mid-copy is resumed from the first chunk missing, not from the start.
func TestACutCopyResumesFromTheFirstMissingChunk(t *testing.T) {
	t.Parallel()
	s := newSetup(t, "big.bin", "big.bin")
	data := big(6 * xferchan.ChunkSize)
	write(t, s.src, "big.bin", data)
	s.source.next = func(p *pipe) { p.cutAfter = 3 }

	p := s.run(context.Background(), t, s.job(t))
	if !p.Ended || p.Code != tilderv1.XferFailed_CODE_UNSPECIFIED {
		t.Fatalf("copy ended %+v", p)
	}
	if sum(t, filepath.Join(s.src, "big.bin")) != sum(t, filepath.Join(s.dst, "big.bin")) {
		t.Fatal("the resumed file differs")
	}
	if w := <-s.source.conn(1).wants; w.GetFromChunk() != 3 {
		t.Fatalf("the second connection asked from chunk %d, want 3", w.GetFromChunk())
	}
	noPart(t, s.dst)
}

// A cut just as the last chunk's ack goes leaves a file with every chunk:
// the next connection finishes it, rather than asking the source for a
// chunk past its end and waiting for ever.
func TestACutAtTheLastAckStillFinishesTheFile(t *testing.T) {
	t.Parallel()
	s := newSetup(t, "big.bin", "big.bin")
	data := big(3 * xferchan.ChunkSize)
	write(t, s.src, "big.bin", data)
	s.source.next = func(p *pipe) { p.failAck = 3 }

	p := s.run(context.Background(), t, s.job(t))
	if !p.Ended || p.Code != tilderv1.XferFailed_CODE_UNSPECIFIED {
		t.Fatalf("copy ended %+v", p)
	}
	if sum(t, filepath.Join(s.src, "big.bin")) != sum(t, filepath.Join(s.dst, "big.bin")) {
		t.Fatal("the file differs")
	}
	noPart(t, s.dst)
}

// A name added in a folder while its copy is cut does not throw away what
// had already arrived in that folder: the copy ends with every file.
func TestAFolderThatChangedKeepsWhatArrived(t *testing.T) {
	t.Parallel()
	s := newSetup(t, "proj", "proj")
	write(t, s.src, "proj/d/first.bin", big(2*xferchan.ChunkSize))
	write(t, s.src, "proj/d/second.bin", big(2*xferchan.ChunkSize))
	s.source.next = func(p *pipe) {
		p.cutAfter = 3 // one file whole, one chunk of the other
		p.onCut = func() { write(t, s.src, "proj/d/new.txt", []byte("added\n")) }
	}

	p := s.run(context.Background(), t, s.job(t))
	if !p.Ended || p.Code != tilderv1.XferFailed_CODE_UNSPECIFIED {
		t.Fatalf("copy ended %+v", p)
	}
	for _, name := range []string{"proj/d/first.bin", "proj/d/second.bin", "proj/d/new.txt"} {
		if sum(t, filepath.Join(s.src, name)) != sum(t, filepath.Join(s.dst, name)) {
			t.Fatalf("%s differs", name)
		}
	}
	noPart(t, s.dst)
}

// A copy survives the agent stopping: the next run takes up where it was.
func TestACopyResumesAfterTheAgentRestarts(t *testing.T) {
	t.Parallel()
	s := newSetup(t, "big.bin", "big.bin")
	write(t, s.src, "big.bin", big(5*xferchan.ChunkSize))
	ctx, stop := context.WithCancel(context.Background())
	s.source.next = func(p *pipe) {
		p.cutAfter = 2
		go func() { // the agent stops once two chunks are in
			for p.ends.Load() < 2 {
				time.Sleep(time.Millisecond) //nolint:forbidigo // watching a real pipe
			}
			stop()
		}()
	}
	if p := s.run(ctx, t, s.job(t)); p.Ended {
		t.Fatalf("a stopping agent ended the copy: %+v", p)
	}
	p := s.run(context.Background(), t, s.job(t))
	if !p.Ended || p.Code != tilderv1.XferFailed_CODE_UNSPECIFIED {
		t.Fatalf("resumed copy ended %+v", p)
	}
	if w := <-s.source.conn(1).wants; w.GetFromChunk() == 0 {
		t.Fatal("the restarted copy began again from chunk 0")
	}
	if sum(t, filepath.Join(s.src, "big.bin")) != sum(t, filepath.Join(s.dst, "big.bin")) {
		t.Fatal("the resumed file differs")
	}
}

// A chunk whose bytes do not match its hash is never kept: it is asked for again.
func TestASpoiledChunkIsAskedForAgain(t *testing.T) {
	t.Parallel()
	s := newSetup(t, "f.bin", "f.bin")
	write(t, s.src, "f.bin", big(2*xferchan.ChunkSize))
	s.source.next = func(p *pipe) { p.spoil.Store(true) }
	if p := s.run(context.Background(), t, s.job(t)); p.Code != tilderv1.XferFailed_CODE_UNSPECIFIED {
		t.Fatalf("copy ended %+v", p)
	}
	if sum(t, filepath.Join(s.src, "f.bin")) != sum(t, filepath.Join(s.dst, "f.bin")) {
		t.Fatal("a spoiled chunk was kept")
	}
	if s.source.count() < 2 {
		t.Fatal("the spoiled chunk was not asked for again on a new connection")
	}
}

// A name taken while the copy ran is kept; the copy goes beside it.
func TestACopyNeverReplacesAName(t *testing.T) {
	t.Parallel()
	s := newSetup(t, "notes.txt", "notes.txt")
	write(t, s.src, "notes.txt", []byte("new"))
	write(t, s.dst, "notes.txt", []byte("old"))
	if p := s.run(context.Background(), t, s.job(t)); p.Code != tilderv1.XferFailed_CODE_UNSPECIFIED {
		t.Fatalf("copy ended %+v", p)
	}
	if b, _ := os.ReadFile(filepath.Join(s.dst, "notes.txt")); string(b) != "old" {
		t.Fatalf("the name was replaced: %q", b)
	}
	matches, _ := filepath.Glob(filepath.Join(s.dst, "notes.tilder-conflict-*.txt"))
	if len(matches) != 1 {
		t.Fatalf("conflict copies: %v", matches)
	}
	if b, _ := os.ReadFile(matches[0]); string(b) != "new" {
		t.Fatalf("the copy holds %q", b)
	}
}

// A file saved again on the source mid-copy arrives as it is now.
func TestAFileChangedOnTheSourceArrivesAsItIsNow(t *testing.T) {
	t.Parallel()
	s := newSetup(t, "proj", "proj")
	write(t, s.src, "proj/a.bin", big(3*xferchan.ChunkSize))
	write(t, s.src, "proj/b.txt", []byte("before"))
	s.source.next = func(p *pipe) {
		go func() { // b.txt is saved again once a.bin has begun
			for p.ends.Load() < 1 {
				time.Sleep(time.Millisecond) //nolint:forbidigo // watching a real pipe
			}
			write(t, s.src, "proj/b.txt", []byte("after, longer"))
			later := time.Unix(2_000_000_000, 0)
			_ = os.Chtimes(filepath.Join(s.src, "proj/b.txt"), later, later)
		}()
	}
	if p := s.run(context.Background(), t, s.job(t)); p.Code != tilderv1.XferFailed_CODE_UNSPECIFIED {
		t.Fatalf("copy ended %+v", p)
	}
	if b, _ := os.ReadFile(filepath.Join(s.dst, "proj/b.txt")); string(b) != "after, longer" {
		t.Fatalf("b.txt = %q", b)
	}
	if s.source.count() < 2 {
		t.Fatal("the change was not met by listing again")
	}
}

// Cancelling removes what arrived and puts nothing in place.
func TestACancelledCopyLeavesNothing(t *testing.T) {
	t.Parallel()
	s := newSetup(t, "big.bin", "big.bin")
	write(t, s.src, "big.bin", big(8*xferchan.ChunkSize))
	j := s.job(t)
	s.source.next = func(p *pipe) {
		go func() {
			for p.ends.Load() < 2 {
				time.Sleep(time.Millisecond) //nolint:forbidigo // watching a real pipe
			}
			j.Cancel()
		}()
	}
	if p := s.run(context.Background(), t, j); !p.Ended || p.Code != tilderv1.XferFailed_CODE_CANCELLED {
		t.Fatalf("copy ended %+v", p)
	}
	if _, err := os.Lstat(filepath.Join(s.dst, "big.bin")); err == nil {
		t.Fatal("a cancelled copy was put in place")
	}
	noPart(t, s.dst)
	j.Cancel() // idempotent
}

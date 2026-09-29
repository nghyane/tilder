//go:build unix

package xferchan_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/coder/quartz"
	"go.uber.org/goleak"
	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/files"
	"github.com/nghyane/tilder/go/internal/agent/xferchan"
	"github.com/nghyane/tilder/go/internal/identity"
	"github.com/nghyane/tilder/go/internal/testutil"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m, testutil.GoleakOptions...) }

// dest is the destination's end of a channel: it reads on its own goroutine,
// as a DataChannel buffers.
type dest struct {
	t     *testing.T
	conn  net.Conn
	inbox chan *tilderv1.XferServer
}

// home makes a home with the agent's directory in it.
func home(t *testing.T) string {
	t.Helper()
	h := t.TempDir()
	write(t, h, ".tilder/identity.json", []byte("machine key"))
	return h
}

func write(t *testing.T, h, rel string, data []byte) {
	t.Helper()
	p := filepath.Join(h, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// serve starts a source for a grant of src under h.
func serve(t *testing.T, h, src string) *dest {
	t.Helper()
	tree := files.New(h, filepath.Join(h, ".tilder"), quartz.NewMock(t))
	c, s := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- xferchan.Serve(ctx, s, tree, identity.Transfer{SrcPath: []byte(src)}) }()
	d := &dest{t: t, conn: c, inbox: make(chan *tilderv1.XferServer, 4096)}
	go func() {
		defer close(d.inbox)
		buf := make([]byte, 64*1024)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			msg := &tilderv1.XferServer{}
			if proto.Unmarshal(buf[:n], msg) != nil {
				return
			}
			d.inbox <- msg
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = c.Close()
		<-done
	})
	return d
}

func (d *dest) send(msg *tilderv1.XferClient) {
	d.t.Helper()
	frame, _ := proto.Marshal(msg)
	if _, err := d.conn.Write(frame); err != nil {
		d.t.Fatal(err)
	}
}

func (d *dest) recv() *tilderv1.XferServer {
	d.t.Helper()
	select {
	case m, ok := <-d.inbox:
		if !ok {
			d.t.Fatal("the source closed the channel")
		}
		return m
	case <-time.After(testutil.WaitShort): //nolint:forbidigo // a real pipe
		d.t.Fatal("no message from the source")
		return nil
	}
}

// quiet reports whether nothing arrives for a moment.
func (d *dest) quiet() bool {
	select {
	case <-d.inbox:
		return false
	case <-time.After(200 * time.Millisecond): //nolint:forbidigo // proving an absence
		return true
	}
}

func (d *dest) manifest() []*tilderv1.XferEntry {
	d.t.Helper()
	d.send(&tilderv1.XferClient{Msg: &tilderv1.XferClient_Manifest{Manifest: &tilderv1.XferManifestRequest{}}})
	var all []*tilderv1.XferEntry
	for {
		got := d.recv()
		m := got.GetManifest()
		if m == nil {
			d.t.Fatalf("expected a manifest page, got %v", got)
		}
		all = append(all, m.GetEntries()...)
		if m.GetLast() {
			return all
		}
	}
}

func (d *dest) want(file uint32, from uint64) {
	d.send(&tilderv1.XferClient{Msg: &tilderv1.XferClient_Want{Want: &tilderv1.XferWant{File: file, FromChunk: from}}})
}

func (d *dest) ack(file uint32, index uint64) {
	d.send(&tilderv1.XferClient{Msg: &tilderv1.XferClient_Ack{Ack: &tilderv1.XferAck{File: file, Index: index}}})
}

// chunk reads one chunk's pieces and end, checking the hash, and acks it.
func (d *dest) chunk(file uint32, index uint64) []byte {
	d.t.Helper()
	var data []byte
	for {
		m := d.recv()
		if p := m.GetPiece(); p != nil {
			if p.GetFile() != file || p.GetIndex() != index || len(p.GetData()) > 15*1024 {
				d.t.Fatalf("piece %d/%d of %d bytes, want %d/%d, ≤ 15 KiB", p.GetFile(), p.GetIndex(), len(p.GetData()), file, index)
			}
			data = append(data, p.GetData()...)
			continue
		}
		end := m.GetChunkEnd()
		if end == nil || end.GetFile() != file || end.GetIndex() != index {
			d.t.Fatalf("got %v, want the end of chunk %d/%d", m, file, index)
		}
		if sum := sha256.Sum256(data); !bytes.Equal(sum[:], end.GetSha256()) {
			d.t.Fatalf("chunk %d/%d hash does not match its bytes", file, index)
		}
		d.ack(file, index)
		return data
	}
}

func paths(entries []*tilderv1.XferEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = string(e.GetPath())
	}
	return out
}

func index(t *testing.T, entries []*tilderv1.XferEntry, path string) uint32 {
	t.Helper()
	for i, e := range entries {
		if string(e.GetPath()) == path {
			return uint32(i) //nolint:gosec // G115: a test's few entries
		}
	}
	t.Fatalf("%q not in the manifest %v", path, paths(entries))
	return 0
}

// The manifest is what the grant names and nothing else: each directory
// before what it holds, links as links, special files left out, and never
// the agent's own directory, even when the grant is the whole home.
func TestTheManifestListsWhatTheGrantNamesAndNothingMore(t *testing.T) {
	t.Parallel()
	h := home(t)
	write(t, h, "proj/a.txt", []byte("alpha"))
	write(t, h, "proj/lib/b.txt", []byte("beta"))
	write(t, h, "secret.txt", []byte("not in the grant"))
	if err := os.Symlink("../secret.txt", filepath.Join(h, "proj/out")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(h, "proj/pipe"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := serve(t, h, "proj")
	d.send(&tilderv1.XferClient{Msg: &tilderv1.XferClient_Manifest{Manifest: &tilderv1.XferManifestRequest{}}})
	m := d.recv().GetManifest()
	if !m.GetLast() || m.GetSkipped() != 1 || m.GetChunkSize() != xferchan.ChunkSize {
		t.Fatalf("manifest last=%v skipped=%d chunk=%d", m.GetLast(), m.GetSkipped(), m.GetChunkSize())
	}
	got := paths(m.GetEntries())
	want := []string{"", "a.txt", "lib", "out", "lib/b.txt"}
	if len(got) != len(want) {
		t.Fatalf("manifest %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("manifest %q, want %q", got, want)
		}
	}
	out := m.GetEntries()[3]
	if out.GetKind() != tilderv1.FsKind_FS_KIND_SYMLINK || string(out.GetLinkTarget()) != "../secret.txt" {
		t.Fatalf("the link is %v, want a link to ../secret.txt", out)
	}
	// A link is never served as the file it points at.
	d.want(3, 0)
	if r := d.recv().GetRefused(); r == nil || r.GetFile() != 3 || r.GetCode() != tilderv1.XferFailed_CODE_NOT_FOUND {
		t.Fatalf("a want for the link got %v", r)
	}

	whole := serve(t, h, "").manifest()
	for _, p := range paths(whole) {
		if p == ".tilder" || filepath.Dir(p) == ".tilder" {
			t.Fatalf("the agent's directory is in the manifest: %q", paths(whole))
		}
	}
}

// A file comes as chunks of pieces, each chunk with its hash; a copy
// resumed asks from the first chunk it lacks and gets only the rest.
func TestAFileComesInHashedChunksAndResumesWhereItStopped(t *testing.T) {
	t.Parallel()
	h := home(t)
	data := bytes.Repeat([]byte("0123456789abcdef"), (5*xferchan.ChunkSize/2)/16) // 2.5 chunks
	write(t, h, "big.bin", data)
	write(t, h, "empty", nil)

	d := serve(t, h, "")
	entries := d.manifest()
	big, empty := index(t, entries, "big.bin"), index(t, entries, "empty")
	d.want(big, 1)
	got := append(d.chunk(big, 1), d.chunk(big, 2)...)
	if !bytes.Equal(got, data[xferchan.ChunkSize:]) {
		t.Fatal("the resumed chunks are not the file's bytes from chunk 1")
	}
	d.want(empty, 0)
	if len(d.chunk(empty, 0)) != 0 {
		t.Fatal("an empty file is one empty chunk")
	}
}

// The source stops at 16 chunks not acked, and goes on one chunk per ack.
func TestTheSourceSendsNoMoreThanItsCreditAhead(t *testing.T) {
	t.Parallel()
	h := home(t)
	write(t, h, "huge.bin", make([]byte, 18*xferchan.ChunkSize))
	d := serve(t, h, "")
	file := index(t, d.manifest(), "huge.bin")
	d.want(file, 0)
	ends := 0
	for ends < 16 {
		if d.recv().GetChunkEnd() != nil {
			ends++
		}
	}
	if !d.quiet() {
		t.Fatal("the source sent past 16 chunks not acked")
	}
	d.ack(file, 0)
	for d.recv().GetChunkEnd() == nil {
	}
	if !d.quiet() {
		t.Fatal("one ack let more than one chunk through")
	}
}

// A file saved again since the manifest is refused alone; the copy goes on.
func TestAFileChangedSinceTheManifestIsRefusedAlone(t *testing.T) {
	t.Parallel()
	h := home(t)
	write(t, h, "log.txt", []byte("first"))
	write(t, h, "keep.txt", []byte("kept"))
	d := serve(t, h, "")
	entries := d.manifest()
	changed, kept := index(t, entries, "log.txt"), index(t, entries, "keep.txt")
	later := time.Unix(2_000_000_000, 0)
	write(t, h, "log.txt", []byte("second, longer"))
	if err := os.Chtimes(filepath.Join(h, "log.txt"), later, later); err != nil {
		t.Fatal(err)
	}
	d.want(changed, 0)
	if r := d.recv().GetRefused(); r == nil || r.GetFile() != changed || r.GetCode() != tilderv1.XferFailed_CODE_CHANGED {
		t.Fatalf("a changed file got %v, want refused as changed", r)
	}
	d.want(kept, 0)
	if string(d.chunk(kept, 0)) != "kept" {
		t.Fatal("the copy did not go on after one file was refused")
	}
	d.want(uint32(len(entries)), 0) //nolint:gosec // G115: a test's few entries
	if r := d.recv().GetRefused(); r == nil || r.GetCode() != tilderv1.XferFailed_CODE_NOT_FOUND {
		t.Fatalf("a want past the manifest got %v", r)
	}
}

// Asking for a file before any manifest ends the channel: the destination
// can only name what the source listed.
func TestAWantBeforeTheManifestEndsTheChannel(t *testing.T) {
	t.Parallel()
	h := home(t)
	write(t, h, "a.txt", []byte("a"))
	d := serve(t, h, "")
	d.want(0, 0)
	select {
	case _, ok := <-d.inbox:
		if ok {
			t.Fatal("the source answered a want before the manifest")
		}
	case <-time.After(testutil.WaitShort): //nolint:forbidigo // a real pipe
		t.Fatal("the channel stayed open")
	}
}

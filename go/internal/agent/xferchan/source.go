// Package xferchan copies between two machines of an owner over one `xfer`
// channel (ADR 0035). The source serves read-only exactly what the copy's
// grant names: the destination names files only by their number in the
// manifest the source listed, never by path.
package xferchan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/files"
	"github.com/nghyane/tilder/go/internal/identity"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

const (
	// ChunkSize is the unit hashed, acked and resumed.
	ChunkSize = 1 << 20
	// A message stays under 16 KiB (ADR 0022): a piece of a chunk, or a
	// page of the manifest.
	maxPiece = 15 * 1024
	maxPage  = 15 * 1024
	// credit is how many chunks may be sent and not yet acked: 16 MiB.
	credit = 16
	// maxEntries bounds one copy's manifest, held in memory on both sides.
	maxEntries = 100_000
	maxWants   = 64
	readBuffer = 64 * 1024
	listPage   = 1000
)

// ErrTooLarge means the source holds more entries than one copy may.
var ErrTooLarge = errors.New("xferchan: too many entries for one copy")

// Serve answers one destination's `xfer` channel for grant until the channel
// closes or ctx ends. The tree keeps every path under the owner's home and
// out of the agent's own directory.
func Serve(ctx context.Context, ch io.ReadWriteCloser, tree *files.Tree, grant identity.Transfer) error {
	ctx, cancel := context.WithCancel(ctx)
	s := &source{ch: ch, tree: tree, root: string(grant.SrcPath), wants: make(chan *tilderv1.XferWant, maxWants), acked: make(chan struct{}, 1)}
	var wg sync.WaitGroup
	defer func() {
		cancel()
		_ = ch.Close()
		wg.Wait()
	}()
	buf := make([]byte, readBuffer)
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return err
		}
		msg := &tilderv1.XferClient{}
		if err := proto.Unmarshal(buf[:n], msg); err != nil {
			return fmt.Errorf("xferchan: malformed message: %w", err)
		}
		switch m := msg.GetMsg().(type) {
		case *tilderv1.XferClient_Manifest:
			if s.entries != nil {
				return errors.New("xferchan: manifest asked twice")
			}
			if err := s.manifest(); err != nil {
				return err
			}
			wg.Go(func() { s.serveWants(ctx) })
		case *tilderv1.XferClient_Want:
			if s.entries == nil {
				return errors.New("xferchan: want before the manifest")
			}
			select {
			case s.wants <- m.Want:
			default:
				return errors.New("xferchan: too many wants queued")
			}
		case *tilderv1.XferClient_Ack:
			s.ack()
		default:
			return errors.New("xferchan: unknown message")
		}
	}
}

type source struct {
	ch    io.Writer
	tree  *files.Tree
	root  string
	wants chan *tilderv1.XferWant
	// entries is the manifest, as sent; set once, by the read loop, before
	// the want server starts.
	entries []*tilderv1.XferEntry
	acked   chan struct{}

	// The mutex protects the following elements.
	mu sync.Mutex
	// unacked is how many chunks were sent and not yet acked.
	unacked int
	// writeMu orders frames on the channel.
	writeMu sync.Mutex
}

func (s *source) send(msg *tilderv1.XferServer) error {
	frame, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err = s.ch.Write(frame)
	return err
}

func (s *source) refuse(code tilderv1.XferFailed_Code, file *uint32) error {
	return s.send(&tilderv1.XferServer{Msg: &tilderv1.XferServer_Refused{Refused: &tilderv1.XferRefused{Code: code, File: file}}})
}

// manifest lists what the grant names and sends it in pages.
func (s *source) manifest() error {
	entries, skipped, err := s.walk()
	if err != nil {
		code := tilderv1.XferFailed_CODE_NOT_FOUND
		if errors.Is(err, ErrTooLarge) {
			code = tilderv1.XferFailed_CODE_TOO_LARGE
		}
		_ = s.refuse(code, nil)
		return err
	}
	s.entries = entries
	page := &tilderv1.XferManifest{ChunkSize: ChunkSize}
	size := 0
	for _, e := range entries {
		if n := proto.Size(e) + 4; size+n > maxPage && len(page.Entries) > 0 {
			if err := s.send(&tilderv1.XferServer{Msg: &tilderv1.XferServer_Manifest{Manifest: page}}); err != nil {
				return err
			}
			page, size = &tilderv1.XferManifest{ChunkSize: ChunkSize}, 0
		}
		size += proto.Size(e) + 4
		page.Entries = append(page.Entries, e)
	}
	page.Last, page.Skipped = true, skipped
	return s.send(&tilderv1.XferServer{Msg: &tilderv1.XferServer_Manifest{Manifest: page}})
}

// walk lists the grant's source: itself, then, for a directory, everything
// under it, each directory before what it holds. Links are listed as links,
// never followed. Special files, and directories that cannot be read (the
// agent's own among them), are counted and left out.
func (s *source) walk() ([]*tilderv1.XferEntry, uint32, error) {
	top, err := s.tree.Stat(s.root)
	if err != nil {
		return nil, 0, err
	}
	type dir struct {
		rel string
		at  int // its entry
	}
	var entries []*tilderv1.XferEntry
	var skipped uint32
	var queue []dir
	add := func(rel string, e files.Entry) {
		x, ok := entryOf(rel, e)
		if !ok {
			skipped++
			return
		}
		if e.Kind == files.Dir {
			queue = append(queue, dir{rel, len(entries)})
		}
		entries = append(entries, x)
	}
	add("", top)
	if len(entries) == 0 {
		return nil, 0, &files.Error{Code: files.NotRegular}
	}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		listed, err := s.list(d.rel, func(e files.Entry) { add(join(d.rel, e.Name), e) })
		if err != nil {
			return nil, 0, err
		}
		if !listed {
			if d.at == 0 {
				return nil, 0, &files.Error{Code: files.Denied}
			}
			entries[d.at] = nil
			skipped++
		}
		if len(entries) > maxEntries {
			return nil, 0, ErrTooLarge
		}
	}
	return slices.DeleteFunc(entries, func(e *tilderv1.XferEntry) bool { return e == nil }), skipped, nil
}

// list hands each entry of the directory at rel to add, page by page, and
// reports whether it could be read at all.
func (s *source) list(rel string, add func(files.Entry)) (bool, error) {
	after := ""
	for {
		page, next, truncated, err := s.tree.List(s.path(rel), after, listPage)
		if err != nil {
			return false, nil //nolint:nilerr // an unreadable directory is left out, not fatal
		}
		if truncated {
			return false, ErrTooLarge
		}
		for _, e := range page {
			add(e)
		}
		if next == "" {
			return true, nil
		}
		after = next
	}
}

func entryOf(rel string, e files.Entry) (*tilderv1.XferEntry, bool) {
	x := &tilderv1.XferEntry{
		Path: []byte(rel), Size: uint64(max(e.Size, 0)), Perm: uint32(e.Perm.Perm()),
		MtimeNs: e.ModTime.UnixNano(), Etag: e.ETag,
	}
	switch e.Kind {
	case files.File:
		x.Kind = tilderv1.FsKind_FS_KIND_FILE
	case files.Dir:
		x.Kind, x.Size = tilderv1.FsKind_FS_KIND_DIR, 0
	case files.Symlink:
		x.Kind, x.Size, x.LinkTarget = tilderv1.FsKind_FS_KIND_SYMLINK, 0, []byte(e.LinkTarget)
	default:
		return nil, false
	}
	return x, true
}

func join(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + "/" + name
}

// path is where a manifest path is in the tree.
func (s *source) path(rel string) string {
	if rel == "" {
		return s.root
	}
	return join(s.root, rel)
}

func (s *source) ack() {
	s.mu.Lock()
	if s.unacked > 0 {
		s.unacked--
	}
	s.mu.Unlock()
	select {
	case s.acked <- struct{}{}:
	default:
	}
}

// serveWants streams each wanted file, in order, until ctx ends.
func (s *source) serveWants(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case w := <-s.wants:
			if err := s.stream(ctx, w); err != nil {
				return
			}
		}
	}
}

// stream sends file w.File from chunk w.FromChunk: each chunk as pieces,
// then its hash. A file not as listed (changed, gone) is refused alone.
func (s *source) stream(ctx context.Context, w *tilderv1.XferWant) error {
	i := w.GetFile()
	if int(i) >= len(s.entries) || s.entries[i].GetKind() != tilderv1.FsKind_FS_KIND_FILE {
		return s.refuse(tilderv1.XferFailed_CODE_NOT_FOUND, &i)
	}
	want := s.entries[i]
	f, e, err := s.tree.Open(s.path(string(want.GetPath())))
	if err != nil {
		return s.refuse(tilderv1.XferFailed_CODE_NOT_FOUND, &i)
	}
	defer func() { _ = f.Close() }()
	if !same(e, want) {
		return s.refuse(tilderv1.XferFailed_CODE_CHANGED, &i)
	}
	chunks := max(1, (want.GetSize()+ChunkSize-1)/ChunkSize)
	buf := make([]byte, maxPiece)
	for c := w.GetFromChunk(); c < chunks; c++ {
		if err := s.wait(ctx); err != nil {
			return err
		}
		sum, err := s.chunk(f, i, c, want.GetSize(), buf)
		if errors.Is(err, errChanged) {
			return s.refuse(tilderv1.XferFailed_CODE_CHANGED, &i)
		}
		if err != nil {
			return err
		}
		if err := s.send(&tilderv1.XferServer{Msg: &tilderv1.XferServer_ChunkEnd{ChunkEnd: &tilderv1.XferChunkEnd{File: i, Index: c, Sha256: sum}}}); err != nil {
			return err
		}
	}
	// Read to the end as listed: the file must still be that file.
	if info, err := f.Stat(); err != nil || !sameInfo(info, want) {
		return s.refuse(tilderv1.XferFailed_CODE_CHANGED, &i)
	}
	return nil
}

var errChanged = errors.New("xferchan: the file changed while it was read")

// chunk sends chunk c of file i as pieces and returns its hash.
func (s *source) chunk(f *os.File, i uint32, c, size uint64, buf []byte) ([]byte, error) {
	sum := sha256.New()
	off, end := c*ChunkSize, min((c+1)*ChunkSize, size)
	for off < end {
		n, err := f.ReadAt(buf[:min(uint64(len(buf)), end-off)], int64(off)) //nolint:gosec // G115: offsets fit in int64
		if n > 0 {
			sum.Write(buf[:n])
			if serr := s.send(&tilderv1.XferServer{Msg: &tilderv1.XferServer_Piece{Piece: &tilderv1.XferPiece{File: i, Index: c, Data: buf[:n]}}}); serr != nil {
				return nil, serr
			}
			off += uint64(n) //nolint:gosec // G115: n is never negative
		}
		if err != nil {
			if errors.Is(err, io.EOF) && off < end {
				return nil, errChanged // shorter than listed
			}
			if !errors.Is(err, io.EOF) {
				return nil, err
			}
		}
	}
	return sum.Sum(nil), nil
}

// wait takes one chunk of credit, waiting for an ack when none is left.
func (s *source) wait(ctx context.Context) error {
	for {
		s.mu.Lock()
		if s.unacked < credit {
			s.unacked++
			s.mu.Unlock()
			return nil
		}
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.acked:
		}
	}
}

// same: the file opened is the version listed.
func same(e files.Entry, want *tilderv1.XferEntry) bool {
	return bytes.Equal(e.ETag, want.GetEtag())
}

// sameInfo: after reading, the file still has the listed size and time.
func sameInfo(info os.FileInfo, want *tilderv1.XferEntry) bool {
	return uint64(max(info.Size(), 0)) == want.GetSize() && info.ModTime().UnixNano() == want.GetMtimeNs()
}

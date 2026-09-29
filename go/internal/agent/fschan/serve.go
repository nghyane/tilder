// Package fschan serves a machine's files over one `fs` message channel
// (ADR 0022): many requests at once, each by id, reads and writes metered by
// a window so a big file never stalls the shells on the same connection.
package fschan

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/files"
	"github.com/nghyane/tilder/go/internal/clock"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

const (
	readBuffer = 64 * 1024
	// A data message stays under 16 KiB, as the shell's do: Chrome has no
	// I-DATA yet, so one big message holds up every other channel.
	maxChunk  = 15 * 1024
	maxReply  = 15 * 1024
	minWindow = 64 * 1024
	maxWindow = 1 << 20
	// What a writer may send ahead of the disk.
	writeCredit = 1 << 20
	maxInFlight = 8
	// maxWrites bounds the writes open at once on a channel: each holds a
	// directory and a temp file open until it is committed or cancelled, and
	// a client that never did ran the agent out of descriptors (Syncthing
	// caps its concurrent writes the same way, 16 per folder by default).
	maxWrites = 8
	listLimit = 1000
)

// Serve answers the channel's requests until it closes or ctx ends.
func Serve(ctx context.Context, ch io.ReadWriteCloser, tree *files.Tree, clk clock.Clock) error {
	ctx, cancel := context.WithCancel(ctx)
	s := &server{ch: ch, tree: tree, reads: map[uint32]*reading{}, writes: map[uint32]*writing{}}
	s.watches = newWatches(s, clk)
	defer func() {
		cancel()
		_ = ch.Close()
		s.watches.close()
		s.wg.Wait()
		s.dropWrites()
	}()
	buf := make([]byte, readBuffer)
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return err
		}
		msg := &tilderv1.FsClient{}
		if err := proto.Unmarshal(buf[:n], msg); err != nil {
			return fmt.Errorf("fschan: malformed message: %w", err)
		}
		if err := s.handle(ctx, msg); err != nil {
			return err
		}
	}
}

type server struct {
	ch      io.Writer
	tree    *files.Tree
	watches *watches
	wg      sync.WaitGroup

	// The mutex protects the following elements.
	mu       sync.Mutex
	inFlight int
	reads    map[uint32]*reading
	writes   map[uint32]*writing
	// writeMu orders frames on the channel; taken after mu, never before.
	writeMu sync.Mutex
}

type reading struct {
	cancel context.CancelFunc
	acks   chan uint64
}

type writing struct {
	path     string
	w        *files.Write
	received uint64
	granted  uint64
}

func (s *server) send(id uint32, msg *tilderv1.FsServer) {
	msg.ReqId = id
	frame, err := proto.Marshal(msg)
	if err != nil {
		return
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, _ = s.ch.Write(frame)
}

func (s *server) fail(id uint32, err error) {
	s.send(id, &tilderv1.FsServer{Msg: &tilderv1.FsServer_Error{Error: &tilderv1.FsError{Code: codeOf(err)}}})
}

// start runs a request in its own goroutine, at most maxInFlight at once,
// and reports whether it did.
func (s *server) start(id uint32, run func()) bool {
	s.mu.Lock()
	if s.inFlight >= maxInFlight {
		s.mu.Unlock()
		s.send(id, &tilderv1.FsServer{Msg: &tilderv1.FsServer_Error{Error: &tilderv1.FsError{Code: tilderv1.FsError_CODE_BUSY}}})
		return false
	}
	s.inFlight++
	s.mu.Unlock()
	s.wg.Go(func() {
		defer func() {
			s.mu.Lock()
			s.inFlight--
			s.mu.Unlock()
		}()
		run()
	})
	return true
}

func (s *server) handle(ctx context.Context, msg *tilderv1.FsClient) error {
	id := msg.GetReqId()
	switch m := msg.GetMsg().(type) {
	case *tilderv1.FsClient_Stat:
		s.start(id, func() { s.stat(id, string(m.Stat.GetPath())) })
	case *tilderv1.FsClient_List:
		s.start(id, func() { s.list(id, m.List) })
	case *tilderv1.FsClient_Read:
		s.read(ctx, id, m.Read)
	case *tilderv1.FsClient_Ack:
		s.mu.Lock()
		r := s.reads[id]
		s.mu.Unlock()
		if r != nil {
			latest(r.acks, m.Ack.GetReceived())
		}
	case *tilderv1.FsClient_Write:
		s.beginWrite(id, m.Write)
	case *tilderv1.FsClient_Data:
		return s.data(id, m.Data.GetData())
	case *tilderv1.FsClient_Commit:
		s.commit(id)
	case *tilderv1.FsClient_Abort, *tilderv1.FsClient_Cancel:
		s.cancel(id)
	case *tilderv1.FsClient_Mkdir:
		s.start(id, func() { s.done(id, s.tree.Mkdir(string(m.Mkdir.GetPath()))) })
	case *tilderv1.FsClient_Rename:
		r := m.Rename
		s.start(id, func() { s.done(id, s.tree.Rename(string(r.GetFrom()), string(r.GetTo()), r.GetNoReplace())) })
	case *tilderv1.FsClient_Watch:
		path := string(m.Watch.GetPath())
		s.start(id, func() { s.watches.add(id, path) })
	case *tilderv1.FsClient_Unwatch:
		s.watches.remove(id)
	case *tilderv1.FsClient_Remove:
		r := m.Remove
		s.start(id, func() { s.done(id, s.tree.Remove(string(r.GetPath()), r.GetRecursive())) })
	default:
		// A newer client's request this build does not know.
		s.fail(id, nil)
	}
	return nil
}

func (s *server) done(id uint32, err error) {
	if err != nil {
		s.fail(id, err)
		return
	}
	s.send(id, &tilderv1.FsServer{Msg: &tilderv1.FsServer_Ok{Ok: &tilderv1.FsOk{}}})
}

func (s *server) stat(id uint32, path string) {
	e, err := s.tree.Stat(path)
	if err != nil {
		s.fail(id, err)
		return
	}
	s.send(id, &tilderv1.FsServer{Msg: &tilderv1.FsServer_Entry{Entry: entry(e)}})
}

// list answers one page, cut to fit a message: a long directory is paged by
// size as well as by count.
func (s *server) list(id uint32, req *tilderv1.FsList) {
	limit := int(min(max(req.GetLimit(), 1), listLimit))
	entries, next, truncated, err := s.tree.List(string(req.GetPath()), string(req.GetAfter()), limit)
	if err != nil {
		s.fail(id, err)
		return
	}
	page := &tilderv1.FsEntries{Truncated: truncated}
	size := 0
	for i, e := range entries {
		pe := entry(e)
		if size+proto.Size(pe)+4 > maxReply && i > 0 {
			next = entries[i-1].Name // the rest in the next page
			break
		}
		size += proto.Size(pe) + 4
		page.Entries = append(page.Entries, pe)
	}
	if next != "" {
		page.Next = []byte(next)
	}
	s.send(id, &tilderv1.FsServer{Msg: &tilderv1.FsServer_Entries{Entries: page}})
}

func (s *server) read(ctx context.Context, id uint32, req *tilderv1.FsRead) {
	s.mu.Lock()
	if _, dup := s.reads[id]; dup {
		s.mu.Unlock()
		s.fail(id, nil)
		return
	}
	rctx, cancel := context.WithCancel(ctx)
	r := &reading{cancel: cancel, acks: make(chan uint64, 1)}
	s.reads[id] = r
	s.mu.Unlock()
	started := s.start(id, func() {
		defer func() {
			cancel()
			s.mu.Lock()
			delete(s.reads, id)
			s.mu.Unlock()
		}()
		s.stream(rctx, id, req, r.acks)
	})
	if !started {
		cancel()
		s.mu.Lock()
		delete(s.reads, id)
		s.mu.Unlock()
	}
}

// stream sends the file's bytes in chunks, waiting for acks past the window.
func (s *server) stream(ctx context.Context, id uint32, req *tilderv1.FsRead, acks chan uint64) {
	f, e, err := s.tree.Open(string(req.GetPath()))
	if err != nil {
		s.fail(id, err)
		return
	}
	defer func() { _ = f.Close() }()
	window := uint64(min(max(req.GetWindow(), minWindow), maxWindow))
	remaining := req.GetLength()
	if remaining == 0 {
		remaining = ^uint64(0)
	}
	offset := req.GetOffset()
	var sent, acked uint64
	sum := sha256.New()
	buf := make([]byte, maxChunk)
	for remaining > 0 {
		for sent-acked >= window {
			select {
			case <-ctx.Done():
				return
			case a := <-acks:
				if a > acked && a <= sent {
					acked = a
				}
			}
		}
		n, rerr := f.ReadAt(buf[:min(uint64(len(buf)), remaining, window-(sent-acked))], int64(offset)) //nolint:gosec // G115: offsets fit in int64
		if n > 0 {
			sum.Write(buf[:n])
			s.send(id, &tilderv1.FsServer{Msg: &tilderv1.FsServer_Chunk{Chunk: &tilderv1.FsChunk{Offset: offset, Data: buf[:n]}}})
			offset += uint64(n)    //nolint:gosec // G115: n is never negative
			sent += uint64(n)      //nolint:gosec // G115: n is never negative
			remaining -= uint64(n) //nolint:gosec // G115: n is never negative
		}
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) {
				s.fail(id, rerr)
				return
			}
			break
		}
	}
	s.send(id, &tilderv1.FsServer{Msg: &tilderv1.FsServer_Eof{Eof: &tilderv1.FsEof{Entry: entry(e), Sha256: sum.Sum(nil)}}})
}

func (s *server) beginWrite(id uint32, req *tilderv1.FsWrite) {
	s.mu.Lock()
	_, dup := s.writes[id]
	full := len(s.writes) >= maxWrites
	s.mu.Unlock()
	switch {
	case dup:
		s.fail(id, nil)
		return
	case full:
		s.send(id, &tilderv1.FsServer{Msg: &tilderv1.FsServer_Error{Error: &tilderv1.FsError{Code: tilderv1.FsError_CODE_BUSY}}})
		return
	}
	w, err := s.tree.BeginWrite(string(req.GetPath()), req.GetIfEtag(), req.GetCreateOnly())
	if err != nil {
		s.fail(id, err)
		return
	}
	s.mu.Lock()
	s.writes[id] = &writing{path: string(req.GetPath()), w: w, granted: writeCredit}
	s.mu.Unlock()
	s.send(id, &tilderv1.FsServer{Msg: &tilderv1.FsServer_Credit{Credit: &tilderv1.FsCredit{Accepted: writeCredit}}})
}

// data writes a part to disk and grants more credit as the disk keeps up.
// The credit is how the console paces itself so the shells on the same
// connection are not held up; it is not a check: the agent grants ahead as
// it writes, so it cannot tell a client that ignores it.
func (s *server) data(id uint32, p []byte) error {
	s.mu.Lock()
	wr := s.writes[id]
	s.mu.Unlock()
	if wr == nil {
		return nil // a write already committed, aborted or refused
	}
	if _, err := wr.w.Write(p); err != nil {
		s.cancel(id)
		s.fail(id, err)
		return nil
	}
	wr.received += uint64(len(p))
	if wr.granted-wr.received < writeCredit/2 {
		wr.granted = wr.received + writeCredit
		s.send(id, &tilderv1.FsServer{Msg: &tilderv1.FsServer_Credit{Credit: &tilderv1.FsCredit{Accepted: wr.granted}}})
	}
	return nil
}

func (s *server) commit(id uint32) {
	s.mu.Lock()
	wr := s.writes[id]
	delete(s.writes, id)
	s.mu.Unlock()
	if wr == nil {
		s.fail(id, nil)
		return
	}
	e, err := wr.w.Commit()
	switch {
	case err != nil && files.CodeOf(err) == files.Conflict:
		// What the file is now, so the console can offer Compare.
		conflict := &tilderv1.FsConflict{}
		if current, serr := s.tree.Stat(wr.path); serr == nil {
			conflict.Current = entry(current)
		}
		s.send(id, &tilderv1.FsServer{Msg: &tilderv1.FsServer_Conflict{Conflict: conflict}})
	case err != nil:
		s.fail(id, err)
	default:
		s.send(id, &tilderv1.FsServer{Msg: &tilderv1.FsServer_Ok{Ok: &tilderv1.FsOk{Entry: entry(e)}}})
	}
}

// cancel stops a read or drops a write.
func (s *server) cancel(id uint32) {
	s.mu.Lock()
	r := s.reads[id]
	wr := s.writes[id]
	delete(s.writes, id)
	s.mu.Unlock()
	if r != nil {
		r.cancel()
	}
	if wr != nil {
		wr.w.Abort()
	}
}

func (s *server) dropWrites() {
	s.mu.Lock()
	writes := s.writes
	s.writes = map[uint32]*writing{}
	s.mu.Unlock()
	for _, wr := range writes {
		wr.w.Abort()
	}
}

// latest keeps only the newest ack: acks are cumulative.
func latest(acks chan uint64, v uint64) {
	select {
	case <-acks:
	default:
	}
	acks <- v
}

package transfer

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/xferchan"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

const (
	readBuffer = 64 * 1024
	// maxWants is how many files are asked for ahead: the source serves them
	// in order, so small files follow one another without a round trip.
	maxWants = 32
)

// pull copies over one connection: list, then want every file not done from
// its first missing chunk, keeping each chunk only once its hash checks.
// It returns nil when every file has arrived.
func (j *Job) pull(conn Conn) error {
	p := &puller{j: j, conn: conn, buf: make([]byte, readBuffer)}
	if err := p.send(&tilderv1.XferClient{Msg: &tilderv1.XferClient_Manifest{Manifest: &tilderv1.XferManifestRequest{}}}); err != nil {
		return err
	}
	entries, err := readManifest(p.next)
	if err != nil {
		return err
	}
	if err := j.adopt(entries); err != nil {
		return err
	}
	for i, d := range j.done {
		f := uint32(i) //nolint:gosec // G115: i < maxEntries
		switch {
		case d:
		case j.partial[f] >= chunks(j.entries[i].GetSize()):
			// Every chunk arrived and was checked before a cut: finished
			// here, never asked for again (the source would send nothing).
			if err := j.complete(f); err != nil {
				return failure{codeOf(err)}
			}
		default:
			p.todo = append(p.todo, f)
		}
	}
	for range maxWants {
		if err := p.want(); err != nil {
			return err
		}
	}
	for len(p.wanted) > 0 {
		msg, err := p.next()
		if err != nil {
			return err
		}
		if err := p.handle(msg); err != nil {
			return err
		}
	}
	return nil
}

// puller is one connection's pull.
type puller struct {
	j    *Job
	conn Conn
	buf  []byte
	// todo are the files not yet asked for; wanted, asked for, in order:
	// the source serves them so, the first is the one arriving.
	todo, wanted []uint32
	chunk        []byte
}

func (p *puller) next() (*tilderv1.XferServer, error) {
	n, err := p.conn.Read(p.buf)
	if err != nil {
		return nil, err
	}
	msg := &tilderv1.XferServer{}
	if err := proto.Unmarshal(p.buf[:n], msg); err != nil {
		return nil, errProtocol
	}
	return msg, nil
}

func (p *puller) send(msg *tilderv1.XferClient) error {
	frame, err := proto.Marshal(msg)
	if err == nil {
		_, err = p.conn.Write(frame)
	}
	return err
}

// want asks for the next file, from its first missing chunk.
func (p *puller) want() error {
	if len(p.todo) == 0 || len(p.wanted) >= maxWants {
		return nil
	}
	f := p.todo[0]
	p.todo, p.wanted = p.todo[1:], append(p.wanted, f)
	return p.send(&tilderv1.XferClient{Msg: &tilderv1.XferClient_Want{Want: &tilderv1.XferWant{File: f, FromChunk: p.j.partial[f]}}})
}

func (p *puller) handle(msg *tilderv1.XferServer) error {
	head := p.wanted[0]
	e, c := p.j.entries[head], p.j.partial[head]
	switch m := msg.GetMsg().(type) {
	case *tilderv1.XferServer_Piece:
		piece := m.Piece
		if piece.GetFile() != head || piece.GetIndex() != c || uint64(len(p.chunk)+len(piece.GetData())) > chunkLen(e.GetSize(), c) {
			return errProtocol
		}
		p.chunk = append(p.chunk, piece.GetData()...)
		return nil
	case *tilderv1.XferServer_ChunkEnd:
		end := m.ChunkEnd
		sum := sha256.Sum256(p.chunk)
		if end.GetFile() != head || end.GetIndex() != c || uint64(len(p.chunk)) != chunkLen(e.GetSize(), c) || !bytes.Equal(sum[:], end.GetSha256()) {
			return errProtocol // the chunk is asked for again
		}
		return p.keep(head, c)
	case *tilderv1.XferServer_Refused:
		if m.Refused.File != nil {
			return errAgain // listed again, the file starts over as it is now
		}
		return failure{m.Refused.GetCode()}
	default:
		return errProtocol
	}
}

// keep writes a checked chunk, acks it, and finishes its file at its end.
func (p *puller) keep(file uint32, c uint64) error {
	j := p.j
	if err := j.write(file, c, p.chunk); err != nil {
		return failure{codeOf(err)}
	}
	p.chunk = p.chunk[:0]
	j.partial[file] = c + 1
	// The file is finished before the ack goes: the chunk is written and
	// checked whatever becomes of the ack, and a cut here must not leave a
	// file with every chunk and not done, which no later want can finish.
	last := c+1 == chunks(j.entries[file].GetSize())
	if last {
		if err := j.complete(file); err != nil {
			return failure{codeOf(err)}
		}
		p.wanted = p.wanted[1:]
	}
	if err := p.send(&tilderv1.XferClient{Msg: &tilderv1.XferClient_Ack{Ack: &tilderv1.XferAck{File: file, Index: c}}}); err != nil {
		return err
	}
	if last {
		if err := p.want(); err != nil {
			return err
		}
	}
	j.maybeSave()
	j.report(Progress{}, false)
	return nil
}

// readManifest reads the manifest's pages, checking each entry's lengths as
// its page arrives: a source that sends long names is refused before it has
// filled memory, not after (validate checks the rest once all is in).
func readManifest(next func() (*tilderv1.XferServer, error)) ([]*tilderv1.XferEntry, error) {
	var entries []*tilderv1.XferEntry
	size, pages := 0, 0
	for {
		if pages++; pages > maxEntries+1 {
			return nil, errProtocol // pages that list nothing, for ever
		}
		msg, err := next()
		if err != nil {
			return nil, err
		}
		if r := msg.GetRefused(); r != nil {
			return nil, failure{r.GetCode()}
		}
		m := msg.GetManifest()
		if m == nil || m.GetChunkSize() != xferchan.ChunkSize {
			return nil, errProtocol
		}
		for _, e := range m.GetEntries() {
			if len(e.GetPath()) > maxPath || len(e.GetLinkTarget()) > maxPath || len(e.GetEtag()) > maxEtag {
				return nil, errBadManifest
			}
			size += len(e.GetPath()) + len(e.GetLinkTarget()) + len(e.GetEtag())
		}
		if entries = append(entries, m.GetEntries()...); len(entries) > maxEntries || size > maxManifestBytes {
			return nil, failure{tilderv1.XferFailed_CODE_TOO_LARGE}
		}
		if m.GetLast() {
			return entries, nil
		}
	}
}

// adopt takes a manifest: the first builds the part; a later one (after a cut)
// keeps what still matches by path and version and starts the rest over.
func (j *Job) adopt(entries []*tilderv1.XferEntry) error {
	if err := validate(entries); err != nil {
		return failure{tilderv1.XferFailed_CODE_INTERNAL}
	}
	j.closeCur()
	old := map[string]int{}
	for i, e := range j.entries {
		old[string(e.GetPath())] = i
	}
	done := make([]bool, len(entries))
	partial := map[uint32]uint64{}
	keep := map[string]bool{}
	for i, e := range entries {
		k, ok := old[string(e.GetPath())]
		if !ok || !sameFile(j.entries[k], e) {
			continue
		}
		keep[string(e.GetPath())] = true
		done[i] = j.done[k]
		if n, ok := j.partial[uint32(k)]; ok { //nolint:gosec // G115: k < maxEntries
			partial[uint32(i)] = n //nolint:gosec // G115: i < maxEntries
		}
	}
	// What no longer matches goes, deepest first; then what is new is made.
	for i := len(j.entries) - 1; i >= 0; i-- {
		if p := string(j.entries[i].GetPath()); !keep[p] {
			if err := j.part.dir.RemoveAll(j.part.item(p)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return failure{codeOf(err)}
			}
		}
	}
	for i, e := range entries {
		if keep[string(e.GetPath())] {
			continue
		}
		if err := j.make(e); err != nil {
			return failure{codeOf(err)}
		}
		done[i] = e.GetKind() != tilderv1.FsKind_FS_KIND_FILE
	}
	j.entries, j.done, j.partial = entries, done, partial
	if err := j.part.saveManifest(entries); err != nil {
		return failure{codeOf(err)}
	}
	return j.saveErr()
}

// make creates a directory or a link of the manifest; files are made when
// their first chunk arrives.
func (j *Job) make(e *tilderv1.XferEntry) error {
	p := j.part.item(string(e.GetPath()))
	if err := j.part.under(string(e.GetPath())); err != nil {
		return err
	}
	switch e.GetKind() {
	case tilderv1.FsKind_FS_KIND_DIR:
		// Its parent was made before it: one level, and then it must be a
		// directory, not a name the disk took as the same as a link's.
		if err := j.part.dir.Mkdir(p, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if info, err := j.part.dir.Lstat(p); err != nil || !info.IsDir() {
			return errBadManifest
		}
		return nil
	case tilderv1.FsKind_FS_KIND_SYMLINK:
		// A link is recreated as a link, never followed (as cp -P).
		return j.part.dir.Symlink(string(e.GetLinkTarget()), p)
	default:
		return nil
	}
}

// write puts chunk c of file i in place.
func (j *Job) write(i uint32, c uint64, data []byte) error {
	if j.cur == nil || j.curIndex != i {
		j.closeCur()
		f, err := j.openFile(i, c)
		if err != nil {
			return err
		}
		j.cur, j.curIndex = f, i
	}
	_, err := j.cur.WriteAt(data, int64(c*chunkSize)) //nolint:gosec // G115: offsets fit in int64
	return err
}

// openFile opens file i to write chunk c: a file begun afresh is made anew,
// at its size, never trusting what an earlier attempt left.
func (j *Job) openFile(i uint32, c uint64) (*os.File, error) {
	e := j.entries[i]
	p := j.part.item(string(e.GetPath()))
	if err := j.part.under(string(e.GetPath())); err != nil {
		return nil, err
	}
	if c > 0 {
		return j.part.dir.OpenFile(p, os.O_RDWR|syscallNoFollow, 0)
	}
	_ = j.part.dir.Remove(p)
	f, err := j.part.dir.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscallNoFollow, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(int64(e.GetSize())); err != nil { //nolint:gosec // G115: size ≤ maxSize
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// complete syncs a file that has every chunk and gives it its permissions
// (never setuid or setgid) and time.
func (j *Job) complete(i uint32) error {
	e := j.entries[i]
	if j.cur == nil || j.curIndex != i {
		// Not open: finished after a cut, its chunks on disk, so opened as
		// it is (from chunk 0 openFile would make it anew, empty).
		j.closeCur()
		f, err := j.openFile(i, max(j.partial[i], 1))
		if err != nil {
			return err
		}
		j.cur, j.curIndex = f, i
	}
	if err := j.cur.Sync(); err != nil {
		return err
	}
	j.closeCur()
	p := j.part.item(string(e.GetPath()))
	if err := j.part.dir.Chmod(p, fs.FileMode(e.GetPerm())&fs.ModePerm); err != nil {
		return err
	}
	mtime := time.Unix(0, e.GetMtimeNs())
	if err := j.part.dir.Chtimes(p, mtime, mtime); err != nil {
		return err
	}
	j.done[i] = true
	delete(j.partial, i)
	return nil
}

func (j *Job) closeCur() {
	if j.cur != nil {
		_ = j.cur.Close()
		j.cur = nil
	}
}

func (j *Job) maybeSave() {
	if j.Clock.Now().Sub(j.lastSave) >= saveEvery {
		j.save()
	}
}

func (j *Job) save() {
	if err := j.saveErr(); err != nil {
		j.Log.Warn("could not save how far a copy got", slogErr(err))
	}
}

// saveErr records how far the copy got, after syncing the data it counts.
func (j *Job) saveErr() error {
	if j.entries == nil {
		return nil
	}
	j.lastSave = j.Clock.Now()
	if j.cur != nil {
		if err := j.cur.Sync(); err != nil {
			return err
		}
	}
	return j.part.saveState(slices.Clone(j.done), j.partial)
}

package files

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"slices"
)

// Write is a file being written; nothing on disk changes until Commit.
type Write struct {
	dir        *os.Root
	tmp        *os.File
	tmpName    string
	base       string
	ifETag     []byte
	createOnly bool
	perm       fs.FileMode
}

// BeginWrite starts writing path. With ifETag, Commit fails with Conflict if
// the file changed since it had that etag; with createOnly, if it exists.
func (t *Tree) BeginWrite(path string, ifETag []byte, createOnly bool) (*Write, error) {
	dir, base, err := t.parent(path)
	if err != nil {
		return nil, err
	}
	perm := fs.FileMode(0o644)
	if info, lerr := dir.Lstat(base); lerr == nil {
		var why error
		switch {
		case createOnly:
			why = refused(Exists, nil)
		case !info.Mode().IsRegular():
			why = refused(NotRegular, nil) // a link is edited at its target
		case t.isAgentFile(info):
			why = refused(Denied, nil)
		}
		if why != nil {
			_ = dir.Close()
			return nil, why
		}
		perm = info.Mode().Perm()
	}
	var suffix [4]byte
	if _, err = rand.Read(suffix[:]); err != nil {
		_ = dir.Close()
		return nil, err
	}
	name := ".tilder." + base + "." + hex.EncodeToString(suffix[:]) + ".tmp"
	if len(name) > maxName {
		name = ".tilder." + hex.EncodeToString(suffix[:]) + ".tmp"
	}
	tmp, err := dir.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		_ = dir.Close()
		return nil, mapErr(err)
	}
	return &Write{dir: dir, tmp: tmp, tmpName: name, base: base, ifETag: ifETag, createOnly: createOnly, perm: perm}, nil
}

// Write appends to the file being written.
func (w *Write) Write(p []byte) (int, error) {
	n, err := w.tmp.Write(p)
	return n, mapErr(err)
}

var _ io.Writer = (*Write)(nil)

// Commit puts the new file in place: synced, with the old file's
// permissions (never setuid or setgid), only if the file is still the one
// the writer read.
func (w *Write) Commit() (Entry, error) {
	defer func() { _ = w.dir.Close() }()
	fail := func(err error) (Entry, error) {
		_ = w.tmp.Close()
		_ = w.dir.Remove(w.tmpName)
		return Entry{}, err
	}
	if err := w.tmp.Sync(); err != nil {
		return fail(mapErr(err))
	}
	if err := w.tmp.Chmod(w.perm & 0o777); err != nil {
		return fail(mapErr(err))
	}
	if err := w.tmp.Close(); err != nil {
		return fail(mapErr(err))
	}
	if w.ifETag != nil {
		cur, err := w.dir.Lstat(w.base)
		if err != nil || !slices.Equal(etagOf(cur), w.ifETag) {
			return fail(refused(Conflict, err))
		}
	}
	if w.createOnly {
		if err := w.dir.Link(w.tmpName, w.base); err != nil {
			return fail(mapErr(err))
		}
		_ = w.dir.Remove(w.tmpName)
	} else if err := w.dir.Rename(w.tmpName, w.base); err != nil {
		return fail(mapErr(err))
	}
	if d, err := w.dir.Open("."); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return describe(w.dir, w.base)
}

// Abort drops the file being written.
func (w *Write) Abort() {
	_ = w.tmp.Close()
	_ = w.dir.Remove(w.tmpName)
	_ = w.dir.Close()
}

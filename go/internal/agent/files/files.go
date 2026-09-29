// Package files is the part of a machine's disk the owner's browsers reach
// (ADR 0022): the home directory, walked one directory at a time, never the
// agent's own directory, only regular files, written atomically.
//
// os.Root alone is not enough here: it follows a symlink whose target stays
// inside the root, so a root at the home directory reads the machine key
// through proj/k -> ../.tilder/identity.json. Each directory is therefore
// opened from its parent's root, so a link is followed only downward, and
// each is compared by identity (device and inode, never by name) with the
// agent's directory.
package files

import (
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/nghyane/tilder/go/internal/clock"
)

// Limits on what a request may name or ask for.
const (
	MaxPath    = 4096
	maxName    = 255
	MaxEntries = 100_000
	maxLink    = 4096
	// A temp file older than this was left by a write that never finished.
	staleTemp = 24 * time.Hour
)

// Kind is what an entry is.
type Kind int

// Kinds.
const (
	File Kind = iota + 1
	Dir
	Symlink
	Other
)

// Entry describes one name in a directory.
type Entry struct {
	Name    string // exactly the bytes on disk
	Kind    Kind
	Size    int64
	ModTime time.Time
	Perm    fs.FileMode
	// ETag changes whenever the file does (ADR 0022): what a write checks.
	ETag []byte
	// For a symlink: its target text, what it points at, or that it is dangling
	// (or points above its directory, which is never followed).
	LinkTarget string
	LinkKind   Kind
	Dangling   bool
}

// Tree serves the disk under top, minus the agent's directory.
type Tree struct {
	top   string
	agent string
	clock clock.Clock
	// guarded are the agent's directory and every directory between it and
	// top, as they were when the tree was made: none may be removed or
	// renamed, and the agent's directory is refused even once moved.
	guarded []fileID
	// hadAgent is whether the agent's directory existed then: if it is gone
	// since, every check that needs it refuses instead of passing.
	hadAgent bool
}

// New serves the tree at top; agent is the agent's own directory.
func New(top, agent string, clk clock.Clock) *Tree {
	t := &Tree{top: top, agent: agent, clock: clk}
	t.guarded, t.hadAgent = guardedIDs(top, agent)
	return t
}

// split checks a request path: slash-separated names, relative, no "." or
// "..", no empty part, no NUL. "" is the top itself.
func split(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	if len(path) > MaxPath {
		return nil, refused(Invalid, nil)
	}
	parts := strings.Split(path, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || len(p) > maxName || strings.ContainsRune(p, 0) {
			return nil, refused(Invalid, nil)
		}
	}
	return parts, nil
}

// agentIDs are the identities of the agent's directory and the files in it,
// read afresh each time (a file there may be new). ok is false when there is
// no agent directory to guard; gone, when there was one and it cannot be
// read now: then the caller refuses, never passes.
func (t *Tree) agentIDs() (dir fileID, files []fileID, ok bool, gone bool) {
	info, err := os.Lstat(t.agent)
	if err != nil {
		return fileID{}, nil, false, t.hadAgent
	}
	dir = idOf(info)
	entries, _ := os.ReadDir(t.agent)
	for _, e := range entries {
		if fi, err := e.Info(); err == nil {
			files = append(files, idOf(fi))
		}
	}
	return dir, files, true, false
}

// openDir walks parts from the top, one directory at a time.
func (t *Tree) openDir(parts []string) (*os.Root, error) {
	agentDir, _, haveAgent, gone := t.agentIDs()
	if gone {
		return nil, refused(Denied, nil)
	}
	r, err := os.OpenRoot(t.top)
	if err != nil {
		return nil, mapErr(err)
	}
	for _, part := range parts {
		sub, err := r.OpenRoot(part)
		_ = r.Close()
		if err != nil {
			return nil, mapErr(err)
		}
		info, err := sub.Stat(".")
		if err != nil || haveAgent && sameFile(idOf(info), agentDir) || t.isGuardedAgent(idOf(info)) {
			_ = sub.Close()
			return nil, refused(Denied, err)
		}
		r = sub
	}
	return r, nil
}

// OpenDir opens directory path as a root: nothing done through it leaves it,
// and it is never the agent's directory or reached through a link above.
// The caller closes it.
func (t *Tree) OpenDir(path string) (*os.Root, error) {
	parts, err := split(path)
	if err != nil {
		return nil, err
	}
	return t.openDir(parts)
}

// parent opens the directory holding path's last name.
func (t *Tree) parent(path string) (*os.Root, string, error) {
	parts, err := split(path)
	if err != nil {
		return nil, "", err
	}
	if len(parts) == 0 {
		return nil, "", refused(Invalid, nil)
	}
	dir, err := t.openDir(parts[:len(parts)-1])
	if err != nil {
		return nil, "", err
	}
	return dir, parts[len(parts)-1], nil
}

// Stat describes path ("" is the top).
func (t *Tree) Stat(path string) (Entry, error) {
	if path == "" {
		dir, err := t.openDir(nil)
		if err != nil {
			return Entry{}, err
		}
		defer func() { _ = dir.Close() }()
		info, err := dir.Stat(".")
		if err != nil {
			return Entry{}, mapErr(err)
		}
		return entryOf(info), nil
	}
	dir, base, err := t.parent(path)
	if err != nil {
		return Entry{}, err
	}
	defer func() { _ = dir.Close() }()
	return describe(dir, base)
}

// describe is one name in dir, a symlink with what it points at.
func describe(dir *os.Root, name string) (Entry, error) {
	info, err := dir.Lstat(name)
	if err != nil {
		return Entry{}, mapErr(err)
	}
	e := entryOf(info)
	e.Name = name
	if e.Kind == Symlink {
		if target, err := dir.Readlink(name); err == nil && len(target) <= maxLink {
			e.LinkTarget = target
		}
		// Resolved within dir only: a link above it is shown, never followed.
		if to, err := dir.Stat(name); err == nil {
			e.LinkKind = entryOf(to).Kind
		} else {
			e.Dangling = true
		}
	}
	return e, nil
}

func entryOf(info fs.FileInfo) Entry {
	e := Entry{Name: info.Name(), Size: info.Size(), ModTime: info.ModTime(), Perm: info.Mode().Perm(), ETag: etagOf(info)}
	switch m := info.Mode(); {
	case m.IsRegular():
		e.Kind = File
	case m.IsDir():
		e.Kind = Dir
	case m&fs.ModeSymlink != 0:
		e.Kind = Symlink
	default:
		e.Kind = Other
	}
	return e
}

// List returns up to limit entries of path's directory after the name
// after, sorted by bytes, and the name to continue from ("" at the end).
// Temp files of unfinished writes are hidden, and removed once stale.
func (t *Tree) List(path, after string, limit int) (entries []Entry, next string, truncated bool, err error) {
	parts, err := split(path)
	if err != nil {
		return nil, "", false, err
	}
	dir, err := t.openDir(parts)
	if err != nil {
		return nil, "", false, err
	}
	defer func() { _ = dir.Close() }()
	d, err := dir.Open(".")
	if err != nil {
		return nil, "", false, mapErr(err)
	}
	var names []string
	for len(names) < MaxEntries {
		batch, rerr := d.Readdirnames(1000)
		names = append(names, batch...)
		if rerr != nil {
			break
		}
	}
	truncated = len(names) >= MaxEntries
	_ = d.Close()
	now := t.clock.Now()
	names = slices.DeleteFunc(names, func(n string) bool {
		if n == PartDir {
			return true
		}
		if !isTemp(n) {
			return false
		}
		if info, err := dir.Lstat(n); err == nil && now.Sub(info.ModTime()) > staleTemp {
			_ = dir.Remove(n)
		}
		return true
	})
	slices.Sort(names)
	start, _ := slices.BinarySearch(names, after)
	if after != "" && start < len(names) && names[start] == after {
		start++
	}
	end := min(start+max(limit, 1), len(names))
	for _, n := range names[start:end] {
		if e, err := describe(dir, n); err == nil {
			entries = append(entries, e)
		}
	}
	if end < len(names) {
		next = names[end-1]
	}
	return entries, next, truncated, nil
}

// Open opens path's regular file for reading. It never blocks on a FIFO or a
// device, and never opens one of the agent's files, however it is reached.
func (t *Tree) Open(path string) (*os.File, Entry, error) {
	dir, base, err := t.parent(path)
	if err != nil {
		return nil, Entry{}, err
	}
	defer func() { _ = dir.Close() }()
	f, err := dir.OpenFile(base, os.O_RDONLY|openNonblock, 0)
	if err != nil {
		return nil, Entry{}, mapErr(err)
	}
	info, err := f.Stat()
	if err == nil && !info.Mode().IsRegular() {
		err = refused(NotRegular, nil)
	}
	if err == nil && t.isAgentFile(info) {
		err = refused(Denied, nil)
	}
	if err != nil {
		_ = f.Close()
		return nil, Entry{}, mapErr(err)
	}
	e := entryOf(info)
	e.Name = base
	return f, e, nil
}

func (t *Tree) isAgentFile(info fs.FileInfo) bool {
	_, files, ok, gone := t.agentIDs()
	return gone || ok && containsID(files, idOf(info))
}

// PartDir holds, in the directory a copy goes to, the copies from another
// machine still arriving (ADR 0035): hidden like a temp file.
const PartDir = ".tilder-part"

func isTemp(name string) bool {
	return strings.HasPrefix(name, ".tilder.") && strings.HasSuffix(name, ".tmp")
}

// Mkdir makes path's directory.
func (t *Tree) Mkdir(path string) error {
	dir, base, err := t.parent(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return mapErr(dir.Mkdir(base, 0o755))
}

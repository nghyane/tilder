package files

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// guardedIDs are the identities of the agent's directory and of every
// directory between it and top, the agent's first: removing or renaming
// any of them would take the agent's keys with it, or put them where a
// check by name no longer finds them.
func guardedIDs(top, agent string) ([]fileID, bool) {
	info, err := os.Lstat(agent)
	if err != nil {
		return nil, false
	}
	ids := []fileID{idOf(info)}
	rel, err := filepath.Rel(top, agent)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ids, true
	}
	for dir := filepath.Dir(agent); dir != top && strings.HasPrefix(dir, top); dir = filepath.Dir(dir) {
		if info, err := os.Lstat(dir); err == nil {
			ids = append(ids, idOf(info))
		}
	}
	return ids, true
}

// isGuardedAgent reports whether id is the agent's directory as it was when
// the tree was made, wherever it is now.
func (t *Tree) isGuardedAgent(id fileID) bool {
	return len(t.guarded) > 0 && sameFile(t.guarded[0], id)
}

// refuseGuarded refuses when base, in dir, is the agent's directory or one
// above it. A missing base is refused with NotFound, unless mayBeAbsent (a
// rename's destination).
func (t *Tree) refuseGuarded(dir *os.Root, base string, mayBeAbsent bool) error {
	info, err := dir.Lstat(base)
	switch {
	case err == nil && containsID(t.guarded, idOf(info)):
		return refused(Denied, nil)
	case err == nil, mayBeAbsent && errors.Is(err, fs.ErrNotExist):
		return nil
	default:
		return mapErr(err)
	}
}

// Remove removes path; recursive removes a directory's contents too, never
// following a symlink out of it. The agent's directory, and any directory
// above it, is never removed.
func (t *Tree) Remove(path string, recursive bool) error {
	dir, base, err := t.parent(path)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	if err := t.refuseGuarded(dir, base, false); err != nil {
		return err
	}
	if recursive {
		return mapErr(dir.RemoveAll(base))
	}
	return mapErr(dir.Remove(base))
}

// containsID: id is one of ids.
func containsID(ids []fileID, id fileID) bool {
	return slices.ContainsFunc(ids, func(x fileID) bool { return sameFile(x, id) })
}

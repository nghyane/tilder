//go:build windows

package files

import (
	"errors"
	"io/fs"
	"os"
)

// Rename moves from to to; with noReplace an existing to is kept (Exists).
// Both parents are walked and neither end may be the agent's directory or
// one above it, as on Unix. The move itself goes through a root at the
// home (handle-relative on Windows, reparse points resolved by Go), not
// between the two open parents: Windows has no renameat, so a name swapped
// for a junction after the walk is not caught here (ADR 0044).
func (t *Tree) Rename(from, to string, noReplace bool) error {
	src, srcBase, err := t.parent(from)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()
	dst, dstBase, err := t.parent(to)
	if err != nil {
		return err
	}
	defer func() { _ = dst.Close() }()
	if gerr := t.refuseGuarded(src, srcBase, false); gerr != nil {
		return gerr
	}
	if gerr := t.refuseGuarded(dst, dstBase, true); gerr != nil {
		return gerr
	}
	top, err := os.OpenRoot(t.top)
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = top.Close() }()
	if noReplace {
		if _, err := top.Lstat(to); err == nil {
			return refused(Exists, nil)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return mapErr(err)
		}
	}
	return mapErr(top.Rename(from, to))
}

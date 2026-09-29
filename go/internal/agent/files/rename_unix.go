//go:build unix

package files

import "golang.org/x/sys/unix"

// Rename moves from to to; with noReplace an existing to is kept (Exists).
// Both parents are walked first, so neither is the agent's directory or
// reached through a link above it, and the move then happens between those
// two open directories (renameat): a name swapped for a link after the walk
// is not followed. The agent's directory, and any above it, never moves.
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
	srcDir, err := src.Open(".")
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = srcDir.Close() }()
	dstDir, err := dst.Open(".")
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = dstDir.Close() }()
	sfd, dfd := int(srcDir.Fd()), int(dstDir.Fd()) //nolint:gosec // G115: a descriptor fits an int
	if !noReplace {
		return mapErr(unix.Renameat(sfd, srcBase, dfd, dstBase))
	}
	var st unix.Stat_t
	if err := unix.Fstatat(sfd, srcBase, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return mapErr(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		// A link fails if to exists: nothing is replaced, even in a race.
		if err := unix.Linkat(sfd, srcBase, dfd, dstBase, 0); err != nil {
			return mapErr(err)
		}
		return mapErr(unix.Unlinkat(sfd, srcBase, 0))
	}
	if err := unix.Fstatat(dfd, dstBase, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return refused(Exists, nil)
	}
	return mapErr(unix.Renameat(sfd, srcBase, dfd, dstBase))
}

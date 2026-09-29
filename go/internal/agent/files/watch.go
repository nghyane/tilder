package files

import (
	"os"
	"path/filepath"
	"runtime"
)

// On macOS a watch (kqueue) holds a file descriptor for every file in the
// directory (fsnotify README), so a big directory is looked at again on
// focus instead.
const maxWatchedEntries = 4096

// WatchPath checks that path is a directory the owner may watch, walked as
// every other request is, and returns the real path to give the watcher.
func (t *Tree) WatchPath(path string) (string, error) {
	real, dir, err := t.realDir(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = dir.Close() }()
	if runtime.GOOS == "darwin" {
		d, err := dir.Open(".")
		if err != nil {
			return "", mapErr(err)
		}
		names, _ := d.Readdirnames(maxWatchedEntries + 1)
		_ = d.Close()
		if len(names) > maxWatchedEntries {
			return "", refused(WatchLimit, nil)
		}
	}
	return real, nil
}

// DirPath checks that path is a directory under the home, walked as every
// other request is, and returns its real path: where a new shell starts
// (ADR 0024). The shell may cd anywhere afterwards; this only keeps "open a
// terminal here" from landing somewhere the owner did not point at.
func (t *Tree) DirPath(path string) (string, error) {
	real, dir, err := t.realDir(path)
	if err != nil {
		// Opening a plain file as a directory does not say ENOTDIR; say it
		// here, so the owner reads "not a folder", not "not allowed".
		if e, serr := t.Stat(path); serr == nil && e.Kind == File {
			return "", refused(NotDir, err)
		}
		return "", err
	}
	_ = dir.Close()
	return real, nil
}

// realDir walks to directory path and resolves its real path. A watcher or a
// process takes a path, not a handle, so the path is held to the identity of
// the directory the walk opened: a link swapped in between would name
// another directory, and is refused. The caller closes the opened root.
func (t *Tree) realDir(path string) (string, *os.Root, error) {
	parts, err := split(path)
	if err != nil {
		return "", nil, err
	}
	dir, err := t.openDir(parts)
	if err != nil {
		return "", nil, err
	}
	walked, err := dir.Stat(".")
	if err != nil {
		_ = dir.Close()
		return "", nil, mapErr(err)
	}
	real, err := filepath.EvalSymlinks(filepath.Join(append([]string{t.top}, parts...)...))
	if err != nil {
		_ = dir.Close()
		return "", nil, mapErr(err)
	}
	resolved, err := os.Stat(real)
	if err != nil || !sameFile(idOf(resolved), idOf(walked)) {
		_ = dir.Close()
		return "", nil, refused(Denied, err)
	}
	return real, dir, nil
}

// IsTemp reports whether name is a temp file of a write in progress, or the
// copies still arriving: hidden from lists and from watch events alike.
func IsTemp(name string) bool { return isTemp(name) || name == PartDir }

package transfer

import (
	"errors"
	"strings"

	"github.com/nghyane/tilder/go/internal/agent/xferchan"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

const (
	maxEntries = 100_000
	maxPath    = 4096
	maxName    = 255
	maxSize    = 1 << 50
	// An etag is 40 bytes (files.etagOf); names are bounded one by one, and
	// all of them together by maxManifestBytes, held in memory on this side.
	maxEtag          = 64
	maxManifestBytes = 64 << 20
	chunkSize        = xferchan.ChunkSize
)

var errBadManifest = errors.New("transfer: the source sent a manifest that cannot be copied")

// validate checks a manifest from the source machine before anything is made
// from it: the source's own item first, then names that are plain relative
// paths, each under a directory listed before it, no name twice.
func validate(entries []*tilderv1.XferEntry) error {
	if len(entries) == 0 || len(entries) > maxEntries || len(entries[0].GetPath()) != 0 {
		return errBadManifest
	}
	dirs := map[string]bool{}
	seen := map[string]bool{}
	for i, e := range entries {
		p := string(e.GetPath())
		switch e.GetKind() {
		case tilderv1.FsKind_FS_KIND_FILE:
			if e.GetSize() > maxSize {
				return errBadManifest
			}
		case tilderv1.FsKind_FS_KIND_DIR:
		case tilderv1.FsKind_FS_KIND_SYMLINK:
			if t := e.GetLinkTarget(); len(t) == 0 || len(t) > maxPath || strings.ContainsRune(string(t), 0) {
				return errBadManifest
			}
		default:
			return errBadManifest
		}
		if i == 0 {
			if e.GetKind() == tilderv1.FsKind_FS_KIND_DIR {
				dirs[""] = true
			}
			continue
		}
		if !cleanPath(p) || seen[p] || !dirs[parentOf(p)] {
			return errBadManifest
		}
		seen[p] = true
		if e.GetKind() == tilderv1.FsKind_FS_KIND_DIR {
			dirs[p] = true
		}
	}
	return nil
}

func cleanPath(p string) bool {
	if p == "" || len(p) > maxPath {
		return false
	}
	for part := range strings.SplitSeq(p, "/") {
		if part == "" || part == "." || part == ".." || len(part) > maxName || strings.ContainsRune(part, 0) {
			return false
		}
	}
	return true
}

func parentOf(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[:i]
	}
	return ""
}

func baseOf(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// chunks is how many chunks a file of size has: an empty file has one.
func chunks(size uint64) uint64 {
	return max(1, (size+xferchan.ChunkSize-1)/xferchan.ChunkSize)
}

// chunkLen is the length of chunk c of a file of size.
func chunkLen(size, c uint64) uint64 {
	start := c * xferchan.ChunkSize
	if start >= size {
		return 0
	}
	return min(xferchan.ChunkSize, size-start)
}

// sameFile: the entry is the same version of the same file. A directory has
// no version to compare (Syncthing's handleDir tracks only that it is one):
// its etag changes whenever a name inside it does, and taking that for a new
// directory threw away every file already arrived in it.
func sameFile(a, b *tilderv1.XferEntry) bool {
	if a.GetKind() == tilderv1.FsKind_FS_KIND_DIR {
		return b.GetKind() == tilderv1.FsKind_FS_KIND_DIR
	}
	return a.GetKind() == b.GetKind() && a.GetSize() == b.GetSize() && string(a.GetEtag()) == string(b.GetEtag()) &&
		string(a.GetLinkTarget()) == string(b.GetLinkTarget())
}

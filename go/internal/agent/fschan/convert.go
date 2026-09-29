package fschan

import (
	"github.com/nghyane/tilder/go/internal/agent/files"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

func kindOf(k files.Kind) tilderv1.FsKind {
	switch k {
	case files.File:
		return tilderv1.FsKind_FS_KIND_FILE
	case files.Dir:
		return tilderv1.FsKind_FS_KIND_DIR
	case files.Symlink:
		return tilderv1.FsKind_FS_KIND_SYMLINK
	case files.Other:
		return tilderv1.FsKind_FS_KIND_OTHER
	default:
		return tilderv1.FsKind_FS_KIND_UNSPECIFIED
	}
}

func entry(e files.Entry) *tilderv1.FsEntry {
	return &tilderv1.FsEntry{
		Name: []byte(e.Name), Kind: kindOf(e.Kind), Size: uint64(max(e.Size, 0)), MtimeNs: e.ModTime.UnixNano(),
		Perm: uint32(e.Perm), Etag: e.ETag, LinkTarget: []byte(e.LinkTarget), LinkKind: kindOf(e.LinkKind), Dangling: e.Dangling,
	}
}

// codeOf is the code a client sees; anything unexpected is DENIED.
func codeOf(err error) tilderv1.FsError_Code {
	switch files.CodeOf(err) {
	case files.NotFound:
		return tilderv1.FsError_CODE_NOT_FOUND
	case files.Exists:
		return tilderv1.FsError_CODE_EXISTS
	case files.NotDir:
		return tilderv1.FsError_CODE_NOT_DIR
	case files.IsDir:
		return tilderv1.FsError_CODE_IS_DIR
	case files.NotRegular:
		return tilderv1.FsError_CODE_NOT_REGULAR
	case files.Conflict:
		return tilderv1.FsError_CODE_CONFLICT
	case files.Invalid:
		return tilderv1.FsError_CODE_INVALID
	case files.NoSpace:
		return tilderv1.FsError_CODE_NO_SPACE
	case files.WatchLimit:
		return tilderv1.FsError_CODE_WATCH_LIMIT
	default:
		return tilderv1.FsError_CODE_DENIED
	}
}

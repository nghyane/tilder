package files

import (
	"encoding/binary"
	"io/fs"
	"syscall"
)

type fileID struct{ dev, ino uint64 }

// sameFile: a and b are the same file (a zero id is no file).
func sameFile(a, b fileID) bool { return a != fileID{} && a == b }

func idOf(info fs.FileInfo) fileID {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}
	}
	return fileID{uint64(st.Dev), st.Ino} //nolint:gosec // G115: a device number is never negative
}

// etagOf changes whenever the file does: identity, size, and both clocks.
func etagOf(info fs.FileInfo) []byte {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	b := make([]byte, 0, 40)
	b = binary.BigEndian.AppendUint64(b, uint64(st.Dev)) //nolint:gosec // G115: see idOf
	b = binary.BigEndian.AppendUint64(b, st.Ino)
	b = binary.BigEndian.AppendUint64(b, uint64(st.Size))                                           //nolint:gosec // G115: sizes are never negative
	b = binary.BigEndian.AppendUint64(b, uint64(st.Mtimespec.Sec)*1e9+uint64(st.Mtimespec.Nsec))    //nolint:gosec // G115: after 1970
	return binary.BigEndian.AppendUint64(b, uint64(st.Ctimespec.Sec)*1e9+uint64(st.Ctimespec.Nsec)) //nolint:gosec // G115: after 1970
}

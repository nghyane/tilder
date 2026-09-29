//go:build windows

package files

import (
	"encoding/binary"
	"io/fs"
	"os"
	"syscall"
)

// fileID on Windows is the file's FileInfo itself (ADR 0044): it carries no
// index, and os.SameFile reads the volume serial and file index when asked,
// from the handle for an open file, from the path for one listed.
type fileID struct{ fi fs.FileInfo }

func idOf(info fs.FileInfo) fileID { return fileID{info} }

// sameFile: a and b are the same file (a zero id is no file).
func sameFile(a, b fileID) bool { return a.fi != nil && b.fi != nil && os.SameFile(a.fi, b.fi) }

// etagOf changes whenever the file does: size and both clocks (the change
// time needs a handle; the write time moves with every write).
func etagOf(info fs.FileInfo) []byte {
	d, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return nil
	}
	b := make([]byte, 0, 24)
	b = binary.BigEndian.AppendUint32(b, d.FileSizeHigh)
	b = binary.BigEndian.AppendUint32(b, d.FileSizeLow)
	b = binary.BigEndian.AppendUint64(b, uint64(d.LastWriteTime.Nanoseconds()))   //nolint:gosec // G115: after 1601
	return binary.BigEndian.AppendUint64(b, uint64(d.CreationTime.Nanoseconds())) //nolint:gosec // G115: after 1601
}

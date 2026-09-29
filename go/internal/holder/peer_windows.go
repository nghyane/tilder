//go:build windows

package holder

import (
	"errors"
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sioAFUnixGetPeerPID is SIO_AF_UNIX_GETPEERPID (Windows 10 1803+): the pid
// of the process at the other end of an AF_UNIX socket.
const sioAFUnixGetPeerPID = 0x58000100

// samePeer accepts a socket peer only if it runs as this user (ADR 0005,
// 0044): Windows has no SO_PEERCRED, so the peer's pid is read and its
// token's user compared with ours. Anything that cannot be read refuses.
func samePeer(c *net.UnixConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var pid uint32
	var ioErr error
	if cerr := raw.Control(func(fd uintptr) {
		var n uint32
		ioErr = windows.WSAIoctl(windows.Handle(fd), sioAFUnixGetPeerPID, nil, 0,
			(*byte)(unsafe.Pointer(&pid)), uint32(unsafe.Sizeof(pid)), &n, nil, 0) //nolint:gosec // G103: the pid Winsock fills
	}); cerr != nil {
		return cerr
	}
	if ioErr != nil {
		return fmt.Errorf("holder: peer pid: %w", ioErr)
	}
	theirs, err := userOf(pid)
	if err != nil {
		return err
	}
	ours, err := userOf(windows.GetCurrentProcessId())
	if err != nil {
		return err
	}
	if !windows.EqualSid(theirs, ours) {
		return errors.New("holder: the peer runs as another user")
	}
	return nil
}

// userOf is the user a process runs as.
func userOf(pid uint32) (*windows.SID, error) {
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = windows.CloseHandle(p) }()
	var token windows.Token
	if terr := windows.OpenProcessToken(p, windows.TOKEN_QUERY, &token); terr != nil {
		return nil, terr
	}
	defer func() { _ = token.Close() }()
	u, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid.Copy()
}

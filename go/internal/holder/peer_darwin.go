package holder

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// samePeer accepts a socket peer only if it runs as this user: the run
// directory is 0700, and this checks again at the door (ADR 0005).
func samePeer(c *net.UnixConn) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var uid uint32
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		var cred *unix.Xucred
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr == nil {
			uid = cred.Uid
		}
	}); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	if int(uid) != os.Getuid() {
		return fmt.Errorf("holder: peer uid %d is not %d", uid, os.Getuid())
	}
	return nil
}

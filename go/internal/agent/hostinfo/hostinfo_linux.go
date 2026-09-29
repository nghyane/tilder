package hostinfo

import (
	"os"

	"golang.org/x/sys/unix"

	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

func gatherOS(h *tilderv1.HostInfo) {
	var u unix.Utsname
	if unix.Uname(&u) == nil {
		h.OsVersion = unix.ByteSliceToString(u.Release[:])
	}
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if f, err := os.Open(path); err == nil { //nolint:gosec // G304: two fixed system paths
			h.Distro, h.DistroVersion = osRelease(f)
			_ = f.Close()
			break
		}
	}
	cgroup, _ := os.ReadFile("/proc/1/cgroup")
	h.Container = container(fileExists, string(cgroup))
	if f, err := os.Open("/proc/stat"); err == nil {
		h.BootTime = bootTime(f)
		_ = f.Close()
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

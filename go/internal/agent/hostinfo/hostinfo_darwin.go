package hostinfo

import (
	"golang.org/x/sys/unix"

	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

func gatherOS(h *tilderv1.HostInfo) {
	if v, err := unix.Sysctl("kern.osproductversion"); err == nil {
		h.OsVersion = v
	}
	if tv, err := unix.SysctlTimeval("kern.boottime"); err == nil {
		h.BootTime = tv.Sec
	}
}

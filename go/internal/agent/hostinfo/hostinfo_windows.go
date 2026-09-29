package hostinfo

import (
	"fmt"

	"golang.org/x/sys/windows"

	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// gatherOS on Windows: the version as the kernel reports it (not the one an
// application manifest would fake), and the boot time from the tick count.
func gatherOS(h *tilderv1.HostInfo) {
	v := windows.RtlGetVersion()
	h.OsVersion = fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
	h.BootTime = windowsBootTime()
}

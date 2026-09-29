package hostinfo

import (
	"time"

	"golang.org/x/sys/windows"

	"github.com/nghyane/tilder/go/internal/clock"
)

var getTickCount64 = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetTickCount64")

// windowsBootTime is when Windows started, in Unix seconds; 0 when unknown.
func windowsBootTime() int64 {
	if getTickCount64.Find() != nil {
		return 0
	}
	ms, _, _ := getTickCount64.Call()
	return clock.Real().Now().Add(-time.Duration(ms) * time.Millisecond).Unix() //nolint:gosec // G115: uptime fits
}

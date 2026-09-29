package main

import (
	"testing"

	"github.com/nghyane/tilder/go/internal/agent/rtc"
	"github.com/nghyane/tilder/go/internal/identity"
)

// A connection another machine opened for a copy reaches only that copy,
// never a shell or the owner's files, whatever it names its channels; a
// device never gets the machine-to-machine channel (ADR 0035).
func TestAMachineConnectionGetsNoShellAndNoFiles(t *testing.T) {
	t.Parallel()
	device := rtc.Peer{Name: "d"}
	machine := rtc.Peer{Name: "d", Transfer: &identity.Transfer{}}
	for _, c := range []struct {
		peer  rtc.Peer
		label string
		want  string
	}{
		{device, "pty", "pty"},
		{device, "fs", "fs"},
		{device, "other", ""},
		{device, "xfer", ""},
		{device, "xfer-lan", ""},
		{device, "xfer-ctl", "xfer-ctl"},
		{machine, "xfer-ctl", ""},
		{machine, "xfer", "xfer"},
		{machine, "xfer-lan", "xfer-lan"},
		{machine, "pty", ""},
		{machine, "fs", ""},
		{machine, "ctl", ""},
	} {
		if got := channelFor(c.peer, c.label); got != c.want {
			t.Errorf("channelFor(transfer=%v, %q) = %q, want %q", c.peer.Transfer != nil, c.label, got, c.want)
		}
	}
}

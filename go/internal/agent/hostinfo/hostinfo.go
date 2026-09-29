// Package hostinfo gathers what the owner sees about a machine (ADR 0019),
// once, when the agent starts, the way Tailscale's hostinfo does. Nothing
// here names a user, an address or a process.
package hostinfo

import (
	"bufio"
	"io"
	"runtime"
	"strings"

	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// Gather reports this machine. agentVersion is the build's version.
func Gather(agentVersion string) *tilderv1.HostInfo {
	h := &tilderv1.HostInfo{Os: runtime.GOOS, Arch: runtime.GOARCH, AgentVersion: agentVersion}
	gatherOS(h)
	return h
}

// osRelease reads ID and VERSION_ID from an os-release file.
func osRelease(r io.Reader) (id, version string) {
	s := bufio.NewScanner(io.LimitReader(r, 64<<10))
	for s.Scan() {
		k, v, ok := strings.Cut(s.Text(), "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		switch k {
		case "ID":
			id = v
		case "VERSION_ID":
			version = v
		}
	}
	return id, version
}

// container tells a Docker or LXC container from the host, as Tailscale does:
// marker files first, then PID 1's cgroup.
func container(exists func(string) bool, cgroup string) string {
	switch {
	case exists("/.dockerenv"), exists("/run/.containerenv"), strings.Contains(cgroup, "/docker/"):
		return "docker"
	case strings.Contains(cgroup, "/lxc/"):
		return "lxc"
	default:
		return ""
	}
}

// bootTime reads btime (seconds since the epoch) from /proc/stat.
func bootTime(r io.Reader) int64 {
	s := bufio.NewScanner(io.LimitReader(r, 1<<20))
	for s.Scan() {
		if v, ok := strings.CutPrefix(s.Text(), "btime "); ok {
			var n int64
			for _, c := range strings.TrimSpace(v) {
				if c < '0' || c > '9' {
					return 0
				}
				n = n*10 + int64(c-'0')
			}
			return n
		}
	}
	return 0
}

package hostinfo

import (
	"runtime"
	"strings"
	"testing"

	"go.uber.org/goleak"

	"github.com/nghyane/tilder/go/internal/testutil"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m, testutil.GoleakOptions...) }

func TestOSReleaseNamesTheDistro(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, file, id, version string }{
		{"ubuntu", "NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nID=ubuntu\nID_LIKE=debian\n", "ubuntu", "24.04"},
		{"debian", "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n", "debian", "12"},
		{"alpine", "ID=alpine\nVERSION_ID=3.20.3\n", "alpine", "3.20.3"},
		{"arch has no version", "ID=arch\nBUILD_ID=rolling\n", "arch", ""},
		{"garbage", "\x00\x01 not a file\n", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			id, version := osRelease(strings.NewReader(tc.file))
			if id != tc.id || version != tc.version {
				t.Fatalf("got %q %q, want %q %q", id, version, tc.id, tc.version)
			}
		})
	}
}

func TestContainerIsToldFromTheHost(t *testing.T) {
	t.Parallel()
	none := func(string) bool { return false }
	for _, tc := range []struct {
		name   string
		exists func(string) bool
		cgroup string
		want   string
	}{
		{"docker marker", func(p string) bool { return p == "/.dockerenv" }, "", "docker"},
		{"podman marker", func(p string) bool { return p == "/run/.containerenv" }, "", "docker"},
		{"docker cgroup", none, "12:pids:/docker/3f2a\n", "docker"},
		{"lxc cgroup", none, "0::/lxc/web\n", "lxc"},
		{"the host", none, "0::/init.scope\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := container(tc.exists, tc.cgroup); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBootTimeComesFromProcStat(t *testing.T) {
	t.Parallel()
	if got := bootTime(strings.NewReader("cpu  1 2 3\nintr 5\nbtime 1758700000\nprocesses 9\n")); got != 1758700000 {
		t.Fatalf("got %d", got)
	}
	if got := bootTime(strings.NewReader("btime 17x\n")); got != 0 {
		t.Fatalf("a malformed btime gave %d", got)
	}
}

// The real machine: whatever it runs, the basics are there.
func TestGatherReportsThisMachine(t *testing.T) {
	t.Parallel()
	h := Gather("1.2.3")
	if h.GetOs() != runtime.GOOS || h.GetArch() != runtime.GOARCH || h.GetAgentVersion() != "1.2.3" {
		t.Fatalf("got %v", h)
	}
	if h.GetOsVersion() == "" || h.GetBootTime() <= 0 {
		t.Fatalf("no version or boot time: %v", h)
	}
}

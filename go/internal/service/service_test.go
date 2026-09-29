package service_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/coder/quartz"
	"go.uber.org/goleak"

	"github.com/nghyane/tilder/go/internal/service"
	"github.com/nghyane/tilder/go/internal/testutil"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m, testutil.GoleakOptions...) }

func spec(t *testing.T) service.Spec {
	t.Helper()
	return service.Spec{
		Name: "demo", Binary: "/opt/tilder tools/tilder", Home: t.TempDir(), UID: 501,
		Env: map[string]string{"TILDER_HOME": "/Users/me/.tilder", "PATH": "/usr/bin:/bin", "WEIRD": `a "b" 50% \c & <d>`},
	}
}

// Each line here is what keeps shells alive or the agent coming back; losing
// one is the bug ADR 0016 is about.
func TestTheUnitRestartsTheAgentAndSparesItsShells(t *testing.T) {
	t.Parallel()
	unit := service.SystemdUnit(spec(t))
	for _, want := range []string{
		"KillMode=process", "Restart=always", "RestartSec=5", "WantedBy=default.target",
		`ConditionFileIsExecutable=/opt/tilder\x20tools/tilder`, // gone binary: stop, don't loop
		`ExecStart="/opt/tilder tools/tilder"`,
		`Environment="TILDER_HOME=/Users/me/.tilder"`,
		`Environment="WEIRD=a \"b\" 50%% \\c & <d>"`, // quoted, % not a specifier
	} {
		if !strings.Contains(unit, want+"\n") {
			t.Errorf("unit lacks %q:\n%s", want, unit)
		}
	}
}

func TestTheLaunchAgentKeepsTheAgentAndSparesItsShells(t *testing.T) {
	t.Parallel()
	s := spec(t)
	plist := service.LaunchdPlist(s)
	for _, want := range []string{
		"<key>AbandonProcessGroup</key>\n\t<true/>",
		"<key>KeepAlive</key>\n\t<true/>",
		"<key>RunAtLoad</key>\n\t<true/>",
		"<string>run.tilder.demo</string>",
		"<string>/opt/tilder tools/tilder</string>",
		"<string>a &#34;b&#34; 50% \\c &amp; &lt;d&gt;</string>",
		"<string>" + s.LogPath() + "</string>",
	} {
		if !strings.Contains(plist, want) {
			t.Errorf("plist lacks %q:\n%s", want, plist)
		}
	}
}

func TestANameNeverBecomesAPathOrAForeignLabel(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "../x", "a/b", "A", "-x", strings.Repeat("a", 33), "x y"} {
		s := spec(t)
		s.Name = name
		if s.Check() == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	if got := spec(t).Label(); got == "com.tilder.agent" {
		t.Error("the label is the v1 agent's")
	}
}

// fake records commands; fail answers some with an error and output.
type fake struct {
	mu    sync.Mutex
	calls []string
	fail  func(cmd string, n int) (string, bool)
	// out answers a command that succeeds.
	out func(cmd string, n int) string
}

func (f *fake) run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, cmd)
	n := 0
	for _, c := range f.calls {
		if c == cmd {
			n++
		}
	}
	if f.fail != nil {
		if out, bad := f.fail(cmd, n); bad {
			return []byte(out), errors.New("exit status 1")
		}
	}
	if f.out != nil {
		return []byte(f.out(cmd, n)), nil
	}
	return nil, nil
}

func TestInstallOnLinuxWritesTheUnitThenEnablesAndRestartsIt(t *testing.T) {
	t.Parallel()
	f := &fake{out: lingerAlready}
	m := service.Manager{Spec: spec(t), OS: "linux", Run: f.run, Clock: quartz.NewReal()}
	if _, err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl --user show-environment",
		"systemctl --user daemon-reload",
		"systemctl --user enable tilder-demo.service",
		"systemctl --user restart tilder-demo.service",
		showLinger,
	}
	if !slices.Equal(f.calls, want) {
		t.Fatalf("calls %q, want %q", f.calls, want)
	}
	if raw, err := os.ReadFile(m.Spec.UnitPath()); err != nil || !strings.Contains(string(raw), "KillMode=process") {
		t.Fatalf("unit not written: %v", err)
	}

	if err := m.Uninstall(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.Spec.UnitPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unit left behind: %v", err)
	}
}

const showLinger = "loginctl show-user 501 --property=Linger --value"

func lingerAlready(cmd string, _ int) string {
	if cmd == showLinger {
		return "yes\n"
	}
	return ""
}

// Closing the last ssh session stopped the agent: systemd stops a user's
// units when they log out unless lingering is on (ADR 0030).
func TestInstallOnLinuxTurnsLingeringOn(t *testing.T) {
	t.Parallel()
	f := &fake{out: func(cmd string, n int) string {
		if cmd == showLinger && n == 1 {
			return "no\n"
		}
		if cmd == showLinger {
			return "yes\n"
		}
		return ""
	}}
	m := service.Manager{Spec: spec(t), OS: "linux", Run: f.run, Clock: quartz.NewReal()}
	note, err := m.Install(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.calls, "loginctl enable-linger") {
		t.Fatalf("lingering not turned on: %q", f.calls)
	}
	if !strings.Contains(note, "keeps running after you log out") {
		t.Fatalf("note %q", note)
	}
}

func TestInstallOnLinuxLeavesLingeringAloneWhenOn(t *testing.T) {
	t.Parallel()
	f := &fake{out: lingerAlready}
	m := service.Manager{Spec: spec(t), OS: "linux", Run: f.run, Clock: quartz.NewReal()}
	note, err := m.Install(context.Background())
	if err != nil || note != "" {
		t.Fatalf("note %q, err %v", note, err)
	}
	if slices.Contains(f.calls, "loginctl enable-linger") {
		t.Fatal("enable-linger run though lingering was on")
	}
}

// Without polkit the owner may not turn lingering on alone: the install
// still stands, and the note says how to do it with sudo.
func TestInstallOnLinuxSaysHowWhenLingeringIsRefused(t *testing.T) {
	t.Parallel()
	f := &fake{
		fail: func(cmd string, _ int) (string, bool) {
			return "Access denied", cmd == "loginctl enable-linger"
		},
		out: func(cmd string, _ int) string {
			if cmd == showLinger {
				return "no\n"
			}
			return ""
		},
	}
	m := service.Manager{Spec: spec(t), OS: "linux", Run: f.run, Clock: quartz.NewReal()}
	note, err := m.Install(context.Background())
	if err != nil {
		t.Fatalf("a refused linger failed the install: %v", err)
	}
	for _, want := range []string{"stops when you log out", "Access denied", "sudo loginctl enable-linger $USER"} {
		if !strings.Contains(note, want) {
			t.Fatalf("note %q lacks %q", note, want)
		}
	}
}

func TestInstallOnLinuxWithoutASystemdUserSessionSaysSo(t *testing.T) {
	t.Parallel()
	f := &fake{fail: func(cmd string, _ int) (string, bool) {
		return "Failed to connect to bus", strings.HasSuffix(cmd, "show-environment")
	}}
	m := service.Manager{Spec: spec(t), OS: "linux", Run: f.run, Clock: quartz.NewReal()}
	_, err := m.Install(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no systemd user session") {
		t.Fatalf("err %v", err)
	}
	if _, statErr := os.Stat(m.Spec.UnitPath()); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("a unit was written with no systemd to run it")
	}
}

// bootout returns before launchd is done: installing waits until the old job
// is gone, and retries a bootstrap that races it.
func TestInstallOnMacWaitsForTheOldJobAndRetriesAnIOError(t *testing.T) {
	t.Parallel()
	f := &fake{fail: func(cmd string, n int) (string, bool) {
		switch {
		case strings.HasPrefix(cmd, "launchctl print"):
			return "not found", n >= 2 // still loaded once, then gone
		case strings.HasPrefix(cmd, "launchctl bootstrap"):
			return "Bootstrap failed: 5: Input/output error", n == 1
		}
		return "", false
	}}
	m := service.Manager{Spec: spec(t), OS: "darwin", Run: f.run, Clock: quartz.NewReal()}
	if _, err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	target := "gui/501/run.tilder.demo"
	want := []string{
		"launchctl bootout " + target,
		"launchctl print " + target,
		"launchctl print " + target,
		"launchctl bootstrap gui/501 " + m.Spec.PlistPath(),
		"launchctl bootstrap gui/501 " + m.Spec.PlistPath(),
	}
	if !slices.Equal(f.calls, want) {
		t.Fatalf("calls %q\nwant %q", f.calls, want)
	}
}

func TestInstallOnMacOverSSHSaysThereIsNoGUISession(t *testing.T) {
	t.Parallel()
	f := &fake{fail: func(cmd string, _ int) (string, bool) {
		if strings.HasPrefix(cmd, "launchctl print") {
			return "", true
		}
		return "Bootstrap failed: 125: Domain does not support specified action", strings.HasPrefix(cmd, "launchctl bootstrap")
	}}
	m := service.Manager{Spec: spec(t), OS: "darwin", Run: f.run, Clock: quartz.NewReal()}
	if _, err := m.Install(context.Background()); err == nil || !strings.Contains(err.Error(), "no GUI login session") {
		t.Fatalf("err %v", err)
	}
}

// A file at tilder's path that tilder did not write is someone else's: install
// and uninstall leave it alone.
func TestAServiceFileTilderDidNotWriteIsNeverTouched(t *testing.T) {
	t.Parallel()
	for _, osName := range []string{"linux", "darwin"} {
		f := &fake{}
		m := service.Manager{Spec: spec(t), OS: osName, Run: f.run, Clock: quartz.NewReal()}
		path := m.Spec.UnitPath()
		if osName == "darwin" {
			path = m.Spec.PlistPath()
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("someone else's\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Install(context.Background()); err == nil {
			t.Errorf("%s: installed over a foreign file", osName)
		}
		if err := m.Uninstall(context.Background()); err == nil {
			t.Errorf("%s: uninstalled a foreign file", osName)
		}
		if raw, _ := os.ReadFile(path); string(raw) != "someone else's\n" { //nolint:gosec // G304: the test's temp path
			t.Errorf("%s: the foreign file changed: %q", osName, raw)
		}
	}
}

// Installing twice replaces tilder's own file: that is how an upgrade lands.
func TestInstallingAgainReplacesTildersOwnFile(t *testing.T) {
	t.Parallel()
	f := &fake{}
	m := service.Manager{Spec: spec(t), OS: "linux", Run: f.run, Clock: quartz.NewReal()}
	if _, err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Install(context.Background()); err != nil {
		t.Fatalf("second install: %v", err)
	}
}

func TestStatusTellsNotInstalledFromStopped(t *testing.T) {
	t.Parallel()
	f := &fake{}
	m := service.Manager{Spec: spec(t), OS: "linux", Run: f.run, Clock: quartz.NewReal()}
	got, err := m.Status(context.Background())
	if err != nil || !strings.HasSuffix(got, ": not installed") {
		t.Fatalf("status %q, %v", got, err)
	}
	if _, err := m.Install(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got, _ = m.Status(context.Background()); strings.Contains(got, "not installed") || !strings.Contains(got, "journalctl --user -u tilder-demo.service") {
		t.Fatalf("installed but not active: %q", got)
	}
}

// Package service installs the agent as the owner's own service (ADR 0016):
// a systemd user unit on Linux, a LaunchAgent on macOS, a Run value and a
// monitor on Windows (ADR 0044). It never needs root or admin rights and
// touches only files and values it names itself.
package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nghyane/tilder/go/internal/clock"
)

// Spec is one installed agent.
type Spec struct {
	// Name tells installs apart: "agent" is tilder.service and
	// run.tilder.agent; a demo can install another beside it.
	Name string
	// Binary is the absolute path the service runs.
	Binary string
	// Env is baked into the service: a service gets none of the owner's
	// login environment (PATH, SHELL…), and TILDER_HOME says which agent.
	Env map[string]string
	// Home is the owner's home directory; UID their user id.
	Home string
	UID  int
}

var validName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Check rejects a spec whose name or binary could not be written safely.
func (s Spec) Check() error {
	if !validName.MatchString(s.Name) {
		return fmt.Errorf("service name %q: use a-z, 0-9 and -, up to 32", s.Name)
	}
	if !filepath.IsAbs(s.Binary) || !filepath.IsAbs(s.Home) {
		return errors.New("service binary and home must be absolute paths")
	}
	return nil
}

// Unit is the systemd unit name.
func (s Spec) Unit() string { return "tilder-" + s.Name + ".service" }

// Label is the launchd label. The v1 agent's is com.tilder.agent: never ours.
func (s Spec) Label() string { return "run.tilder." + s.Name }

// UnitPath is where the systemd user unit lives.
func (s Spec) UnitPath() string {
	return filepath.Join(s.Home, ".config", "systemd", "user", s.Unit())
}

// PlistPath is where the LaunchAgent lives.
func (s Spec) PlistPath() string {
	return filepath.Join(s.Home, "Library", "LaunchAgents", s.Label()+".plist")
}

// LogPath is where launchd writes the agent's output (journald does on Linux).
func (s Spec) LogPath() string {
	return filepath.Join(s.Home, "Library", "Logs", "tilder-"+s.Name+".log")
}

func (s Spec) envKeys() []string {
	keys := make([]string, 0, len(s.Env))
	for k := range s.Env {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// The first line tilder writes in a service file. A file there without it is
// someone else's, and is never overwritten.
const (
	unitMarker  = "# Written by `tilder service install`; removed by `tilder service uninstall`."
	plistMarker = "<!-- Written by tilder service install; removed by tilder service uninstall. -->"
)

// ours reports whether path is free or holds a file tilder wrote.
func ours(path, marker string) error {
	raw, err := os.ReadFile(path) //nolint:gosec // G304: a path this package names
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !strings.Contains(string(raw), marker) {
		return fmt.Errorf("%s exists and was not written by tilder: remove it yourself if it is not needed", path)
	}
	return nil
}

// SystemdUnit is the user unit. KillMode=process is the point: systemd's
// default kills the whole cgroup on every restart, every shell with it
// (subshell's service.ts records the same bug).
func SystemdUnit(s Spec) string {
	var b strings.Builder
	b.WriteString(unitMarker + "\n")
	b.WriteString("[Unit]\nDescription=tilder agent (" + s.Name + ")\n")
	b.WriteString("After=network-online.target\nWants=network-online.target\n")
	// A binary deleted or moved stops the unit instead of failing it in a
	// loop (kardianos/service does the same).
	b.WriteString("ConditionFileIsExecutable=" + strings.ReplaceAll(s.Binary, " ", `\x20`) + "\n")
	b.WriteString("StartLimitIntervalSec=300\nStartLimitBurst=20\n\n")
	b.WriteString("[Service]\nType=simple\n")
	b.WriteString("ExecStart=" + systemdQuote(s.Binary) + "\n")
	for _, k := range s.envKeys() {
		b.WriteString("Environment=" + systemdQuote(k+"="+s.Env[k]) + "\n")
	}
	b.WriteString("Restart=always\nRestartSec=5\nKillMode=process\n\n")
	b.WriteString("[Install]\nWantedBy=default.target\n")
	return b.String()
}

// systemdQuote makes one word of a unit line: quoted, with backslashes and
// quotes escaped, and % doubled so it is not read as a specifier.
func systemdQuote(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%", "\n", " ")
	return `"` + r.Replace(v) + `"`
}

// Runner runs a service manager's command and returns its combined output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner runs commands for real.
func ExecRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput() //nolint:gosec // G204: systemctl/launchctl with arguments built here
}

// Manager installs, removes and reports one Spec on one OS.
type Manager struct {
	Spec  Spec
	OS    string // "linux", "darwin" or "windows"
	Run   Runner
	Clock clock.Clock
}

// Install writes the service file and starts the service; installing again
// replaces tilder's own file and restarts. The note, when not empty, is what
// the owner should know about how long it keeps running (ADR 0030).
func (m Manager) Install(ctx context.Context) (note string, err error) {
	if err := m.Spec.Check(); err != nil {
		return "", err
	}
	switch m.OS {
	case "linux":
		if err := m.installSystemd(ctx); err != nil {
			return "", err
		}
		return m.keepAfterLogout(ctx), nil
	case "darwin":
		return "", m.installLaunchd(ctx)
	case "windows":
		if err := m.installRun(ctx); err != nil {
			return "", err
		}
		return "the agent stops when you sign out of Windows", nil
	default:
		return "", fmt.Errorf("no service manager for %s", m.OS)
	}
}

// Uninstall stops the service and removes its file.
func (m Manager) Uninstall(ctx context.Context) error {
	if err := m.Spec.Check(); err != nil {
		return err
	}
	switch m.OS {
	case "linux":
		if err := ours(m.Spec.UnitPath(), unitMarker); err != nil {
			return err
		}
		if out, err := m.systemctl(ctx, "disable", "--now", m.Spec.Unit()); err != nil && !notLoaded(out) {
			return fmt.Errorf("stop %s: %w: %s", m.Spec.Unit(), err, out)
		}
		if err := removeIfThere(m.Spec.UnitPath()); err != nil {
			return err
		}
		_, err := m.systemctl(ctx, "daemon-reload")
		return err
	case "darwin":
		if err := ours(m.Spec.PlistPath(), plistMarker); err != nil {
			return err
		}
		if err := m.bootout(ctx); err != nil {
			return err
		}
		return removeIfThere(m.Spec.PlistPath())
	case "windows":
		return m.uninstallRun(ctx)
	default:
		return fmt.Errorf("no service manager for %s", m.OS)
	}
}

// Status says whether the service runs, and what the owner may need to do.
// "inactive" alone does not tell a stopped service from one never installed
// (kardianos/service checks the unit file too): the file decides.
func (m Manager) Status(ctx context.Context) (string, error) {
	if err := m.Spec.Check(); err != nil {
		return "", err
	}
	switch m.OS {
	case "linux":
		if !exists(m.Spec.UnitPath()) {
			return m.Spec.Unit() + ": not installed", nil
		}
		out, _ := m.systemctl(ctx, "is-active", m.Spec.Unit())
		state := strings.TrimSpace(string(out))
		msg := m.Spec.Unit() + ": " + state
		if state != "active" {
			msg += "\nwhy: journalctl --user -u " + m.Spec.Unit()
		}
		if !m.lingering(ctx) {
			msg += "\nthe agent stops when you log out; to keep it running, run: loginctl enable-linger"
		}
		return msg, nil
	case "darwin":
		if !exists(m.Spec.PlistPath()) {
			return m.Spec.Label() + ": not installed", nil
		}
		out, loaded := m.loaded(ctx)
		if !loaded {
			return m.Spec.Label() + ": installed, not loaded (it loads at the next login)", nil
		}
		return m.Spec.Label() + ": " + launchdState(string(out)) + "\nlog: " + m.Spec.LogPath(), nil
	case "windows":
		return m.statusRun(ctx)
	default:
		return "", fmt.Errorf("no service manager for %s", m.OS)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func (m Manager) installSystemd(ctx context.Context) error {
	if out, err := m.systemctl(ctx, "show-environment"); err != nil {
		why := strings.TrimSpace(string(out))
		if why == "" {
			why = err.Error() // no systemctl at all: a container
		}
		return fmt.Errorf("no systemd user session here (%s): run the agent by hand, or log in to a desktop or with lingering enabled", why)
	}
	if err := ours(m.Spec.UnitPath(), unitMarker); err != nil {
		return err
	}
	if err := writeFile(m.Spec.UnitPath(), SystemdUnit(m.Spec)); err != nil {
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", m.Spec.Unit()}, {"restart", m.Spec.Unit()}} {
		if out, err := m.systemctl(ctx, args...); err != nil {
			return fmt.Errorf("systemctl --user %s: %w: %s", strings.Join(args, " "), err, out)
		}
	}
	return nil
}

func (m Manager) installLaunchd(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(m.Spec.LogPath()), 0o755); err != nil { //nolint:gosec // G301: ~/Library/Logs is the owner's
		return err
	}
	if err := ours(m.Spec.PlistPath(), plistMarker); err != nil {
		return err
	}
	if err := writeFile(m.Spec.PlistPath(), LaunchdPlist(m.Spec)); err != nil {
		return err
	}
	if err := m.bootout(ctx); err != nil {
		return err
	}
	// bootstrap right after a bootout can fail with an I/O error while
	// launchd is still tearing the old job down: retry once.
	for attempt := 0; ; attempt++ {
		out, err := m.Run(ctx, "launchctl", "bootstrap", m.domain(), m.Spec.PlistPath())
		if err == nil {
			return nil
		}
		text := string(out)
		if strings.Contains(text, "Domain does not support") || strings.Contains(text, "Could not find domain") {
			return errors.New("no GUI login session (an SSH session has none): log in on the Mac and install from there")
		}
		if attempt == 0 && strings.Contains(text, "Input/output error") {
			<-m.Clock.NewTimer(time.Second, "bootstrap-retry").C
			continue
		}
		return fmt.Errorf("launchctl bootstrap: %w: %s", err, strings.TrimSpace(text))
	}
}

// bootout unloads the job and waits until it is gone: bootout returns before
// launchd has finished, and a bootstrap then fails.
func (m Manager) bootout(ctx context.Context) error {
	_, _ = m.Run(ctx, "launchctl", "bootout", m.target())
	deadline := m.Clock.Now().Add(10 * time.Second)
	for {
		if _, loaded := m.loaded(ctx); !loaded {
			return nil
		}
		if m.Clock.Now().After(deadline) {
			return fmt.Errorf("launchd did not unload %s within 10s", m.Spec.Label())
		}
		<-m.Clock.NewTimer(100*time.Millisecond, "bootout-wait").C
	}
}

// loaded asks launchd about the job; it answers with an error when the job
// is not loaded.
func (m Manager) loaded(ctx context.Context) ([]byte, bool) {
	out, err := m.Run(ctx, "launchctl", "print", m.target())
	return out, err == nil
}

func (m Manager) domain() string { return fmt.Sprintf("gui/%d", m.Spec.UID) }
func (m Manager) target() string { return m.domain() + "/" + m.Spec.Label() }

func (m Manager) systemctl(ctx context.Context, args ...string) ([]byte, error) {
	return m.Run(ctx, "systemctl", append([]string{"--user"}, args...)...)
}

func notLoaded(out []byte) bool {
	s := string(out)
	return strings.Contains(s, "not loaded") || strings.Contains(s, "does not exist") || strings.Contains(s, "No such file")
}

// writeFile replaces path by rename, so a reader never sees half a file.
func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // G301: ~/.config/systemd/user and ~/Library are the owner's, readable as usual
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil { //nolint:gosec // G306: service files are read by the service manager; they hold no secret
		return err
	}
	return os.Rename(tmp, path)
}

func removeIfThere(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

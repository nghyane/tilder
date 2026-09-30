//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// runKey starts a program at sign-in without admin rights (ADR 0044), as VS
// Code's tunnel service registers itself (cli/src/tunnels/service_windows.rs).
// It never restarts one that stopped: the monitor does.
const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// HiddenEnv tells the monitor it already runs without a console: the Run key
// starts it in one, and it starts itself again hidden, as VS Code does.
const HiddenEnv = "TILDER_MONITOR"

func (s Spec) runValue() string { return "tilder-" + s.Name }

// stateDir holds the monitor's pid file and the agent's log, where launchd's
// LaunchAgent log lives on macOS.
func (s Spec) stateDir() string { return filepath.Join(s.Home, "AppData", "Local", "tilder") }

func (s Spec) winLogPath() string { return filepath.Join(s.stateDir(), "tilder-"+s.Name+".log") }
func (s Spec) pidPath() string    { return filepath.Join(s.stateDir(), "tilder-"+s.Name+".pid") }

// monitorArgs are the monitor's arguments after the binary.
func (s Spec) monitorArgs() []string {
	args := []string{"service", "run", "--name", s.Name}
	if h := s.Env["TILDER_HOME"]; h != "" {
		args = append(args, "--home", h)
	}
	return args
}

// RunCommand is the Run value: the monitor's command line, each word quoted
// as Windows splits it.
func RunCommand(s Spec) string {
	words := append([]string{s.Binary}, s.monitorArgs()...)
	for i, w := range words {
		words[i] = syscall.EscapeArg(w)
	}
	return strings.Join(words, " ")
}

// runValueIsOurs: a value under our name that does not run `service run
// --name <name>` is someone else's, and is never overwritten.
func runValueIsOurs(s Spec, value string) bool {
	return strings.Contains(value, " service run --name "+syscall.EscapeArg(s.Name))
}

func openRunKey(access uint32) (registry.Key, error) {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, access)
	if err != nil {
		return 0, fmt.Errorf("open the Run key: %w", err)
	}
	return k, nil
}

func (m Manager) installRun(ctx context.Context) error {
	k, err := openRunKey(registry.QUERY_VALUE | registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	old, _, err := k.GetStringValue(m.Spec.runValue())
	switch {
	case errors.Is(err, registry.ErrNotExist):
	case err != nil:
		return fmt.Errorf("read the Run value: %w", err)
	case !runValueIsOurs(m.Spec, old):
		return fmt.Errorf(`HKCU\%s\%s exists and was not written by tilder: remove it yourself if it is not needed`, runKey, m.Spec.runValue())
	}
	if err := os.MkdirAll(m.Spec.stateDir(), 0o700); err != nil {
		return err
	}
	if err := k.SetStringValue(m.Spec.runValue(), RunCommand(m.Spec)); err != nil {
		return fmt.Errorf("write the Run value: %w", err)
	}
	if err := stopMonitor(m.Spec); err != nil {
		return err
	}
	if err := startMonitor(m.Spec); err != nil {
		return err
	}
	return m.waitMonitor(ctx)
}

// waitMonitor waits for the new monitor's pid file, so install fails when
// the monitor could not start rather than at the next sign-in.
func (m Manager) waitMonitor(ctx context.Context) error {
	deadline := m.Clock.Now().Add(10 * time.Second)
	for {
		if _, ok := monitorPid(m.Spec); ok {
			return nil
		}
		if m.Clock.Now().After(deadline) {
			return fmt.Errorf("the monitor did not start within 10s: see %s", m.Spec.winLogPath())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.Clock.NewTimer(100*time.Millisecond, "monitor-wait").C:
		}
	}
}

func (m Manager) uninstallRun(context.Context) error {
	k, err := openRunKey(registry.QUERY_VALUE | registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	old, _, err := k.GetStringValue(m.Spec.runValue())
	switch {
	case errors.Is(err, registry.ErrNotExist):
	case err != nil:
		return fmt.Errorf("read the Run value: %w", err)
	case !runValueIsOurs(m.Spec, old):
		return fmt.Errorf(`HKCU\%s\%s was not written by tilder: left alone`, runKey, m.Spec.runValue())
	default:
		if err := k.DeleteValue(m.Spec.runValue()); err != nil {
			return fmt.Errorf("remove the Run value: %w", err)
		}
	}
	return stopMonitor(m.Spec)
}

func (m Manager) statusRun(context.Context) (string, error) {
	k, err := openRunKey(registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer func() { _ = k.Close() }()
	name := m.Spec.runValue()
	if _, _, err := k.GetStringValue(name); errors.Is(err, registry.ErrNotExist) {
		return name + ": not installed", nil
	} else if err != nil {
		return "", fmt.Errorf("read the Run value: %w", err)
	}
	if pid, ok := monitorPid(m.Spec); ok {
		return fmt.Sprintf("%s: running (monitor pid %d)\nlog: %s", name, pid, m.Spec.winLogPath()), nil
	}
	return name + ": installed, not running (it starts at the next sign-in)\nlog: " + m.Spec.winLogPath(), nil
}

// startMonitor starts the monitor with no console, out of the caller's job
// when it may (a terminal's job could end it with the window), as the
// holder starts.
func startMonitor(s Spec) error {
	const flags = windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP
	err := startHidden(s, flags|windows.CREATE_BREAKAWAY_FROM_JOB)
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		err = startHidden(s, flags)
	}
	if err != nil {
		return fmt.Errorf("start the monitor: %w", err)
	}
	return nil
}

func startHidden(s Spec, flags uint32) error {
	cmd := exec.CommandContext(context.Background(), s.Binary, s.monitorArgs()...) //nolint:gosec // G204: this binary, re-run as the monitor
	cmd.Env = append(cmd.Environ(), HiddenEnv+"=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: flags, HideWindow: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Not waited for: it outlives this process.
	return cmd.Process.Release()
}

// monitorPid is the running monitor's pid. The pid file names the process's
// creation time too: a pid reused by another process is not ours to stop,
// and a binary renamed under a running monitor (a reinstall) is still ours.
func monitorPid(s Spec) (uint32, bool) {
	h, pid, err := openMonitor(s, windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return 0, false
	}
	_ = windows.CloseHandle(h)
	return pid, true
}

// monitorRecord is the pid file's content for the process h is.
func monitorRecord(pid uint32, h windows.Handle) (string, error) {
	created, err := processCreated(h)
	if err != nil {
		return "", err
	}
	return strconv.FormatUint(uint64(pid), 10) + "\n" + strconv.FormatInt(created, 10) + "\n", nil
}

// openMonitor opens the process the pid file names, if it is still that
// process and still running.
func openMonitor(s Spec, access uint32) (windows.Handle, uint32, error) {
	raw, err := os.ReadFile(s.pidPath())
	if err != nil {
		return 0, 0, err
	}
	pidText, _, _ := strings.Cut(string(raw), "\n")
	pid, err := strconv.ParseUint(pidText, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("read %s: %w", s.pidPath(), err)
	}
	h, err := windows.OpenProcess(access|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, 0, err
	}
	var code uint32
	record, rerr := monitorRecord(uint32(pid), h)
	if err := windows.GetExitCodeProcess(h, &code); err != nil || code != 259 || rerr != nil || record != string(raw) { // 259: STILL_ACTIVE
		_ = windows.CloseHandle(h)
		return 0, 0, errors.New("the monitor is gone")
	}
	return h, uint32(pid), nil
}

// processCreated is when the process started, in 100 ns ticks.
func processCreated(h windows.Handle) (int64, error) {
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return 0, err
	}
	return created.Nanoseconds(), nil
}

// stopMonitor ends the running monitor, and the agent with it: the agent is
// in the monitor's kill-on-close job. Shells live on in their holders, which
// left that job.
func stopMonitor(s Spec) error {
	h, _, err := openMonitor(s, windows.PROCESS_TERMINATE|windows.SYNCHRONIZE)
	if err == nil {
		defer func() { _ = windows.CloseHandle(h) }()
		if err := windows.TerminateProcess(h, 1); err != nil {
			return fmt.Errorf("stop the monitor: %w", err)
		}
		ev, err := windows.WaitForSingleObject(h, 10_000)
		if err != nil {
			return fmt.Errorf("wait for the monitor: %w", err)
		}
		if ev != windows.WAIT_OBJECT_0 {
			return errors.New("the monitor did not stop within 10s")
		}
	}
	return removeIfThere(s.pidPath())
}

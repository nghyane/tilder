//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// maxLog is how large the agent's log may grow before the next monitor
// start begins it again.
const maxLog = 10 << 20

// Monitor is the Windows service (ADR 0044), as Syncthing's monitor
// process: it runs the agent, starts it again when it stops, and gives up on
// one that cannot run. The agent runs in a job that dies with the monitor,
// so stopping the monitor stops it; the job lets the holders break away, so
// shells outlive both.
func (m Manager) Monitor(ctx context.Context, hidden bool) error {
	if err := m.Spec.Check(); err != nil {
		return err
	}
	if !hidden {
		// Started by the Run key, in a console window: go on without one.
		return startMonitor(m.Spec)
	}
	if _, ok := monitorPid(m.Spec); ok {
		return nil // one runs already (a second sign-in, an install racing the Run key)
	}
	if err := os.MkdirAll(m.Spec.stateDir(), 0o700); err != nil {
		return err
	}
	log, err := openLog(m.Spec.winLogPath())
	if err != nil {
		return err
	}
	defer func() { _ = log.Close() }()
	// Nobody reads a hidden process's stderr: why it stopped goes in the log.
	if err := m.monitor(ctx, log); err != nil {
		_, _ = fmt.Fprintln(log, "tilder monitor:", err)
		return err
	}
	return nil
}

func (m Manager) monitor(ctx context.Context, log *os.File) error {
	job, err := killOnCloseJob()
	if err != nil {
		return err
	}
	// Held until the monitor ends, by exit or by TerminateProcess: the last
	// handle closing is what ends the agent.
	defer func() { _ = windows.CloseHandle(job) }()
	if err = windows.AssignProcessToJobObject(job, windows.CurrentProcess()); err != nil {
		return fmt.Errorf("join the monitor's job: %w", err)
	}
	record, err := monitorRecord(uint32(os.Getpid()), windows.CurrentProcess()) //nolint:gosec // G115: a Windows pid is a DWORD
	if err != nil {
		return fmt.Errorf("read the monitor's start time: %w", err)
	}
	if err := os.WriteFile(m.Spec.pidPath(), []byte(record), 0o600); err != nil {
		return err
	}
	defer func() { _ = os.Remove(m.Spec.pidPath()) }()

	var guard restarts
	for {
		if !guard.allow(m.Clock.Now()) {
			return errors.New("the agent stopped 4 times within a minute; not starting it again")
		}
		code, err := m.runAgent(ctx, log)
		if err != nil {
			return err
		}
		if code == 0 {
			return nil // the agent meant to stop
		}
		_, _ = fmt.Fprintf(log, "tilder monitor: the agent exited with %d; starting it again in 5s\n", code)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-m.Clock.NewTimer(5*time.Second, "monitor-restart").C:
		}
	}
}

// runAgent runs the agent once and returns its exit code. It has no console
// of its own (the monitor has none to share) and writes to the log.
func (m Manager) runAgent(ctx context.Context, log *os.File) (int, error) {
	cmd := exec.CommandContext(ctx, m.Spec.Binary) //nolint:gosec // G204: this binary, run as the agent
	cmd.Env = cmd.Environ()
	for _, k := range m.Spec.envKeys() {
		cmd.Env = append(cmd.Env, k+"="+m.Spec.Env[k])
	}
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW, HideWindow: true}
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &exit):
		return exit.ExitCode(), nil
	default:
		return 0, fmt.Errorf("start the agent: %w", err)
	}
}

// killOnCloseJob is a job that ends its processes when its last handle
// closes, and lets a process started with CREATE_BREAKAWAY_FROM_JOB leave it
// (the holders): the pair OpenSSH for Windows and tailscale's s4u use.
func killOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("create the monitor's job: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_BREAKAWAY_OK,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil { //nolint:gosec // G103: the Win32 call takes the struct's address
		_ = windows.CloseHandle(job)
		return 0, fmt.Errorf("set the monitor's job limits: %w", err)
	}
	return job, nil
}

// openLog opens the agent's log for appending, starting it again when it
// has grown past maxLog.
func openLog(path string) (*os.File, error) {
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if info, err := os.Stat(path); err == nil && info.Size() > maxLog {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600) //nolint:gosec // G304: a path this package names
	if err != nil {
		return nil, fmt.Errorf("open the agent's log: %w", err)
	}
	return f, nil
}

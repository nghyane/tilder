//go:build windows

package holder

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// winConsole is a pseudoconsole (ConPTY, Windows 10 1809+) and the shell in
// it, in a job object that ends the shell's whole tree (ADR 0044): coder's
// agent kills only the shell and leaves its children; OpenSSH for Windows
// and tailscale's s4u use a job the same way.
type winConsole struct {
	hpc  windows.Handle
	in   *os.File // written to: what is typed
	out  *os.File // read from: what the console draws
	proc windows.Handle
	job  windows.Handle
	id   int

	closePC sync.Once
	closed  sync.Once
}

func startConsole(cfg Config, dir string, cols, rows uint16) (_ console, err error) {
	c := &winConsole{}
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("start shell: %w", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		_, _ = inR.Close(), inW.Close()
		return nil, fmt.Errorf("start shell: %w", err)
	}
	c.in, c.out = inW, outR
	// The console's ends are its own once it has them: closing ours lets a
	// read end when conhost lets go (coder closes them the same way).
	defer func() { _, _ = inR.Close(), outW.Close() }()
	defer func() {
		if err != nil {
			c.release()
		}
	}()
	if err = windows.CreatePseudoConsole(size(cols, rows), windows.Handle(inR.Fd()), windows.Handle(outW.Fd()), 0, &c.hpc); err != nil {
		return nil, fmt.Errorf("start shell: pseudoconsole: %w", err)
	}
	if c.job, err = killingJob(); err != nil {
		return nil, fmt.Errorf("start shell: job: %w", err)
	}
	pi, err := c.spawn(cfg, dir)
	if err != nil {
		return nil, fmt.Errorf("start shell: %w", err)
	}
	c.proc, c.id = pi.Process, int(pi.ProcessId)
	return c, nil
}

// spawn starts the shell suspended in the pseudoconsole, puts it in the job
// before it runs a line (so nothing it starts escapes the job), then lets it go.
func (c *winConsole) spawn(cfg Config, dir string) (windows.ProcessInformation, error) {
	var pi windows.ProcessInformation
	path, err := exec.LookPath(cfg.Shell)
	if err != nil {
		return pi, err
	}
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return pi, err
	}
	defer attrs.Delete()
	// The attribute's value is the console handle itself, as the Win32 docs
	// and coder's startPty pass it: its bits read as a pointer.
	value := *(*unsafe.Pointer)(unsafe.Pointer(&c.hpc)) //nolint:gosec // G103: the handle is the value Win32 expects
	if err = attrs.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, value, unsafe.Sizeof(c.hpc)); err != nil {
		return pi, err
	}
	si := &windows.StartupInfoEx{ProcThreadAttributeList: attrs.List()}
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = windows.STARTF_USESTDHANDLES
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return pi, err
	}
	argsPtr, err := windows.UTF16PtrFromString(windows.ComposeCommandLine(append([]string{path}, cfg.Args...)))
	if err != nil {
		return pi, err
	}
	var dirPtr *uint16
	if dir != "" {
		if dirPtr, err = windows.UTF16PtrFromString(dir); err != nil {
			return pi, err
		}
	}
	flags := uint32(windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_SUSPENDED)
	if err = windows.CreateProcess(pathPtr, argsPtr, nil, nil, false, flags, envBlock(cfg.Env), dirPtr, &si.StartupInfo, &pi); err != nil {
		return pi, err
	}
	defer func() { _ = windows.CloseHandle(pi.Thread) }()
	if err = windows.AssignProcessToJobObject(c.job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		_ = windows.CloseHandle(pi.Process)
		return pi, err
	}
	if _, err = windows.ResumeThread(pi.Thread); err != nil {
		_ = windows.TerminateJobObject(c.job, 1)
		_ = windows.CloseHandle(pi.Process)
		return pi, err
	}
	return pi, nil
}

// killingJob is a job whose processes all end when it is terminated or its
// last handle closes.
func killingJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil { //nolint:gosec // G103: the struct Win32 fills
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

func size(cols, rows uint16) windows.Coord {
	return windows.Coord{X: int16(cols), Y: int16(rows)} //nolint:gosec // G115: clamped to 1000 by the holder
}

// envBlock is env as CreateProcess takes it: NUL-separated, NUL-ended,
// UTF-16. SYSTEMROOT is kept whatever env says: without it Winsock, and so
// half of what a shell runs, fails to start (coder's addCriticalEnv).
func envBlock(env []string) *uint16 {
	if !slicesHasPrefix(env, "SYSTEMROOT=") {
		env = append(env, "SYSTEMROOT="+os.Getenv("SYSTEMROOT")) //nolint:forbidigo // the holder's own environment
	}
	var b []uint16
	for _, kv := range env {
		if strings.ContainsRune(kv, 0) {
			continue
		}
		b = append(b, utf16.Encode([]rune(kv))...)
		b = append(b, 0)
	}
	b = append(b, 0)
	return &b[0]
}

func slicesHasPrefix(env []string, prefix string) bool {
	for _, kv := range env {
		if len(kv) >= len(prefix) && strings.EqualFold(kv[:len(prefix)], prefix) {
			return true
		}
	}
	return false
}

func (c *winConsole) Read(p []byte) (int, error)  { return c.out.Read(p) }
func (c *winConsole) Write(p []byte) (int, error) { return c.in.Write(p) }
func (c *winConsole) resize(cols, rows uint16) error {
	return windows.ResizePseudoConsole(c.hpc, size(cols, rows))
}
func (c *winConsole) pid() int { return c.id }

// wait ends when the shell's process does. The pseudoconsole is closed then:
// conhost holds the output pipe's write end, and the read would never end
// (coder's waitInternal).
func (c *winConsole) wait() int {
	_, _ = windows.WaitForSingleObject(c.proc, windows.INFINITE)
	var code uint32
	_ = windows.GetExitCodeProcess(c.proc, &code)
	// Closed here, not in release: the output can end first (a hangup), and
	// the handle is still waited on then.
	_ = windows.CloseHandle(c.proc)
	c.closeConsole()
	return int(code)
}

// hangup closes the pseudoconsole: Windows sends every process attached to
// it CTRL_CLOSE_EVENT, as a terminal's hangup does on Unix.
func (c *winConsole) hangup() { c.closeConsole() }

// killAll ends the shell's whole tree.
func (c *winConsole) killAll() { _ = windows.TerminateJobObject(c.job, 1) }

func (c *winConsole) closeOutput() { c.release() }

// closeConsole may block until conhost has written its last frame: the
// output is still being read when it runs (coder: "a blocking system call").
func (c *winConsole) closeConsole() {
	c.closePC.Do(func() {
		if c.hpc != 0 {
			windows.ClosePseudoConsole(c.hpc)
		}
	})
}

// release frees everything once: closing the job's last handle ends what is
// still in it.
func (c *winConsole) release() {
	c.closed.Do(func() {
		c.closeConsole()
		_, _ = c.in.Close(), c.out.Close()
		if c.job != 0 {
			_ = windows.CloseHandle(c.job)
		}
	})
}

// DefaultShell is the shell a Windows terminal opens (ADR 0044): PowerShell
// 7 if it is there, else Windows PowerShell, else comspec (coder's
// usershell order). There is no $SHELL to read.
func DefaultShell(comspec string) (string, []string) {
	for _, name := range []string{"pwsh.exe", "powershell.exe"} {
		if path, err := exec.LookPath(name); err == nil {
			return path, []string{"-NoLogo"}
		}
	}
	return comspec, nil
}

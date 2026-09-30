//go:build windows

package service_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/coder/quartz"
	"golang.org/x/sys/windows/registry"

	"github.com/nghyane/tilder/go/internal/service"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

// buildAgent builds the real binary: the monitor runs it. Not t.TempDir():
// Windows keeps a running binary from being deleted.
func buildAgent(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "tsvc") //nolint:usetesting // removal may fail while a process holds the binary
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	bin := filepath.Join(dir, "tilder.exe")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "./cmd/tilder") //nolint:gosec // G204: the test's own temp path
	build.Dir = filepath.Join("..", "..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func manager(t *testing.T, name, bin string) service.Manager {
	t.Helper()
	return service.Manager{
		Spec: service.Spec{
			Name: name, Binary: bin, Home: t.TempDir(),
			Env: map[string]string{"TILDER_HOME": filepath.Join(t.TempDir(), ".tilder")},
		},
		OS: "windows", Clock: quartz.NewReal(),
	}
}

func runValue(t *testing.T, name string) (string, bool) {
	t.Helper()
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue("tilder-" + name)
	return v, err == nil
}

// ADR 0044: install writes the Run value and starts the monitor at once;
// uninstall removes the value and stops the monitor.
//
// Not parallel: the monitor finds its folder from USERPROFILE, which the test
// points at its own.
func TestTheWindowsServiceIsARunValueAndAMonitor(t *testing.T) {
	ctx := context.Background()
	name := "ci-" + strconv.Itoa(os.Getpid())
	m := manager(t, name, buildAgent(t))
	t.Setenv("USERPROFILE", m.Spec.Home)
	t.Cleanup(func() { _ = m.Uninstall(ctx) })

	if _, err := m.Install(ctx); err != nil {
		log, _ := os.ReadFile(filepath.Join(m.Spec.Home, "AppData", "Local", "tilder", "tilder-"+name+".log")) //nolint:gosec // G304: the test's own temp path
		t.Fatalf("install: %v\nlog:\n%s", err, log)
	}
	if v, ok := runValue(t, name); !ok || v != service.RunCommand(m.Spec) {
		t.Fatalf("Run value %q, want %q", v, service.RunCommand(m.Spec))
	}
	if st, err := m.Status(ctx); err != nil || !strings.Contains(st, "running (monitor pid") {
		t.Fatalf("status %q, %v", st, err)
	}
	// Installing again replaces the monitor rather than adding one.
	if _, err := m.Install(ctx); err != nil {
		t.Fatalf("install again: %v", err)
	}

	if err := m.Uninstall(ctx); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	if _, ok := runValue(t, name); ok {
		t.Fatal("the Run value is still there")
	}
	if st, err := m.Status(ctx); err != nil || !strings.Contains(st, "not installed") {
		t.Fatalf("status after uninstall %q, %v", st, err)
	}
}

// A value under tilder's name that tilder did not write is never replaced.
func TestSomeoneElsesRunValueIsLeftAlone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	name := "ci-other-" + strconv.Itoa(os.Getpid())
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.SetStringValue("tilder-"+name, `C:\Windows\notepad.exe`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = k.DeleteValue("tilder-" + name); _ = k.Close() })

	m := manager(t, name, `C:\nowhere\tilder.exe`)
	if _, err := m.Install(ctx); err == nil {
		t.Fatal("installed over someone else's Run value")
	}
	if err := m.Uninstall(ctx); err == nil {
		t.Fatal("uninstall removed someone else's Run value")
	}
	if v, _ := runValue(t, name); v != `C:\Windows\notepad.exe` {
		t.Fatalf("the value became %q", v)
	}
}

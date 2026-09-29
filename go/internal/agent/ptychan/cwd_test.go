package ptychan_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coder/quartz"

	"github.com/nghyane/tilder/go/internal/agent/ptychan"
	"github.com/nghyane/tilder/go/internal/holder"
	"github.com/nghyane/tilder/go/internal/testutil"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// The console learns where the shell is at the attach, and again after a cd:
// Duplicate, Split and the tab's name follow it (ADR 0024).
func TestTheShellsFolderIsSentAndFollowsCd(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "src", "api"), 0o750); err != nil {
		t.Fatal(err)
	}
	shells := holder.NewManager(holder.Config{
		Shell: "/bin/sh", Env: []string{"TERM=xterm-256color", "PS1=$ ", "HISTFILE=/dev/null", "HOME=" + home},
		Dir: home, RingSize: 1 << 16, Clock: quartz.NewReal(),
	})
	t.Cleanup(shells.Close)
	clk := quartz.NewMock(t)
	wait := clk.Trap().NewTimer("ptychan", "cwd")
	defer wait.Close()

	c := serveWhere(t, shells, &ptychan.Where{Cwd: holder.WorkingDir, Home: home, Clock: clk})
	send(t, c, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{ShellId: "here", Cols: 80, Rows: 24}}})
	buf := make([]byte, 64*1024)
	next := func() *tilderv1.PtyCwd {
		t.Helper()
		for {
			if cwd := receive(t, c, buf).GetCwd(); cwd != nil {
				return cwd
			}
		}
	}
	if cwd := next(); string(cwd.GetDir()) != "" || cwd.GetOutsideHome() {
		t.Fatalf("at the attach: %q outside=%v, want the home", cwd.GetDir(), cwd.GetOutsideHome())
	}
	ctx := testutil.Context(t, testutil.WaitShort)
	wait.MustWait(ctx).MustRelease(ctx) // the first lookup's wait has started
	// The marker is printed after the cd ran ("cd-%s" in the echo of the line
	// is not it): only then is there a new folder to find. The echo alone
	// pokes a look that can still see the home (it did, on Linux).
	send(t, c, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Input{Input: &tilderv1.PtyInput{Data: []byte("cd src/api && printf 'cd-%s\\n' done\n")}}})
	for seen := ""; !strings.Contains(seen, "cd-done"); {
		seen += string(receive(t, c, buf).GetOutput().GetData())
	}
	clk.Advance(2e9).MustWait(ctx) // the wait ends; the marker's output asked for another look
	if cwd := next(); string(cwd.GetDir()) != "src/api" {
		t.Fatalf("after cd: %q, want src/api", cwd.GetDir())
	}
}

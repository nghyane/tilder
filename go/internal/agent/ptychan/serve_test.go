//go:build unix

package ptychan_test

import (
	"context"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/coder/quartz"
	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/ptychan"
	"github.com/nghyane/tilder/go/internal/holder"
	"github.com/nghyane/tilder/go/internal/testutil"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

func send(t *testing.T, c net.Conn, msg *tilderv1.PtyClient) {
	t.Helper()
	frame, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(frame); err != nil {
		t.Fatal(err)
	}
}

func serve(t *testing.T, shells ptychan.Shells) net.Conn {
	t.Helper()
	return serveIn(t, shells, nil)
}

func serveIn(t *testing.T, shells ptychan.Shells, dirs ptychan.Dirs) net.Conn {
	t.Helper()
	return serveWith(t, shells, dirs, nil)
}

func serveWhere(t *testing.T, shells ptychan.Shells, where *ptychan.Where) net.Conn {
	t.Helper()
	return serveWith(t, shells, nil, where)
}

func serveWith(t *testing.T, shells ptychan.Shells, dirs ptychan.Dirs, where *ptychan.Where) net.Conn {
	t.Helper()
	return serveSized(t, shells, dirs, where, nil)
}

func serveSized(t *testing.T, shells ptychan.Shells, dirs ptychan.Dirs, where *ptychan.Where, sizes *ptychan.Sizes) net.Conn {
	t.Helper()
	client, server := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ptychan.Serve(ctx, server, shells, dirs, where, sizes) }()
	t.Cleanup(func() {
		cancel()
		_ = client.Close()
		<-done
	})
	_ = client.SetReadDeadline(time.Now().Add(testutil.WaitShort)) //nolint:forbidigo // a real shell needs real time
	return client
}

func shellManager(t *testing.T) *holder.Manager {
	t.Helper()
	m := holder.NewManager(holder.Config{
		Shell: "/bin/sh", Env: []string{"TERM=xterm-256color", "PS1=$ ", "HISTFILE=/dev/null", "HOME=" + t.TempDir()},
		Dir: t.TempDir(), RingSize: 1 << 16, Clock: quartz.NewReal(),
	})
	t.Cleanup(m.Close)
	return m
}

func receive(t *testing.T, c net.Conn, buf []byte) *tilderv1.PtyServer {
	t.Helper()
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	msg := &tilderv1.PtyServer{}
	if err := proto.Unmarshal(buf[:n], msg); err != nil {
		t.Fatal(err)
	}
	return msg
}

// A console reconnecting attaches from where its screen stopped and gets the
// rest of the history. It must know which bytes are history: answering the
// colour and cursor queries in them again typed garbage at the prompt (ADR
// 0015).
func TestTheAttachCatchUpIsMarkedAsReplay(t *testing.T) {
	t.Parallel()
	shells := shellManager(t)
	shell, err := shells.Open("restored", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, watcher := shell.Attach(0)
	if err := shell.Input([]byte("echo old-$((20+1))\n")); err != nil {
		t.Fatal(err)
	}
	var history strings.Builder
	for !strings.Contains(history.String(), "old-21") {
		e, ok := <-watcher.Events()
		if !ok {
			t.Fatal("watcher closed")
		}
		history.Write(e.Data)
	}
	shell.Detach(watcher)

	client := serve(t, shells)
	send(t, client, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{
		ShellId: "restored", Since: 1, Cols: 80, Rows: 24, Window: 1 << 20,
	}}})
	buf := make([]byte, 64*1024)
	first := receive(t, client, buf).GetOutput()
	if first == nil || !first.GetReplay() || !strings.Contains(string(first.GetData()), "old-21") {
		t.Fatalf("first frame %v: want the history, marked replay", first)
	}

	send(t, client, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Input{Input: &tilderv1.PtyInput{Data: []byte("echo new-$((1+1))\n")}}})
	var live strings.Builder
	for !strings.Contains(live.String(), "new-2") {
		out := receive(t, client, buf).GetOutput()
		if out == nil {
			continue
		}
		if out.GetReplay() {
			t.Fatalf("live output %q marked replay", out.GetData())
		}
		live.Write(out.GetData())
	}
}

// Closing a tab sends Kill: the shell ends and the client hears its exit
// (ADR 0014), instead of the shell living on with nobody attached.
func TestKillEndsTheShellAndReportsItsExit(t *testing.T) {
	t.Parallel()
	client := serve(t, shellManager(t))
	send(t, client, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{
		ShellId: "doomed", Cols: 80, Rows: 24, Window: 1 << 20,
	}}})
	send(t, client, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Kill{Kill: &tilderv1.Kill{}}})
	buf := make([]byte, 64*1024)
	for receive(t, client, buf).GetExit() == nil {
	}
}

var sttySize = regexp.MustCompile(`size=(\d+ \d+)=`)

// Reopening a shell from another screen (a laptop's tab, then a phone) gives
// it the new screen's size: it kept the size it was started with until the
// next manual resize (abduco resizes on every attach).
func TestAttachingSizesTheShellToTheNewScreen(t *testing.T) {
	t.Parallel()
	shells := shellManager(t)
	if _, err := shells.Open("moved", 80, 24); err != nil {
		t.Fatal(err)
	}
	client := serve(t, shells)
	send(t, client, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{
		ShellId: "moved", Cols: 132, Rows: 40, Window: 1 << 20,
	}}})
	send(t, client, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Input{Input: &tilderv1.PtyInput{Data: []byte("echo size=$(stty size)=\n")}}})
	buf := make([]byte, 64*1024)
	var seen strings.Builder
	var got []string
	for got == nil {
		seen.Write(receive(t, client, buf).GetOutput().GetData())
		got = sttySize.FindStringSubmatch(seen.String())
	}
	if got[1] != "40 132" {
		t.Fatalf("the shell is %s, want 40 132: it kept its old size", got[1])
	}
}

// One shell open on a laptop and a phone (ADR 0033): the phone opening it
// leaves the laptop's size alone; once the phone types, the shell takes the
// phone's size and the laptop is told, so it draws at that size.
func TestTheDeviceThatTypesSizesASharedShell(t *testing.T) {
	t.Parallel()
	shells := shellManager(t)
	sizes := ptychan.NewSizes()
	attach := func(cols, rows uint32) net.Conn {
		c := serveSized(t, shells, nil, nil, sizes)
		send(t, c, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{
			ShellId: "shared", Cols: cols, Rows: rows, Window: 1 << 20,
		}}})
		return c
	}
	buf := make([]byte, 64*1024)
	// The size each side hears, skipping output.
	sizeOf := func(c net.Conn) *tilderv1.Resize {
		for {
			if s := receive(t, c, buf).GetSize(); s != nil {
				return s
			}
		}
	}
	laptop := attach(132, 40)
	if s := sizeOf(laptop); s.GetCols() != 132 || s.GetRows() != 40 {
		t.Fatalf("the laptop heard %v, want 132x40", s)
	}
	phone := attach(45, 30)
	if s := sizeOf(phone); s.GetCols() != 132 {
		t.Fatalf("opening the tab on the phone resized the shell: the phone heard %v", s)
	}
	send(t, phone, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Input{Input: &tilderv1.PtyInput{Data: []byte("echo size=$(stty size)=\n")}}})
	var seen strings.Builder
	var got []string
	for got == nil {
		seen.Write(receive(t, phone, buf).GetOutput().GetData())
		got = sttySize.FindStringSubmatch(seen.String())
	}
	if got[1] != "30 45" {
		t.Fatalf("after the phone typed the shell is %s, want 30 45", got[1])
	}
	if s := sizeOf(laptop); s.GetCols() != 45 || s.GetRows() != 30 {
		t.Fatalf("the laptop heard %v, want 45x30", s)
	}
}

// A console opening a tab afresh gets the screen, not the history (ADR
// 0017): the first part says the size it was drawn at, the last says so, and
// live output goes on from the screen's offset.
func TestAFreshAttachGetsTheScreenThenLiveOutput(t *testing.T) {
	t.Parallel()
	shells := shellManager(t)
	shell, err := shells.Open("drawn", 50, 10)
	if err != nil {
		t.Fatal(err)
	}
	_, watcher := shell.Attach(0)
	if err := shell.Input([]byte("echo drawn-$((20+1))\n")); err != nil {
		t.Fatal(err)
	}
	var history strings.Builder
	for !strings.Contains(history.String(), "drawn-21") {
		e, ok := <-watcher.Events()
		if !ok {
			t.Fatal("watcher closed")
		}
		history.Write(e.Data)
	}
	shell.Detach(watcher)

	client := serve(t, shells)
	send(t, client, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{
		ShellId: "drawn", Cols: 90, Rows: 30, Window: 1 << 20,
	}}})
	buf := make([]byte, 64*1024)
	first := receive(t, client, buf).GetScreen()
	if first == nil || first.GetCols() != 50 || first.GetRows() != 10 {
		t.Fatalf("first frame %v: want the screen, at the size it was drawn (50×10)", first)
	}
	screen := string(first.GetData())
	for last := first.GetLast(); !last; {
		part := receive(t, client, buf).GetScreen()
		screen += string(part.GetData())
		last = part.GetLast()
	}
	if !strings.Contains(screen, "drawn-21") {
		t.Fatalf("the screen lacks the output: %q", screen)
	}

	send(t, client, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Input{Input: &tilderv1.PtyInput{Data: []byte("echo live-$((1+1))\n")}}})
	var live strings.Builder
	for !strings.Contains(live.String(), "live-2") {
		out := receive(t, client, buf).GetOutput()
		if out == nil {
			continue
		}
		if out.GetSeq() < first.GetSeq() || out.GetReplay() {
			t.Fatalf("live output at %d (replay %v); the screen stands for everything before %d", out.GetSeq(), out.GetReplay(), first.GetSeq())
		}
		live.Write(out.GetData())
	}
}

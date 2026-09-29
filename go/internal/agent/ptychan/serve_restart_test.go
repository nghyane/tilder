package ptychan_test

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// A tab that had 5 MB of a shell reconnects after the machine restarted: the
// shell under its id is a new one, counting from 0. The tab must be told to
// start again (a screen), not sent bytes it takes for ones it already has
// and drops: it stayed blank, never acked, and output stopped for good.
func TestATabReturningToANewShellStartsAgain(t *testing.T) {
	t.Parallel()
	client := serve(t, shellManager(t))
	send(t, client, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{
		ShellId: "after-reboot", Since: 5_000_000, Cols: 80, Rows: 24, Window: 1 << 20,
	}}})
	buf := make([]byte, 64*1024)
	first := receive(t, client, buf)
	screen := first.GetScreen()
	if screen == nil {
		t.Fatalf("first frame %v: want a screen, so the tab starts again", first)
	}
	for last := screen.GetLast(); !last; {
		last = receive(t, client, buf).GetScreen().GetLast()
	}
	send(t, client, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Input{Input: &tilderv1.PtyInput{Data: []byte("echo back-$((1+1))\n")}}})
	var live strings.Builder
	for !strings.Contains(live.String(), "back-2") {
		out := receive(t, client, buf).GetOutput()
		if out == nil {
			continue
		}
		if out.GetSeq() < screen.GetSeq() {
			t.Fatalf("output at %d, before the screen at %d", out.GetSeq(), screen.GetSeq())
		}
		live.Write(out.GetData())
	}
}

// A tab away while more than the ring scrolled by gets the screen too: the
// bytes kept start at a cut that can fall inside an escape sequence.
func TestATabThatMissedMoreThanTheRingGetsTheScreen(t *testing.T) {
	t.Parallel()
	shells := shellManager(t) // a 64 KiB ring
	shell, err := shells.Open("scrolled", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_, watcher := shell.Attach(0)
	if err := shell.Input([]byte("yes tilder | head -c 200000; echo done-$((40+2))\n")); err != nil {
		t.Fatal(err)
	}
	var tail strings.Builder
	for !strings.Contains(tail.String(), "done-42") {
		e, ok := <-watcher.Events()
		if !ok {
			t.Fatal("watcher closed")
		}
		tail.Write(e.Data)
		if tail.Len() > 4096 {
			s := tail.String()
			tail.Reset()
			tail.WriteString(s[len(s)-64:])
		}
	}
	shell.Detach(watcher)

	client := serve(t, shells)
	send(t, client, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{
		ShellId: "scrolled", Since: 1, Cols: 80, Rows: 24, Window: 1 << 20,
	}}})
	buf := make([]byte, 64*1024)
	if first := receive(t, client, buf); first.GetScreen() == nil {
		t.Fatalf("first frame is a %T: want the screen, not bytes from the ring's cut", first.GetMsg())
	}
}

// Kill reaches the shell while a paste waits for a program that does not
// read its input: closing the tab must end the shell (ADR 0014), and the
// acks must go on, not queue behind keystrokes nobody reads.
func TestKillIsHeardWhileAPasteIsStuck(t *testing.T) {
	t.Parallel()
	client := serve(t, shellManager(t))
	send(t, client, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{
		ShellId: "stuck", Cols: 80, Rows: 24, Window: 1 << 20,
	}}})
	send(t, client, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Input{Input: &tilderv1.PtyInput{
		Data: []byte("stty raw -echo; echo read-$((40+2)); sleep 60\n"),
	}}})
	buf := make([]byte, 64*1024)
	var out strings.Builder
	for !strings.Contains(out.String(), "read-42") {
		out.Write(receive(t, client, buf).GetOutput().GetData())
	}
	// A megabyte the sleeping shell never reads, in 16 KiB messages as the console sends.
	chunk := &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Input{Input: &tilderv1.PtyInput{Data: make([]byte, 16*1024)}}}
	frame, err := proto.Marshal(chunk)
	if err != nil {
		t.Fatal(err)
	}
	for range 64 {
		if _, err := client.Write(frame); err != nil {
			t.Fatal(err)
		}
	}
	send(t, client, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Kill{Kill: &tilderv1.Kill{}}})
	for receive(t, client, buf).GetExit() == nil {
	}
}

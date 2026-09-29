package rtc_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/coder/quartz"
	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"
	"go.uber.org/goleak"
	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/ptychan"
	"github.com/nghyane/tilder/go/internal/agent/rtc"
	"github.com/nghyane/tilder/go/internal/holder"
	"github.com/nghyane/tilder/go/internal/testutil"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// agent is the machine side: an endpoint whose `pty` channels reach real shells.
func agent(t *testing.T) *rtc.Endpoint {
	t.Helper()
	shells := holder.NewManager(holder.Config{
		Shell: "/bin/sh", Env: []string{"TERM=xterm-256color", "PS1=$ ", "LANG=en_US.UTF-8", "HISTFILE=/dev/null", "HOME=" + t.TempDir()},
		Dir: t.TempDir(), RingSize: 1 << 20, Clock: quartz.NewReal(),
	})
	t.Cleanup(shells.Close)
	e := rtc.New(rtc.Options{IncludeLoopback: true}, func(ctx context.Context, _ rtc.Peer, label string, ch io.ReadWriteCloser) {
		if label == "pty" {
			_ = ptychan.Serve(ctx, ch, shells, nil, nil, nil)
			return
		}
		_ = ch.Close()
	})
	t.Cleanup(e.Close)
	return e
}

// browser opens a `pty` channel to the agent the way the console does.
func browser(t *testing.T, agent *rtc.Endpoint) io.ReadWriteCloser {
	t.Helper()
	_, ch := browserPeer(t, agent)
	return ch
}

// channel opens another `pty` channel on a connection that is up, as the
// console does for a machine's second terminal (ADR 0018).
func channel(t *testing.T, pc *webrtc.PeerConnection) io.ReadWriteCloser {
	t.Helper()
	dc, err := pc.CreateDataChannel("pty", nil)
	if err != nil {
		t.Fatal(err)
	}
	opened := make(chan io.ReadWriteCloser, 1)
	dc.OnOpen(func() {
		raw, derr := dc.DetachWithDeadline()
		if derr == nil {
			opened <- raw
		}
	})
	select {
	case ch := <-opened:
		return ch
	case <-time.After(testutil.WaitShort): //nolint:forbidigo // a real network handshake
		t.Fatal("the second pty channel did not open")
		return nil
	}
}

func browserPeer(t *testing.T, agent *rtc.Endpoint) (*webrtc.PeerConnection, io.ReadWriteCloser) {
	t.Helper()
	var se webrtc.SettingEngine
	se.DetachDataChannels()
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	se.SetIncludeLoopbackCandidate(true)
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(se)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	dc, err := pc.CreateDataChannel("pty", nil)
	if err != nil {
		t.Fatal(err)
	}
	opened := make(chan io.ReadWriteCloser, 1)
	dc.OnOpen(func() {
		raw, derr := dc.DetachWithDeadline()
		if derr == nil {
			opened <- raw
		}
	})
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if lerr := pc.SetLocalDescription(offer); lerr != nil {
		t.Fatal(lerr)
	}
	<-gathered
	answer, err := agent.Answer(testutil.Context(t, testutil.WaitShort), pc.LocalDescription().SDP, rtc.Peer{Name: "test-device"})
	if err != nil {
		t.Fatal(err)
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); err != nil {
		t.Fatal(err)
	}
	select {
	case ch := <-opened:
		return pc, ch
	case <-time.After(testutil.WaitShort): //nolint:forbidigo // a real network handshake
		t.Fatal("the pty channel did not open")
		return nil, nil
	}
}

func send(t *testing.T, ch io.Writer, msg *tilderv1.PtyClient) {
	t.Helper()
	frame, err := proto.Marshal(msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ch.Write(frame); err != nil {
		t.Fatal(err)
	}
}

// readUntil reads Output frames, acking each, until the text contains want;
// it returns the text and the offset after the last byte.
func readUntil(t *testing.T, ch io.ReadWriter, want string) (string, uint64) {
	t.Helper()
	var seen strings.Builder
	var end uint64
	buf := make([]byte, 64*1024)
	deadline := time.Now().Add(testutil.WaitShort) //nolint:forbidigo // a real shell over a real network
	for !strings.Contains(seen.String(), want) {
		if time.Now().After(deadline) { //nolint:forbidigo // a real shell over a real network
			t.Fatalf("no %q; saw %q", want, seen.String())
		}
		n, err := ch.Read(buf)
		if err != nil {
			t.Fatalf("read: %v (saw %q)", err, seen.String())
		}
		msg := &tilderv1.PtyServer{}
		if err := proto.Unmarshal(buf[:n], msg); err != nil {
			t.Fatal(err)
		}
		if out := msg.GetOutput(); out != nil {
			seen.Write(out.GetData())
			end = out.GetSeq() + uint64(len(out.GetData()))
			send(t, ch, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Ack{Ack: &tilderv1.Ack{Seq: end}}})
		}
	}
	return seen.String(), end
}

func TestABrowserRunsACommandAndResumesWithoutRepeats(t *testing.T) {
	t.Parallel()
	machine := agent(t)
	first := browser(t, machine)
	send(t, first, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{
		ShellId: "s1", Since: 0, Cols: 80, Rows: 24, Window: 64 * 1024,
	}}})
	send(t, first, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Input{Input: &tilderv1.PtyInput{Data: []byte("echo chữ-$((20+22))\n")}}})
	_, end := readUntil(t, first, "chữ-42")
	_ = first.Close()

	// A second connection resumes at the offset the screen reached: the same
	// shell, and nothing already shown comes again.
	second := browser(t, machine)
	send(t, second, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{
		ShellId: "s1", Since: end, Cols: 80, Rows: 24, Window: 64 * 1024,
	}}})
	send(t, second, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Input{Input: &tilderv1.PtyInput{Data: []byte("echo again-$((1+1))\n")}}})
	text, _ := readUntil(t, second, "again-2")
	if strings.Contains(text, "chữ-42") {
		t.Fatalf("the resumed stream replayed output already on screen: %q", text)
	}
}

func TestMain(m *testing.M) { goleak.VerifyTestMain(m, testutil.GoleakOptions...) }

// Without acks the agent stops at the window; with them it goes on, and not
// a byte is lost on the way.
func TestOutputStopsAtTheWindowAndResumesOnAck(t *testing.T) {
	t.Parallel()
	ch := browser(t, agent(t))
	const window = 16 * 1024
	send(t, ch, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{
		ShellId: "flood", Cols: 80, Rows: 24, Window: window,
	}}})
	// 200 000 bytes of output, then a marker.
	send(t, ch, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Input{Input: &tilderv1.PtyInput{
		Data: []byte("head -c 200000 /dev/zero | tr '\\0' x; echo; echo done-$((2*21))\n"),
	}}})

	deadlined, ok := ch.(interface{ SetReadDeadline(time.Time) error })
	if !ok {
		t.Fatal("the channel has no read deadline")
	}
	var unacked uint64
	buf := make([]byte, 64*1024)
	for {
		_ = deadlined.SetReadDeadline(time.Now().Add(500 * time.Millisecond)) //nolint:forbidigo // a real channel
		n, err := ch.Read(buf)
		if err != nil {
			break // stalled: the agent is waiting for credit
		}
		msg := &tilderv1.PtyServer{}
		if err := proto.Unmarshal(buf[:n], msg); err != nil {
			t.Fatal(err)
		}
		unacked += uint64(len(msg.GetOutput().GetData()))
	}
	if unacked == 0 || unacked > window {
		t.Fatalf("received %d bytes without acking; the window is %d", unacked, window)
	}
	_ = deadlined.SetReadDeadline(time.Time{})

	// Acking what arrived lets the rest through, to the marker.
	send(t, ch, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Ack{Ack: &tilderv1.Ack{Seq: unacked}}})
	text, end := readUntil(t, ch, "done-42")
	if total := unacked + uint64(len(text)); total != end {
		t.Fatalf("bytes lost: received %d, stream reached %d", total, end)
	}
}

// A machine's terminals share one connection (ADR 0018): a second channel
// opens on it without another handshake, and a terminal flooding output that
// its client does not read holds up only itself (its window), never the
// other.
func TestTerminalsShareOneConnectionWithoutHoldingEachOtherUp(t *testing.T) {
	t.Parallel()
	a := agent(t)
	pc, flood := browserPeer(t, a)
	send(t, flood, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{ShellId: "flood", Cols: 80, Rows: 24}}})
	send(t, flood, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Input{Input: &tilderv1.PtyInput{Data: []byte("yes flood\n")}}})

	other := channel(t, pc)
	send(t, other, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{ShellId: "other", Cols: 80, Rows: 24, Window: 1 << 20}}})
	send(t, other, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Input{Input: &tilderv1.PtyInput{Data: []byte("echo other-$((6*7))\n")}}})
	readUntil(t, other, "other-42")
	send(t, flood, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Kill{Kill: &tilderv1.Kill{}}})
}

// Cutting a device off ends its live channels, not just its next offer
// (Tailscale and Nebula learned that filtering new connections is not enough).
func TestClosingAPeerEndsItsLiveChannels(t *testing.T) {
	t.Parallel()
	a := agent(t)
	_, ch := browserPeer(t, a)
	send(t, ch, &tilderv1.PtyClient{Msg: &tilderv1.PtyClient_Attach{Attach: &tilderv1.Attach{ShellId: "cut", Cols: 80, Rows: 24}}})
	a.ClosePeer("test-device")
	buf := make([]byte, 1<<16)
	deadline := time.Now().Add(testutil.WaitShort) //nolint:forbidigo // a real connection closing
	for {
		if _, err := ch.Read(buf); err != nil {
			return // the channel ended
		}
		if time.Now().After(deadline) { //nolint:forbidigo // a real connection closing
			t.Fatal("the removed device's channel stayed open")
		}
	}
}

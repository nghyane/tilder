package rtc_test

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/coder/quartz"
	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"

	"github.com/nghyane/tilder/go/internal/agent/rtc"
	"github.com/nghyane/tilder/go/internal/testutil"
)

// silentRelay accepts TCP and never says a word: TURN over TCP behind a
// firewall that lets the connection through and nothing after, or a relay
// that is down behind a load balancer.
func silentRelay(t *testing.T) string {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan net.Conn, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			held <- c
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		close(held)
		for c := range held {
			_ = c.Close()
		}
	})
	return l.Addr().String()
}

func hostOffer(t *testing.T) string {
	t.Helper()
	var se webrtc.SettingEngine
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)
	se.SetIncludeLoopbackCandidate(true)
	pc, err := webrtc.NewAPI(webrtc.WithSettingEngine(se)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	if _, cerr := pc.CreateDataChannel("pty", nil); cerr != nil {
		t.Fatal(cerr)
	}
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if lerr := pc.SetLocalDescription(offer); lerr != nil {
		t.Fatal(lerr)
	}
	<-gathered
	return pc.LocalDescription().SDP
}

// ADR 0046: a relay that never answers holds an answer no longer than the
// bound the console keeps too, and the answer still carries what was
// gathered (the host candidates) for a direct try.
func TestASilentRelayHoldsTheAnswerOnlyToTheBound(t *testing.T) {
	t.Parallel()
	clk := quartz.NewMock(t)
	bound := clk.Trap().NewTimer("gather")
	defer bound.Close()
	agent := rtc.New(rtc.Options{
		IncludeLoopback: true, Clock: clk,
		ICEServers: []webrtc.ICEServer{{
			URLs: []string{"turn:" + silentRelay(t) + "?transport=tcp"}, Username: "u", Credential: "p",
		}},
	}, func(_ context.Context, _ rtc.Peer, _ string, ch io.ReadWriteCloser) { _ = ch.Close() })
	t.Cleanup(agent.Close)

	ctx := testutil.Context(t, testutil.WaitShort)
	offer := hostOffer(t)
	type result struct {
		sdp string
		err error
	}
	answered := make(chan result, 1)
	go func() {
		sdp, err := agent.Answer(ctx, offer, rtc.Peer{Name: "device"})
		answered <- result{sdp, err}
	}()

	bound.MustWait(ctx).MustRelease(ctx)
	select {
	case <-answered:
		t.Fatal("answered before the bound: the silent relay was never waited for, so this proves nothing")
	case <-time.After(200 * time.Millisecond): //nolint:forbidigo // the relay stays silent in real time
	}
	clk.Advance(5 * time.Second).MustWait(ctx)
	select {
	case r := <-answered:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if !strings.Contains(r.sdp, "typ host") {
			t.Fatalf("the answer lost what was gathered: %q", r.sdp)
		}
	case <-time.After(2 * time.Second): //nolint:forbidigo // pion gives up on the silent relay itself after ~7 s
		t.Fatal("the answer waited on the silent relay past the bound")
	}
}

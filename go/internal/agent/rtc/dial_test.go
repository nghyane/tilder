package rtc_test

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/nghyane/tilder/go/internal/agent/rtc"
	"github.com/nghyane/tilder/go/internal/identity"
	"github.com/nghyane/tilder/go/internal/testutil"
)

type served struct {
	peer  rtc.Peer
	label string
}

// echoMachine answers machine offers: it reports who each channel serves and
// echoes it.
func echoMachine(t *testing.T) (*rtc.Endpoint, chan served) {
	t.Helper()
	got := make(chan served, 4)
	e := rtc.New(rtc.Options{IncludeLoopback: true}, func(_ context.Context, peer rtc.Peer, label string, ch io.ReadWriteCloser) {
		got <- served{peer, label}
		_, _ = io.Copy(ch, ch)
		_ = ch.Close()
	})
	t.Cleanup(e.Close)
	return e, got
}

func TestAMachineDialsAnotherAndTheAnswerKnowsItsCopy(t *testing.T) {
	t.Parallel()
	src, got := echoMachine(t)
	dst := rtc.New(rtc.Options{IncludeLoopback: true}, func(_ context.Context, _ rtc.Peer, _ string, ch io.ReadWriteCloser) {
		_ = ch.Close()
	})
	t.Cleanup(dst.Close)
	grant := &identity.Transfer{Src: "machine-a", Dst: "machine-b", SrcPath: []byte("proj")}
	peer := rtc.Peer{Name: "device-1", Transfer: grant}

	ctx := testutil.Context(t, testutil.WaitShort)
	conn, err := dst.Dial(ctx, peer, "xfer", func(ctx context.Context, offer string) (string, error) {
		return src.Answer(ctx, offer, peer)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	s := <-got
	if s.label != "xfer" || s.peer.Transfer != grant {
		t.Fatalf("served %q for %+v, want xfer for the grant", s.label, s.peer)
	}
	if conn.Relayed() {
		t.Fatal("a loopback connection reported as relayed")
	}
}

func TestRemovingTheGrantsDeviceEndsTheCopysConnection(t *testing.T) {
	t.Parallel()
	src, _ := echoMachine(t)
	dst := rtc.New(rtc.Options{IncludeLoopback: true}, func(_ context.Context, _ rtc.Peer, _ string, ch io.ReadWriteCloser) {
		_ = ch.Close()
	})
	t.Cleanup(dst.Close)
	peer := rtc.Peer{Name: "device-1", Transfer: &identity.Transfer{}}
	conn, err := dst.Dial(testutil.Context(t, testutil.WaitShort), peer, "xfer", func(ctx context.Context, offer string) (string, error) {
		return src.Answer(ctx, offer, peer)
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	src.ClosePeer("device-1")
	done := make(chan error, 1)
	go func() {
		_, rerr := conn.Read(make([]byte, 1))
		done <- rerr
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("read succeeded after the source cut the connection")
		}
	case <-time.After(testutil.WaitMedium): //nolint:forbidigo // a real network teardown
		t.Fatal("the connection outlived its device's removal")
	}
}

func TestADialThatGetsNoAnswerGivesUpAndLeavesNothing(t *testing.T) {
	t.Parallel()
	dst := rtc.New(rtc.Options{IncludeLoopback: true}, func(_ context.Context, _ rtc.Peer, _ string, ch io.ReadWriteCloser) {
		_ = ch.Close()
	})
	t.Cleanup(dst.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := dst.Dial(ctx, rtc.Peer{Name: "d"}, "xfer", func(ctx context.Context, _ string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	})
	if err == nil {
		t.Fatal("dial without an answer succeeded")
	}
}

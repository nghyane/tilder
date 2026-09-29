package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/coder/quartz"
	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/files"
	"github.com/nghyane/tilder/go/internal/agent/rtc"
	"github.com/nghyane/tilder/go/internal/agent/xferchan"
	"github.com/nghyane/tilder/go/internal/identity"
	"github.com/nghyane/tilder/go/internal/testutil"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// source is a machine that serves one copy, as serve's handler does; with
// lan false it is an agent from before, which closes `xfer-lan`.
func source(t *testing.T, lan bool) (*rtc.Endpoint, rtc.Peer) {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "proj"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "proj", "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	tree := files.New(home, filepath.Join(home, ".tilder"), quartz.NewReal())
	e := rtc.New(rtc.Options{LoopbackOnly: true}, func(ctx context.Context, peer rtc.Peer, label string, ch io.ReadWriteCloser) {
		switch channelFor(peer, label) {
		case "xfer":
			_ = xferchan.Serve(ctx, ch, tree, *peer.Transfer)
		case "xfer-lan":
			if lan {
				serveLAN(ctx, peer, ch, tree)
				return
			}
			_ = ch.Close()
		default:
			_ = ch.Close()
		}
	})
	t.Cleanup(e.Close)
	return e, rtc.Peer{Name: "device-1", Transfer: &identity.Transfer{SrcPath: []byte("proj")}}
}

// pull dials the source as dialSource does and asks for the manifest.
func pull(t *testing.T, src *rtc.Endpoint, peer rtc.Peer) (io.ReadWriteCloser, *tilderv1.XferServer) {
	t.Helper()
	dst := rtc.New(rtc.Options{LoopbackOnly: true}, func(_ context.Context, _ rtc.Peer, _ string, ch io.ReadWriteCloser) {
		_ = ch.Close()
	})
	t.Cleanup(dst.Close)
	ctx := testutil.Context(t, testutil.WaitShort)
	conn, err := dst.Dial(ctx, peer, "xfer", func(ctx context.Context, offer string) (string, error) {
		return src.Answer(ctx, offer, peer)
	})
	if err != nil {
		t.Fatal(err)
	}
	c := overLAN(ctx, quartz.NewReal(), slog.New(slog.DiscardHandler), conn)
	t.Cleanup(func() { _ = c.Close() })
	ask, _ := proto.Marshal(&tilderv1.XferClient{Msg: &tilderv1.XferClient_Manifest{Manifest: &tilderv1.XferManifestRequest{}}})
	if _, werr := c.Write(ask); werr != nil {
		t.Fatal(werr)
	}
	buf := make([]byte, 64*1024)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	msg := &tilderv1.XferServer{}
	if uerr := proto.Unmarshal(buf[:n], msg); uerr != nil {
		t.Fatal(uerr)
	}
	return c, msg
}

// ADR 0039: two machines on one LAN copy over TCP, the same `xfer` messages.
func TestACopyInsideOneLANGoesOverTCP(t *testing.T) {
	t.Parallel()
	src, peer := source(t, true)
	c, msg := pull(t, src, peer)
	if _, ok := c.(*lanConn); !ok {
		t.Fatalf("the copy runs on %T, want TCP", c)
	}
	if len(msg.GetManifest().GetEntries()) == 0 {
		t.Fatalf("got %v, want the manifest", msg)
	}
}

// An agent from before closes `xfer-lan`: the copy goes on over the data
// channel, as it did.
func TestACopyFromAnOlderAgentStaysOnTheDataChannel(t *testing.T) {
	t.Parallel()
	src, peer := source(t, false)
	c, msg := pull(t, src, peer)
	if _, ok := c.(*rtc.Conn); !ok {
		t.Fatalf("the copy runs on %T, want the data channel", c)
	}
	if len(msg.GetManifest().GetEntries()) == 0 {
		t.Fatalf("got %v, want the manifest", msg)
	}
}

// Removing the device that signed the grant cuts the copy's WebRTC
// connection, and the TCP copy with it.
func TestRemovingTheGrantsDeviceEndsTheLANCopy(t *testing.T) {
	t.Parallel()
	src, peer := source(t, true)
	c, _ := pull(t, src, peer)
	src.ClosePeer("device-1")
	ctx := testutil.Context(t, testutil.WaitMedium)
	read := make(chan error, 1)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			if _, err := c.Read(buf); err != nil {
				read <- err
				return
			}
		}
	}()
	select {
	case <-read:
	case <-ctx.Done():
		t.Fatal("the LAN copy outlived its device's removal")
	}
}

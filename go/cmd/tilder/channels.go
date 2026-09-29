package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/pion/webrtc/v4"

	"github.com/nghyane/tilder/go/internal/agent/files"
	"github.com/nghyane/tilder/go/internal/agent/lanxfer"
	"github.com/nghyane/tilder/go/internal/agent/link"
	"github.com/nghyane/tilder/go/internal/agent/rtc"
	"github.com/nghyane/tilder/go/internal/agent/transfer"
	"github.com/nghyane/tilder/go/internal/agent/xferchan"
	"github.com/nghyane/tilder/go/internal/clock"
	"github.com/nghyane/tilder/go/internal/identity"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// channelFor says which service a channel gets: a device, the one it names;
// another machine, only the copy its grant names (ADR 0035), never a shell or
// the owner's other files. Anything else gets none.
func channelFor(peer rtc.Peer, label string) string {
	if peer.Transfer != nil {
		switch label {
		case "xfer", "xfer-lan":
			return label
		default:
			return ""
		}
	}
	switch label {
	case "pty", "fs", "xfer-ctl":
		return label
	default:
		return ""
	}
}

func iceServers() []webrtc.ICEServer {
	urls := strings.Split(envOr("TILDER_STUN", "stun:stun.l.google.com:19302"), ",")
	return []webrtc.ICEServer{{URLs: urls}}
}

// dialSource reaches a copy's source machine: this machine offers, through
// the rendezvous with the grant, and gets the `xfer` channel (ADR 0035).
func dialSource(endpoint *rtc.Endpoint, l *link.Link) func(*tilderv1.TransferGrant, identity.Transfer) transfer.Connect {
	return func(g *tilderv1.TransferGrant, t identity.Transfer) transfer.Connect {
		return func(ctx context.Context) (transfer.Conn, error) {
			peer := rtc.Peer{Name: link.PeerName(t.Device), Transfer: &t, ICEServers: l.ICEServers(ctx)}
			conn, err := endpoint.Dial(ctx, peer, "xfer", l.Signal(g, t))
			if err != nil {
				return nil, err
			}
			return overLAN(ctx, l.Clock, l.Log, conn), nil
		}
	}
}

// lanOpenWait bounds opening `xfer-lan`, which an agent from before closes.
const lanOpenWait = 3 * time.Second

// overLAN moves the copy's messages to TCP when the connection runs inside
// one LAN (ADR 0039). Anything short of that (another network, an agent
// from before, a firewall) keeps them on the data channel.
func overLAN(ctx context.Context, clk clock.Clock, log *slog.Logger, conn *rtc.Conn) transfer.Conn {
	_, remote, ok := conn.LAN()
	if !ok {
		return conn
	}
	opening, cancel := context.WithCancel(ctx)
	defer cancel()
	expired := clk.AfterFunc(lanOpenWait, cancel)
	defer expired.Stop()
	ch, err := conn.Open(opening, "xfer-lan")
	if err == nil {
		var tcp io.ReadWriteCloser
		if tcp, err = lanxfer.Dial(ctx, clk, ch, remote); err == nil {
			return &lanConn{ReadWriteCloser: tcp, rtc: conn}
		}
	}
	log.Info("copy stays on the data channel", "error", err)
	return conn
}

// lanConn is a copy over TCP in one LAN, with the connection that opened it.
type lanConn struct {
	io.ReadWriteCloser
	rtc *rtc.Conn
}

func (*lanConn) Relayed() bool { return false }

func (c *lanConn) Close() error {
	err := c.ReadWriteCloser.Close()
	_ = c.rtc.Close()
	return err
}

// serveLAN answers a destination's `xfer-lan` (ADR 0039): the copy its grant
// names, over TCP, when the connection runs inside one LAN; otherwise the
// channel is closed and the copy stays on `xfer`.
func serveLAN(ctx context.Context, peer rtc.Peer, ch io.ReadWriteCloser, tree *files.Tree) {
	local, remote, ok := peer.LAN()
	if !ok {
		_ = ch.Close()
		return
	}
	grant := *peer.Transfer
	_ = lanxfer.Offer(ctx, clock.Real(), ch, local, remote, func(conn io.ReadWriteCloser) {
		_ = xferchan.Serve(ctx, conn, tree, grant)
	})
}

// verifyPull is link.VerifyPull for the copies: a grant the link cannot
// judge yet (ADR 0040) waits rather than being thrown away.
func verifyPull(l *link.Link) func(*tilderv1.TransferGrant) (identity.Transfer, error) {
	return func(g *tilderv1.TransferGrant) (identity.Transfer, error) {
		t, err := l.VerifyPull(g)
		if errors.Is(err, link.ErrStale) {
			return t, fmt.Errorf("%w: %w", transfer.ErrNotYet, err)
		}
		return t, err
	}
}

// startCopies resumes the copies a previous run left, after the stored list
// of removed devices is read (ADR 0040): a removed device's copy is ended,
// one the list cannot judge yet waits for a newer list.
func startCopies(ctx context.Context, l *link.Link, copies *transfer.Manager, connect func(*tilderv1.TransferGrant, identity.Transfer) transfer.Connect) {
	l.LoadRevocations()
	copies.Verify, copies.Connect = verifyPull(l), connect
	copies.Start(ctx)
}

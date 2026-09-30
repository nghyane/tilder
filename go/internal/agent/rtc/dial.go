package rtc

import (
	"context"
	"io"
	"net/netip"

	"github.com/pion/webrtc/v4"

	"github.com/nghyane/tilder/go/internal/clock"
)

// Conn is a connection this endpoint offered, with the one channel it
// opened. Closing it ends the connection.
type Conn struct {
	io.ReadWriteCloser
	pc *webrtc.PeerConnection
	e  *Endpoint
}

// Close ends the channel and its connection.
func (c *Conn) Close() error {
	err := c.ReadWriteCloser.Close()
	c.e.untrack(c.pc)
	return err
}

// Relayed reports whether the connection goes through a TURN relay.
func (c *Conn) Relayed() bool {
	sctp := c.pc.SCTP()
	if sctp == nil {
		return false
	}
	pair, err := sctp.Transport().ICETransport().GetSelectedCandidatePair()
	if err != nil || pair == nil {
		return false
	}
	return pair.Local.Typ == webrtc.ICECandidateTypeRelay || pair.Remote.Typ == webrtc.ICECandidateTypeRelay
}

// LAN reports the two addresses the connection runs between when it runs
// host to host inside one LAN (ADR 0039).
func (c *Conn) LAN() (local, remote netip.Addr, ok bool) { return lanPath(c.pc) }

// Open opens another channel on the connection, for the other side to serve.
func (c *Conn) Open(ctx context.Context, label string) (io.ReadWriteCloser, error) {
	dc, err := c.pc.CreateDataChannel(label, nil)
	if err != nil {
		return nil, err
	}
	opened := make(chan struct{})
	dc.OnOpen(func() { close(opened) })
	select {
	case <-opened:
	case <-ctx.Done():
		_ = dc.Close()
		return nil, ctx.Err()
	}
	return dc.Detach()
}

// lanPath is the selected pair's two addresses when they share a LAN: host
// candidates (or the far one learned from its checks) at private IPv4
// addresses, at IPv6 addresses in one /64 or both ULA, or loopback in tests.
// A relay, a reflexive address, or two addresses across the internet is
// not: that copy stays on the data channel. Link-local is not either: TCP
// to it needs the interface's zone, which ICE does not carry.
func lanPath(pc *webrtc.PeerConnection) (local, remote netip.Addr, ok bool) {
	if pc == nil || pc.SCTP() == nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	pair, err := pc.SCTP().Transport().ICETransport().GetSelectedCandidatePair()
	if err != nil || pair == nil || pair.Local.Typ != webrtc.ICECandidateTypeHost ||
		(pair.Remote.Typ != webrtc.ICECandidateTypeHost && pair.Remote.Typ != webrtc.ICECandidateTypePrflx) {
		return netip.Addr{}, netip.Addr{}, false
	}
	local, lerr := netip.ParseAddr(pair.Local.Address)
	remote, rerr := netip.ParseAddr(pair.Remote.Address)
	if lerr != nil || rerr != nil || !sameLAN(local.Unmap(), remote.Unmap()) {
		return netip.Addr{}, netip.Addr{}, false
	}
	return local, remote, true
}

func sameLAN(a, b netip.Addr) bool {
	switch {
	case a.Is4() != b.Is4() || a.IsLinkLocalUnicast() || b.IsLinkLocalUnicast():
		return false
	case a.IsLoopback() && b.IsLoopback():
		return true
	case a.Is4():
		return a.IsPrivate() && b.IsPrivate()
	case a.IsPrivate() && b.IsPrivate():
		return true
	default:
		pa, errA := a.Prefix(64)
		pb, errB := b.Prefix(64)
		return errA == nil && errB == nil && a.IsGlobalUnicast() && pa == pb
	}
}

// Signal carries a complete offer to the other side and returns its answer,
// which the caller has verified came from the machine it meant to reach.
type Signal func(ctx context.Context, offerSDP string) (answerSDP string, err error)

// Dial offers a connection to another machine (ADR 0035: the destination of
// a copy offers, it is the one pulling) and opens one channel on it. Channels
// the other side opens are not served. ctx bounds the whole setup.
func (e *Endpoint) Dial(ctx context.Context, peer Peer, label string, signal Signal) (*Conn, error) {
	pc, err := e.newPeer(peer)
	if err != nil {
		return nil, err
	}
	ch, err := dial(ctx, e.clock, pc, label, signal)
	if err != nil {
		e.untrack(pc)
		return nil, err
	}
	return &Conn{ReadWriteCloser: ch, pc: pc, e: e}, nil
}

func dial(ctx context.Context, clk clock.Clock, pc *webrtc.PeerConnection, label string, signal Signal) (io.ReadWriteCloser, error) {
	dc, err := pc.CreateDataChannel(label, nil)
	if err != nil {
		return nil, err
	}
	opened := make(chan struct{})
	dc.OnOpen(func() { close(opened) })
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return nil, err
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if lerr := pc.SetLocalDescription(offer); lerr != nil {
		return nil, lerr
	}
	if gerr := gather(ctx, clk, gathered); gerr != nil {
		return nil, gerr
	}
	answer, err := signal(ctx, pc.LocalDescription().SDP)
	if err != nil {
		return nil, err
	}
	if rerr := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); rerr != nil {
		return nil, rerr
	}
	select {
	case <-opened:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return dc.Detach()
}

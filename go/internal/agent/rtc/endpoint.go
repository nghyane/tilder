// Package rtc is the agent's WebRTC endpoint (ADR 0002): Pion, full ICE,
// DataChannels only. It answers offers that the caller has already verified,
// and hands each opened channel to a handler by label.
package rtc

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/webrtc/v4"

	"github.com/nghyane/tilder/go/internal/identity"
)

// Options configure the endpoint; cmd/ fills them.
type Options struct {
	// ICEServers are STUN/TURN URLs (with credentials for TURN when needed).
	ICEServers []webrtc.ICEServer
	// IncludeLoopback offers 127.0.0.1 candidates: tests on one machine only.
	IncludeLoopback bool
	// LoopbackOnly offers 127.0.0.1 and nothing else: tests whose outcome
	// hangs on which pair ICE picks, the same on every machine.
	LoopbackOnly bool
}

// Peer is who a connection serves, as the caller verified it.
type Peer struct {
	// Name groups connections for ClosePeer: the device key; for a copy, the
	// device that signed its grant, so removing that device ends the copy.
	Name string
	// Transfer is set on a connection with another machine (ADR 0035): it
	// serves that one copy only, never a shell or the owner's other files.
	Transfer *identity.Transfer
	// ICEServers replace the endpoint's for this connection (fresh TURN
	// credentials); nil keeps the endpoint's.
	ICEServers []webrtc.ICEServer

	// pc is set by the endpoint on what the handler gets.
	pc *webrtc.PeerConnection
}

// LAN reports the two addresses the connection runs between when it runs
// host to host inside one LAN (ADR 0039).
func (p Peer) LAN() (local, remote netip.Addr, ok bool) { return lanPath(p.pc) }

// Handler serves one opened DataChannel. It owns ch and must close it.
type Handler func(ctx context.Context, peer Peer, label string, ch io.ReadWriteCloser)

// Endpoint answers offers and serves their channels until closed.
type Endpoint struct {
	api     *webrtc.API
	config  webrtc.Configuration
	handler Handler
	ctx     context.Context
	cancel  context.CancelFunc

	// The mutex protects the following elements.
	mu      sync.Mutex
	closing bool
	wg      sync.WaitGroup
	// peers maps each connection to who it serves (Peer.Name), so a removed
	// device's connections can be cut.
	peers map[*webrtc.PeerConnection]string
}

// New builds an endpoint. Pion settings follow docs/v2/REFERENCES.md §2.
func New(opts Options, handler Handler) *Endpoint {
	var se webrtc.SettingEngine
	se.DetachDataChannels()                                 // io.ReadWriteCloser per channel
	se.EnableDataChannelBlockWrite(true)                    // writes wait for SCTP room: backpressure, not loss
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled) // no .local names on the wire
	se.SetICETimeouts(5*time.Second, 15*time.Second, 2*time.Second)
	se.SetIncludeLoopbackCandidate(opts.IncludeLoopback || opts.LoopbackOnly)
	if opts.LoopbackOnly {
		se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
		se.SetIPFilter(func(ip net.IP) bool { return ip.IsLoopback() })
	}
	// Every channel of a connection shares one SCTP receive window (Pion's
	// default 1 MiB): a machine's terminals now share a connection (ADR 0018).
	se.SetSCTPMaxReceiveBufferSize(4 << 20)
	ctx, cancel := context.WithCancel(context.Background())
	return &Endpoint{
		api:     webrtc.NewAPI(webrtc.WithSettingEngine(se)),
		config:  webrtc.Configuration{ICEServers: opts.ICEServers},
		handler: handler,
		ctx:     ctx,
		cancel:  cancel,
		peers:   map[*webrtc.PeerConnection]string{},
	}
}

var errClosing = errors.New("rtc: endpoint is closing")

// Answer creates a peer for offerSDP and returns the complete answer SDP
// (all candidates gathered: one blob, signed by the caller). The offer's DTLS
// fingerprint is what Pion will hold the browser to; the caller verified the
// owner's signature over that SDP before calling this.
// Each channel the browser opens goes to the handler with peer.
func (e *Endpoint) Answer(ctx context.Context, offerSDP string, peer Peer) (string, error) {
	pc, err := e.newPeer(peer)
	if err != nil {
		return "", err
	}
	peer.pc = pc
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		dc.OnOpen(func() {
			raw, derr := dc.Detach()
			if derr != nil {
				return
			}
			e.run(func() { e.handler(e.ctx, peer, dc.Label(), raw) })
		})
	})

	answer, err := negotiate(ctx, pc, offerSDP)
	if err != nil {
		e.untrack(pc)
		return "", err
	}
	return answer, nil
}

// newPeer creates a tracked connection for peer, cut when it fails.
func (e *Endpoint) newPeer(peer Peer) (*webrtc.PeerConnection, error) {
	config := e.config
	if peer.ICEServers != nil {
		config.ICEServers = peer.ICEServers
	}
	pc, err := e.api.NewPeerConnection(config)
	if err != nil {
		return nil, err
	}
	if !e.track(pc, peer.Name) {
		_ = pc.Close()
		return nil, errClosing
	}
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateFailed || state == webrtc.PeerConnectionStateClosed {
			e.untrack(pc)
		}
	})
	return pc, nil
}

func negotiate(ctx context.Context, pc *webrtc.PeerConnection, offerSDP string) (string, error) {
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offerSDP}); err != nil {
		return "", err
	}
	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return "", err
	}
	gathered := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(answer); err != nil {
		return "", err
	}
	select {
	case <-gathered:
	case <-ctx.Done():
		return "", ctx.Err()
	}
	return pc.LocalDescription().SDP, nil
}

func (e *Endpoint) track(pc *webrtc.PeerConnection, peer string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closing {
		return false
	}
	e.peers[pc] = peer
	return true
}

// ClosePeer ends every connection serving peer, and so every channel and
// shell stream on them (a removed device, ADR 0004). Its shells live on.
func (e *Endpoint) ClosePeer(peer string) {
	e.mu.Lock()
	var cut []*webrtc.PeerConnection
	for pc, p := range e.peers {
		if p == peer {
			cut = append(cut, pc)
		}
	}
	e.mu.Unlock()
	for _, pc := range cut {
		e.untrack(pc)
	}
}

func (e *Endpoint) untrack(pc *webrtc.PeerConnection) {
	e.mu.Lock()
	_, ok := e.peers[pc]
	delete(e.peers, pc)
	e.mu.Unlock()
	if ok {
		e.run(func() { _ = pc.Close() })
	}
}

// run starts fn unless the endpoint is closing, and lets Close wait for it
// (coder's trackGoroutine).
func (e *Endpoint) run(fn func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closing {
		return
	}
	e.wg.Go(fn)
}

// Close ends every peer and waits for their handlers.
func (e *Endpoint) Close() {
	e.mu.Lock()
	e.closing = true
	peers := e.peers
	e.peers = map[*webrtc.PeerConnection]string{}
	e.mu.Unlock()
	e.cancel()
	for pc := range peers {
		_ = pc.Close()
	}
	e.wg.Wait()
}

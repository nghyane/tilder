package link

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/pion/webrtc/v4"

	"github.com/nghyane/tilder/go/internal/agent/rtc"
	"github.com/nghyane/tilder/go/internal/identity"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

const (
	sessionIDSize = 16
	// turnWait bounds asking for relay credentials: without them a copy
	// still tries a direct connection.
	turnWait = 3 * time.Second
	// turnMargin: credentials this close to expiring are asked for again.
	turnMargin = 5 * time.Minute
)

var (
	// ErrOffline means the rendezvous is not connected: the copy waits.
	ErrOffline = errors.New("link: not connected to the rendezvous")
	// ErrUndeliverable means the other machine is offline, or the server
	// would not pass the offer on.
	ErrUndeliverable = errors.New("link: the other machine could not be reached")
	// ErrBadAnswer means the answer was not signed by the machine the grant names.
	ErrBadAnswer = errors.New("link: the answer is not from the machine the grant names")
)

// Signal is how this machine, the destination of a copy, reaches the source
// the grant names (ADR 0035): its offer goes through the rendezvous with the
// grant, and only an answer signed by that source's key is returned.
func (l *Link) Signal(grant *tilderv1.TransferGrant, t identity.Transfer) rtc.Signal {
	return func(ctx context.Context, offerSDP string) (string, error) {
		session := make([]byte, sessionIDSize)
		if _, err := rand.Read(session); err != nil {
			return "", err
		}
		self := identity.MachineID(l.Key.Public())
		sig := l.Key.Sign(identity.MachineOfferStatement(t.Src, self, session, offerSDP, grant.GetStatement()))
		reply, err := l.ask(ctx, string(session), &tilderv1.Envelope{Msg: &tilderv1.Envelope_MachineSignal{MachineSignal: &tilderv1.MachineSignal{
			ToMachine: t.Src, SessionId: session, Sdp: offerSDP, Signature: sig, Grant: grant,
		}}})
		if err != nil {
			return "", err
		}
		answer := reply.GetSignalAnswer()
		if answer == nil {
			return "", ErrUndeliverable
		}
		key, err := identity.MachinePublicFromBytes(answer.GetMachinePublicKey())
		if err != nil || identity.MachineID(key) != t.Src ||
			!key.Verify(identity.AnswerStatement(t.Src, session, offerSDP, answer.GetSdp()), answer.GetSignature()) {
			return "", ErrBadAnswer
		}
		return answer.GetSdp(), nil
	}
}

// ask sends env and waits for the reply to session: SignalAnswer or
// Undeliverable. A dropped connection ends the wait at once.
func (l *Link) ask(ctx context.Context, session string, env *tilderv1.Envelope) (*tilderv1.Envelope, error) {
	wait := make(chan *tilderv1.Envelope, 1)
	l.connMu.Lock()
	conn := l.conn
	if conn != nil {
		l.waits[session] = wait
	}
	l.connMu.Unlock()
	if conn == nil {
		return nil, ErrOffline
	}
	defer func() {
		l.connMu.Lock()
		delete(l.waits, session)
		l.connMu.Unlock()
	}()
	if err := conn.write(ctx, env); err != nil {
		return nil, ErrOffline
	}
	select {
	case reply := <-wait:
		if reply == nil {
			return nil, ErrOffline
		}
		return reply, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ICEServers returns STUN and, when the server has a relay, TURN credentials
// for a connection with another machine; nil when none could be had in time
// (the endpoint's own STUN is used).
func (l *Link) ICEServers(ctx context.Context) []webrtc.ICEServer {
	now := l.Clock.Now()
	l.connMu.Lock()
	if l.turn != nil && now.Add(turnMargin).Before(l.turnUntil) {
		servers := l.turn
		l.connMu.Unlock()
		return servers
	}
	conn := l.conn
	wait := make(chan struct{})
	if conn != nil {
		l.turnWaits = append(l.turnWaits, wait)
	}
	l.connMu.Unlock()
	if conn == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, turnWait)
	defer cancel()
	if err := conn.write(ctx, &tilderv1.Envelope{Msg: &tilderv1.Envelope_TurnRequest{TurnRequest: &tilderv1.TurnRequest{}}}); err != nil {
		return nil
	}
	select {
	case <-wait:
	case <-ctx.Done():
	}
	l.connMu.Lock()
	defer l.connMu.Unlock()
	return l.turn
}

// took hands a rendezvous message to whoever waits for it.
func (l *Link) took(env *tilderv1.Envelope) {
	l.connMu.Lock()
	defer l.connMu.Unlock()
	var session []byte
	switch m := env.GetMsg().(type) {
	case *tilderv1.Envelope_SignalAnswer:
		session = m.SignalAnswer.GetSessionId()
	case *tilderv1.Envelope_Undeliverable:
		session = m.Undeliverable.GetSessionId()
	case *tilderv1.Envelope_TurnServers:
		l.turn = iceServers(m.TurnServers)
		l.turnUntil = time.UnixMilli(m.TurnServers.GetExpiresAtMs())
		for _, w := range l.turnWaits {
			close(w)
		}
		l.turnWaits = nil
		return
	default:
		return
	}
	if wait, ok := l.waits[string(session)]; ok {
		wait <- env
		delete(l.waits, string(session))
	}
}

// connected records the live connection, or its end (nil): every wait on
// the old one ends.
func (l *Link) connected(conn *wsConn) {
	l.connMu.Lock()
	defer l.connMu.Unlock()
	l.conn = conn
	if conn != nil {
		if l.waits == nil {
			l.waits = map[string]chan *tilderv1.Envelope{}
		}
		return
	}
	for session, wait := range l.waits {
		wait <- nil
		delete(l.waits, session)
	}
	for _, w := range l.turnWaits {
		close(w)
	}
	l.turnWaits = nil
}

func iceServers(t *tilderv1.TurnServers) []webrtc.ICEServer {
	out := make([]webrtc.ICEServer, 0, len(t.GetIceServers()))
	for _, s := range t.GetIceServers() {
		out = append(out, webrtc.ICEServer{URLs: s.GetUrls(), Username: s.GetUsername(), Credential: s.GetCredential()})
	}
	return out
}

// trustedMachine checks an offer from another machine for a copy (ADR 0035),
// all of it on this machine, trusting nothing the server checked: the grant's
// device certified by the root pinned at join, valid on this clock, not
// removed; the grant signed by that device, naming this machine as the
// source; the offer signed by the key of the machine the grant names as the
// destination, over this session, SDP and grant.
func (l *Link) trustedMachine(d *tilderv1.SignalDeliver) (identity.Transfer, bool) {
	key, err := identity.MachinePublicFromBytes(d.GetMachinePublicKey())
	if err != nil {
		return identity.Transfer{}, false
	}
	g := d.GetGrant()
	cert := g.GetDeviceCertificate()
	now := l.Clock.Now()
	dc, err := identity.VerifyDeviceCert(cert.GetStatement(), cert.GetSignature(), now)
	if err != nil || dc.Root != l.Owner {
		return identity.Transfer{}, false
	}
	l.revMu.Lock()
	revoked := l.revokedLocked(dc.Device, dc.RevSeq)
	l.revMu.Unlock()
	if revoked {
		return identity.Transfer{}, false
	}
	t, err := identity.VerifyTransfer(g.GetStatement(), g.GetSignature(), dc, now)
	self := identity.MachineID(l.Key.Public())
	if err != nil || t.Src != self || identity.MachineID(key) != t.Dst {
		return identity.Transfer{}, false
	}
	offer := identity.MachineOfferStatement(self, t.Dst, d.GetSessionId(), d.GetSdp(), g.GetStatement())
	return t, key.Verify(offer, d.GetSignature())
}

// ErrGrant means a grant this machine may not act on.
var ErrGrant = errors.New("link: the copy is not allowed")

// ErrStale means a grant cannot be judged yet: the list of removed devices
// is unread, unreadable, or older than the grant's certificate knows. The
// copy waits for a newer list; it is neither run nor thrown away.
var ErrStale = fmt.Errorf("%w: the list of removed devices is not known yet", ErrGrant)

// VerifyPull checks a grant a device sent this machine to pull (ADR 0035),
// all on this machine: its device certified by the pinned root, valid on this
// clock, not removed; the grant signed by that device, naming this machine as
// the destination.
func (l *Link) VerifyPull(g *tilderv1.TransferGrant) (identity.Transfer, error) {
	cert := g.GetDeviceCertificate()
	now := l.Clock.Now()
	dc, err := identity.VerifyDeviceCert(cert.GetStatement(), cert.GetSignature(), now)
	if err != nil || dc.Root != l.Owner {
		return identity.Transfer{}, ErrGrant
	}
	l.revMu.Lock()
	removed := l.revoked.Has(dc.Device)
	stale := !l.revLoaded || l.revBroken || dc.RevSeq > l.revoked.Seq
	l.revMu.Unlock()
	switch {
	case removed:
		return identity.Transfer{}, ErrGrant
	case stale:
		return identity.Transfer{}, ErrStale
	}
	t, err := identity.VerifyTransfer(g.GetStatement(), g.GetSignature(), dc, now)
	if err != nil || t.Dst != identity.MachineID(l.Key.Public()) {
		return identity.Transfer{}, ErrGrant
	}
	return t, nil
}

// answerMachine answers a verified machine offer with a connection that
// serves only that copy, named after the grant's device so removing the
// device ends it.
func (l *Link) answerMachine(ctx context.Context, d *tilderv1.SignalDeliver) (rtc.Peer, bool) {
	t, ok := l.trustedMachine(d)
	if !ok {
		l.Log.Warn("ignored an offer from a machine without a valid copy grant")
		return rtc.Peer{}, false
	}
	return rtc.Peer{Name: PeerName(t.Device), Transfer: &t, ICEServers: l.ICEServers(ctx)}, true
}

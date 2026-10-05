// Package link keeps an agent connected to its rendezvous and answers the
// owner's signed offers. It trusts nothing the server says about who asks:
// an offer is answered only if the owner key pinned at join signed it.
package link

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/pion/webrtc/v4"
	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/rtc"
	"github.com/nghyane/tilder/go/internal/clock"
	"github.com/nghyane/tilder/go/internal/identity"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

const (
	protocolVersion = 1
	answerTimeout   = 20 * time.Second
	maxBackoff      = 60 * time.Second
)

// Answerer creates the WebRTC answer for a verified offer (rtc.Endpoint).
type Answerer interface {
	// peer is who the connection serves: a device, or another machine for
	// one copy; its Name lets the owner's removing a device cut it.
	Answer(ctx context.Context, offerSDP string, peer rtc.Peer) (string, error)
}

// PeerName is how a device is named to the Answerer.
func PeerName(d identity.DevicePublic) string { return d.String() }

// Link is one agent's connection to its rendezvous.
type Link struct {
	Server   string // wss://host/ws
	Key      identity.MachinePrivate
	Owner    identity.RootPublic
	Hostname string
	// Host is what the machine runs (ADR 0019), reported in every hello.
	Host     *tilderv1.HostInfo
	Answerer Answerer
	Clock    clock.Clock
	Log      *slog.Logger
	// JoinSecret registers the machine on first connection; OnJoined is told
	// once the server accepted it, so the caller can erase the secret.
	JoinSecret []byte
	OnJoined   func()
	// OnConnected is told each time the server has welcomed the machine.
	OnConnected func()
	// Revocations keeps the owner's list of removed devices across restarts
	// (ADR 0004); OnRevoked is told which devices to cut off now.
	Revocations RevocationStore
	OnRevoked   func(devices []identity.DevicePublic)
	// OnUpdateNow runs the console's "update now" (ADR 0026) and says how it
	// went; nil means no answer (the agent is stopping).
	OnUpdateNow func(ctx context.Context) *tilderv1.UpdateResult

	// The mutex protects the following elements.
	revMu   sync.Mutex
	revoked identity.Revocations
	// revBroken: the stored list could not be read or checked; every offer
	// is refused until a good list arrives, rather than let a removed device in.
	revBroken bool
	// revLoaded: the stored list was read (LoadRevocations); before that no
	// grant is judged, only kept.
	revLoaded bool
	revOnce   sync.Once

	// The mutex protects the following elements.
	connMu sync.Mutex
	// conn is the live rendezvous connection, nil between them.
	conn *wsConn
	// waits are this machine's offers waiting for their answer, by session.
	waits map[string]chan *tilderv1.Envelope
	// turn is the newest relay credentials, good until turnUntil;
	// turnWaits are closed when new ones arrive.
	turn      []webrtc.ICEServer
	turnUntil time.Time
	turnWaits []chan struct{}
}

// RevocationStore persists the newest root-signed list of removed devices.
type RevocationStore interface {
	Load() (statement string, signature []byte, ok bool, err error)
	Save(statement string, signature []byte) error
}

// ErrBadJoin means the join secret was unknown, used or expired: retrying
// cannot help, the owner has to open a new join.
var ErrBadJoin = errors.New("link: the join token is unknown, used or expired")

// ErrRemoved means the rendezvous does not know this machine: the owner
// removed it (ADR 0052), or it never finished joining. Asking again soon
// changes nothing; the owner adds it back with a new join command.
var ErrRemoved = errors.New("link: this machine was removed; run the join command to add it again")

// removedWait is how long a removed machine waits before asking again.
const removedWait = time.Hour

// Run stays connected until ctx ends, reconnecting with backoff.
func (l *Link) Run(ctx context.Context) error {
	l.LoadRevocations()
	attempt := 0
	for ctx.Err() == nil {
		connected, err := l.session(ctx)
		if errors.Is(err, ErrBadJoin) {
			return err
		}
		if connected {
			attempt = 0
		}
		if ctx.Err() != nil {
			return nil //nolint:nilerr // a cancelled context is a clean stop, not a failure
		}
		wait := backoff(attempt)
		attempt++
		if errors.Is(err, ErrRemoved) {
			wait = removedWait
		}
		l.Log.Warn("rendezvous connection ended", slog.Any("error", err), slog.Duration("retry_in", wait))
		timer := l.Clock.NewTimer(wait, "reconnect")
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
	return nil
}

// backoff is 1 s doubling to 60 s, ±30 %.
func backoff(attempt int) time.Duration {
	base := min(time.Second<<min(attempt, 6), maxBackoff)
	return time.Duration(float64(base) * (0.7 + 0.6*rand.Float64())) //nolint:gosec // G404: jitter, not a secret
}

// session is one connection; connected reports whether the handshake passed.
func (l *Link) session(ctx context.Context) (connected bool, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, l.Server, nil) //nolint:bodyclose // the websocket owns the response
	if err != nil {
		return false, err
	}
	defer func() { _ = ws.CloseNow() }()
	conn := &wsConn{ws: ws}

	if err := l.hello(ctx, conn); err != nil {
		return false, err
	}
	l.Log.Info("connected to rendezvous", slog.String("machine_id", identity.MachineID(l.Key.Public())))
	if l.OnConnected != nil {
		l.OnConnected()
	}
	l.connected(conn)
	defer l.connected(nil)

	var wg sync.WaitGroup
	defer wg.Wait()
	// Ends with this connection, before the wait: the loop below only
	// returns on a read error, with ctx still live.
	turnCtx, stopTurn := context.WithCancel(ctx)
	defer stopTurn()
	wg.Go(func() { l.keepTurn(turnCtx) })
	for {
		env, err := conn.read(ctx)
		if err != nil {
			return true, err
		}
		l.took(env)
		if deliver := env.GetSignalDeliver(); deliver != nil {
			wg.Go(func() { l.answer(ctx, conn, deliver) })
		}
		if list := env.GetRevocations(); list != nil {
			l.applyRevocations(list.GetStatement(), list.GetSignature())
		}
		if env.GetUpdateNow() != nil && l.OnUpdateNow != nil {
			wg.Go(func() {
				if r := l.OnUpdateNow(ctx); r != nil {
					_ = conn.write(ctx, &tilderv1.Envelope{Msg: &tilderv1.Envelope_UpdateResult{UpdateResult: r}})
				}
			})
		}
	}
}

func (l *Link) hello(ctx context.Context, conn *wsConn) error {
	env, err := conn.read(ctx)
	if err != nil {
		return err
	}
	nonce := env.GetChallenge().GetNonce()
	pub := l.Key.Public().Raw32()
	hello := &tilderv1.AgentHello{
		Hello: &tilderv1.Hello{Protocol: protocolVersion}, MachinePublicKey: pub[:],
		Signature: l.Key.Sign(identity.AgentHelloStatement(nonce, l.Key.Public())),
		Hostname:  l.Hostname, Host: l.Host,
	}
	if len(l.JoinSecret) > 0 {
		// The server gets only the lookup half; the other half proves this
		// machine's key to the console that made the secret (ADR 0004).
		lookup, auth, serr := identity.SplitJoinSecret(l.JoinSecret)
		if serr != nil {
			return ErrBadJoin
		}
		hello.JoinSecret, hello.JoinProof = lookup, identity.JoinProof(auth, l.Key.Public())
	}
	if werr := conn.write(ctx, &tilderv1.Envelope{Msg: &tilderv1.Envelope_AgentHello{AgentHello: hello}}); werr != nil {
		return werr
	}
	reply, err := conn.read(ctx)
	if err != nil {
		return err
	}
	if refused := reply.GetRefused(); refused != nil {
		switch refused.GetReason() {
		case tilderv1.Refused_REASON_BAD_JOIN:
			return ErrBadJoin
		case tilderv1.Refused_REASON_UNKNOWN_MACHINE:
			return ErrRemoved
		}
		return fmt.Errorf("rendezvous refused this machine: %s", refused.GetReason())
	}
	if reply.GetWelcome() == nil {
		return errors.New("rendezvous did not welcome this machine")
	}
	if l.JoinSecret != nil {
		l.JoinSecret = nil
		if l.OnJoined != nil {
			l.OnJoined()
		}
	}
	return nil
}

// LoadRevocations reads the stored list of removed devices, once: the agent
// calls it before it resumes any copy or serves anyone (ADR 0040), as
// tailscale opens its tailnet-lock state from disk before logging in. Run
// calls it too; the second call does nothing.
func (l *Link) LoadRevocations() { l.revOnce.Do(l.loadRevocations) }

func (l *Link) loadRevocations() {
	defer func() {
		l.revMu.Lock()
		l.revLoaded = true
		l.revMu.Unlock()
	}()
	if l.Revocations == nil {
		return
	}
	statement, sig, ok, err := l.Revocations.Load()
	if err == nil && ok {
		var rev identity.Revocations
		if rev, err = identity.VerifyRevocations(statement, sig, l.Owner); err == nil {
			l.revMu.Lock()
			l.revoked = l.revoked.Merge(rev)
			l.revMu.Unlock()
		}
	}
	if err != nil {
		l.Log.Error("refusing every device until the owner's list of removed devices arrives again", slog.Any("error", err))
		l.revMu.Lock()
		l.revBroken = true
		l.revMu.Unlock()
	}
}

// applyRevocations merges a list the owner's root signed (the set only
// grows), stores it before acting when it supersedes the stored one, then
// has the newly removed devices cut off.
func (l *Link) applyRevocations(statement string, sig []byte) {
	rev, err := identity.VerifyRevocations(statement, sig, l.Owner)
	if err != nil {
		l.Log.Warn("ignored a list of removed devices not signed by this machine's owner")
		return
	}
	l.revMu.Lock()
	var added []identity.DevicePublic
	superset := true
	for _, d := range rev.Devices {
		if !l.revoked.Has(d) {
			added = append(added, d)
		}
	}
	for _, d := range l.revoked.Devices {
		superset = superset && rev.Has(d)
	}
	if superset && l.Revocations != nil {
		// Stored first; a failed write still applies in memory (refusing more
		// is safe), and says so.
		if serr := l.Revocations.Save(statement, sig); serr != nil {
			l.Log.Error("could not store the list of removed devices", slog.Any("error", serr))
		}
	}
	l.revoked = l.revoked.Merge(rev)
	l.revBroken = false
	l.revMu.Unlock()
	if len(added) > 0 && l.OnRevoked != nil {
		l.OnRevoked(added)
	}
}

// revokedLocked reports whether a device may not be trusted: removed, or its
// certificate knows a newer list than this machine does (it must catch up).
// l.revMu must be held.
func (l *Link) revokedLocked(d identity.DevicePublic, certRevSeq uint64) bool {
	return l.revBroken || l.revoked.Has(d) || certRevSeq > l.revoked.Seq
}

// trusted checks an offer's device and signature.
func (l *Link) trusted(d *tilderv1.SignalDeliver) bool {
	device, err := identity.DevicePublicFromBytes(d.GetDevicePublicKey())
	if err != nil {
		return false
	}
	cert := d.GetDeviceCertificate()
	dc, err := identity.VerifyDeviceCert(cert.GetStatement(), cert.GetSignature(), l.Clock.Now())
	if err != nil || dc.Root != l.Owner || dc.Device != device {
		return false
	}
	l.revMu.Lock()
	revoked := l.revokedLocked(device, dc.RevSeq)
	l.revMu.Unlock()
	if revoked {
		return false
	}
	offer := identity.OfferStatement(identity.MachineID(l.Key.Public()), d.GetSessionId(), d.GetSdp())
	return device.Verify(offer, d.GetSignature())
}

// answer replies with a signed answer to an offer from one of the owner's
// devices: a device-cert signed by the root pinned at join and valid on this
// machine's clock (never the server's), for the very key that signed the
// offer (ADR 0004). An offer that fails gets no reply at all: an error would
// tell a prober something.
func (l *Link) answer(ctx context.Context, conn *wsConn, d *tilderv1.SignalDeliver) {
	actx, cancel := context.WithTimeout(ctx, answerTimeout)
	defer cancel()
	var peer rtc.Peer
	if len(d.GetMachinePublicKey()) > 0 {
		var ok bool
		if peer, ok = l.answerMachine(actx, d); !ok {
			return
		}
	} else {
		if !l.trusted(d) {
			l.Log.Warn("ignored an offer not from one of this machine's owner's devices")
			return
		}
		device, _ := identity.DevicePublicFromBytes(d.GetDevicePublicKey()) // checked by trusted
		// The machine's own relay too (ADR 0046): behind a network that lets
		// only the relay out, the browser's relay alone cannot reach it.
		peer = rtc.Peer{Name: PeerName(device), ICEServers: l.relay()}
	}
	answerSDP, err := l.Answerer.Answer(actx, d.GetSdp(), peer)
	if err != nil {
		l.Log.Warn("could not answer an offer", slog.Any("error", err))
		return
	}
	machineID := identity.MachineID(l.Key.Public())
	sig := l.Key.Sign(identity.AnswerStatement(machineID, d.GetSessionId(), d.GetSdp(), answerSDP))
	_ = conn.write(ctx, &tilderv1.Envelope{Msg: &tilderv1.Envelope_SignalReply{SignalReply: &tilderv1.SignalReply{
		ReplyHandle: d.GetReplyHandle(), Sdp: answerSDP, Signature: sig,
	}}})
}

// wsConn serialises writes: answers are produced concurrently.
type wsConn struct {
	ws *websocket.Conn
	mu sync.Mutex
}

func (c *wsConn) read(ctx context.Context) (*tilderv1.Envelope, error) {
	_, data, err := c.ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	env := &tilderv1.Envelope{}
	return env, proto.Unmarshal(data, env)
}

func (c *wsConn) write(ctx context.Context, env *tilderv1.Envelope) error {
	frame, err := proto.Marshal(env)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ws.Write(ctx, websocket.MessageBinary, frame)
}

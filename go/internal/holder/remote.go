package holder

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nghyane/tilder/go/internal/clock"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// lostCode is the exit reported when a holder is gone without saying how its
// shell ended (ADR 0005: "report lost honestly").
const lostCode = -1

const dialTimeout = 2 * time.Second

// remote is a Session whose shell lives in a holder process. Each attach is
// its own connection (it carries the stream); input and resizes share one
// control connection, in order; a kill dials its own, so a paste stuck behind
// a program that reads nothing cannot hold it back.
type remote struct {
	path string

	// ctlMu keeps writes on the control connection in order, and is held
	// across a write that blocks for as long as the shell reads nothing.
	// Lock order: ctlMu, then mu.
	ctlMu sync.Mutex
	// sizeMu does the same for resizes, which go on a connection of their
	// own: a resize behind a paste the program never reads waited with it,
	// and held up every client of the shell and the tab's Kill (tmux sets
	// the size with an ioctl that never waits on input; zellij keeps input
	// in a queue of its own). Lock order: sizeMu, then mu.
	sizeMu sync.Mutex

	// The mutex protects the following elements.
	mu      sync.Mutex
	ctl     net.Conn
	size    net.Conn
	viewers map[*Viewer]net.Conn
	pid     int
}

var _ Session = (*remote)(nil)

// Pid is the holder's shell, as its welcome said; 0 before the first attach.
func (s *remote) Pid() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pid
}

func newRemote(path string) *remote {
	return &remote{path: path, viewers: map[*Viewer]net.Conn{}}
}

// dial connects and exchanges Hello/Welcome.
func dial(path string) (net.Conn, *bufio.Reader, *tilderv1.HolderWelcome, error) {
	// Bounded: a wedged holder must not wedge the agent.
	d := net.Dialer{Timeout: dialTimeout}
	c, err := d.DialContext(context.Background(), "unix", path)
	if err != nil {
		return nil, nil, nil, err
	}
	// The handshake is bounded too: Open holds the holders' lock meanwhile,
	// and one stopped holder must not freeze every other shell.
	_ = c.SetDeadline(clock.Real().Now().Add(dialTimeout))
	r := bufio.NewReader(c)
	hello := &tilderv1.HolderRequest{Msg: &tilderv1.HolderRequest_Hello{Hello: &tilderv1.HolderHello{ContractVersion: ContractVersion}}}
	if err := send(c, hello); err != nil {
		_ = c.Close()
		return nil, nil, nil, err
	}
	e := &tilderv1.HolderEvent{}
	if err := receive(r, e); err != nil || e.GetWelcome() == nil {
		_ = c.Close()
		return nil, nil, nil, fmt.Errorf("holder: no welcome: %w", errors.Join(err, errors.New("unexpected first event")))
	}
	if v := e.GetWelcome().GetContractVersion(); v < oldestContract || v > ContractVersion {
		_ = c.Close()
		return nil, nil, nil, fmt.Errorf("holder: contract %d, this agent speaks %d to %d", v, oldestContract, ContractVersion)
	}
	_ = c.SetDeadline(time.Time{})
	return c, r, e.GetWelcome(), nil
}

// Attach opens a stream connection. A holder that cannot be reached means the
// shell is gone: the replay says it exited, with lostCode.
func (s *remote) Attach(since uint64) (Replay, *Viewer) {
	v := &Viewer{events: make(chan Event, viewerQueue)}
	c, r, welcome, err := dial(s.path)
	if err == nil {
		s.mu.Lock()
		s.pid = int(welcome.GetPid())
		s.mu.Unlock()
		err = send(c, &tilderv1.HolderRequest{Msg: &tilderv1.HolderRequest_Attach{Attach: &tilderv1.HolderAttach{Since: since}}})
	}
	e := &tilderv1.HolderEvent{}
	if err == nil {
		err = receive(r, e)
	}
	rep := e.GetReplay()
	if err != nil || rep == nil {
		if c != nil {
			_ = c.Close()
		}
		v.stop()
		return Replay{From: since, Exited: true, Code: lostCode}, v
	}
	replay := Replay{
		Data: rep.GetData(), From: rep.GetFrom(), Lost: rep.GetLost(), Exited: rep.GetExited(), Code: int(rep.GetCode()),
		Screen: rep.GetScreen(), Cols: clampSize(rep.GetCols()), Rows: clampSize(rep.GetRows()),
	}
	if replay.Exited {
		_ = c.Close()
		v.stop()
		return replay, v
	}
	s.mu.Lock()
	s.viewers[v] = c
	s.mu.Unlock()
	go s.pump(r, v)
	return replay, v
}

// pump delivers the stream, and is the only sender on v: it alone closes v's
// channel (closing it from Detach raced a send in flight). A full queue drops
// the viewer, as in-process: the channel closes and the caller re-attaches
// from what it has.
func (s *remote) pump(r *bufio.Reader, v *Viewer) {
	defer func() {
		s.mu.Lock()
		c := s.viewers[v]
		delete(s.viewers, v)
		s.mu.Unlock()
		if c != nil {
			_ = c.Close()
		}
		v.stop()
	}()
	for {
		e := &tilderv1.HolderEvent{}
		if receive(r, e) != nil {
			return
		}
		var ev Event
		switch m := e.GetMsg().(type) {
		case *tilderv1.HolderEvent_Output:
			ev = Event{Seq: m.Output.GetSeq(), Data: m.Output.GetData()}
		case *tilderv1.HolderEvent_Exit:
			ev = Event{Exited: true, Code: int(m.Exit.GetCode())}
		default:
			continue
		}
		if !deliverOrDrop(v, ev) || ev.Exited {
			return
		}
	}
}

// deliverOrDrop hands ev to v unless its queue is full.
func deliverOrDrop(v *Viewer, ev Event) bool {
	select {
	case v.events <- ev:
		return true
	default:
		return false
	}
}

// Detach closes the viewer's stream connection; its pump then ends and closes
// the channel.
func (s *remote) Detach(v *Viewer) {
	s.mu.Lock()
	c := s.viewers[v]
	s.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func (s *remote) control(req *tilderv1.HolderRequest) error {
	s.ctlMu.Lock()
	defer s.ctlMu.Unlock()
	return s.sendOn(&s.ctl, req)
}

// sendOn sends req on the connection *conn names, dialling it first; a
// failed one is dropped, to be dialled again. The caller holds the lock
// that orders that connection's writes. *conn is guarded by mu.
func (s *remote) sendOn(conn *net.Conn, req *tilderv1.HolderRequest) error {
	s.mu.Lock()
	c := *conn
	s.mu.Unlock()
	if c == nil {
		var err error
		if c, _, _, err = dial(s.path); err != nil {
			return err
		}
		s.mu.Lock()
		*conn = c
		s.mu.Unlock()
	}
	// Not under mu: close must be able to cut a write that blocks.
	if err := send(c, req); err != nil {
		s.mu.Lock()
		if *conn == c {
			*conn = nil
		}
		s.mu.Unlock()
		_ = c.Close()
		return err
	}
	return nil
}

func (s *remote) Input(p []byte) error {
	return s.control(&tilderv1.HolderRequest{Msg: &tilderv1.HolderRequest_Input{Input: &tilderv1.PtyInput{Data: p}}})
}

func (s *remote) Resize(cols, rows uint16) error {
	s.sizeMu.Lock()
	defer s.sizeMu.Unlock()
	return s.sendOn(&s.size, &tilderv1.HolderRequest{Msg: &tilderv1.HolderRequest_Resize{Resize: &tilderv1.Resize{Cols: uint32(cols), Rows: uint32(rows)}}})
}

func (s *remote) Kill() {
	c, _, _, err := dial(s.path)
	if err != nil {
		return // no holder: nothing left to kill
	}
	defer func() { _ = c.Close() }()
	_ = send(c, &tilderv1.HolderRequest{Msg: &tilderv1.HolderRequest_Kill{Kill: &tilderv1.Kill{}}})
}

// close drops every connection, a blocked write included; the holder and its
// shell keep running.
func (s *remote) close() {
	s.mu.Lock()
	viewers := s.viewers
	s.viewers = map[*Viewer]net.Conn{}
	ctl, size := s.ctl, s.size
	s.ctl, s.size = nil, nil
	s.mu.Unlock()
	for _, c := range viewers {
		_ = c.Close() // each pump ends and closes its viewer
	}
	for _, c := range []net.Conn{ctl, size} {
		if c != nil {
			_ = c.Close()
		}
	}
}

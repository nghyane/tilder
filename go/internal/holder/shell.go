// Package holder owns shells: the PTY, the process group, and the output ring.
// It is the only package that starts processes (depguard). In P1 it runs
// inside the agent; P2 moves it into its own process so shells outlive the
// agent (ADR 0005), without changing this API.
package holder

import (
	"sync"
	"time"

	"github.com/nghyane/tilder/go/internal/clock"
)

const (
	readChunk = 32 * 1024
	// Events a viewer may be behind before it is dropped: a slow viewer is
	// disconnected and reattaches from its offset rather than stalling the
	// shell or losing bytes mid-stream (upterm's per-guest cap).
	viewerQueue = 128
	killGrace   = 3 * time.Second
	// How long output left in the terminal is read after the shell exits.
	drainGrace = 100 * time.Millisecond
)

// Event is output (Data at offset Seq) or, when Exited, the exit code.
type Event struct {
	Seq    uint64
	Data   []byte
	Exited bool
	Code   int
}

// Viewer receives a shell's events after its replay. Its channel closes when
// the viewer is dropped (too slow) or closed.
type Viewer struct {
	events chan Event
	once   sync.Once
}

// Events is the stream after the replay Attach returned.
func (v *Viewer) Events() <-chan Event { return v.events }

func (v *Viewer) stop() { v.once.Do(func() { close(v.events) }) }

// Shell is one process on a PTY.
type Shell struct {
	ID    string
	con   console
	clock clock.Clock
	// onExit runs once, after the shell has exited and every viewer heard it.
	onExit func()
	// done closes when the shell has exited.
	done chan struct{}

	// The mutex protects the following elements.
	mu      sync.Mutex
	ring    *Ring
	screen  *screen
	viewers map[*Viewer]struct{}
	exited  bool
	code    int
}

// Replay is what a viewer missed: Data from offset From, and Lost bytes
// that are no longer kept. Screen is the screen as of From, Cols×Rows, for
// a viewer that starts afresh (ADR 0017); the stream goes on from From.
type Replay struct {
	Data   []byte
	From   uint64
	Lost   uint64
	Exited bool
	Code   int
	Screen []byte
	Cols   uint16
	Rows   uint16
}

// Attach replays from since and subscribes, under one lock, so nothing is
// written between the replay and the subscription (coder's doAttach). The
// screen is taken under the same lock, so it matches the ring's end.
func (s *Shell) Attach(since uint64) (Replay, *Viewer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, from, lost := s.ring.Since(since)
	v := &Viewer{events: make(chan Event, viewerQueue)}
	if s.exited {
		v.stop()
	} else {
		s.viewers[v] = struct{}{}
	}
	cols, rows := s.screen.size()
	return Replay{
		Data: data, From: from, Lost: lost, Exited: s.exited, Code: s.code,
		Screen: s.screen.snapshot(), Cols: cols, Rows: rows,
	}, v
}

// ScreenEnd is the ring offset a screen from Attach stands for: the stream
// after it starts there.
func (r Replay) ScreenEnd() uint64 { return r.From + uint64(len(r.Data)) }

// Detach stops delivering to v.
func (s *Shell) Detach(v *Viewer) {
	s.mu.Lock()
	delete(s.viewers, v)
	s.mu.Unlock()
	v.stop()
}

// Input writes keystrokes. It never holds the shell's lock: a program that is
// not reading its input blocks only this caller, never output or other shells.
func (s *Shell) Input(p []byte) error {
	_, err := s.con.Write(p)
	return err
}

// Done closes when the shell has exited.
func (s *Shell) Done() <-chan struct{} { return s.done }

// Pid is the shell's process id (its session leader).
func (s *Shell) Pid() int { return s.con.pid() }

// Resize sets the terminal size.
func (s *Shell) Resize(cols, rows uint16) error {
	s.mu.Lock()
	s.screen.resize(cols, rows) // under the lock: output is drawn at the size it was printed at
	s.mu.Unlock()
	return s.con.resize(cols, rows)
}

// Kill hangs up the shell and every job it started, then ends whatever is
// left after a grace period.
func (s *Shell) Kill() {
	s.mu.Lock()
	exited := s.exited
	s.mu.Unlock()
	if exited {
		return // reaped: its pid may belong to another process by now
	}
	s.con.hangup()
	s.clock.AfterFunc(killGrace, s.con.killAll, "kill-grace")
}

// pump copies output into the ring and out to viewers, and reports the exit
// when the shell's process ends (tmux and abduco go by SIGCHLD, not by EOF on
// the terminal): a background job can hold the terminal open long after the
// shell, and on Linux the read then never ends. Output still in the terminal
// is drained for up to drainGrace first. A read deadline cannot cut the read
// short instead: on macOS the master cannot be polled.
func (s *Shell) pump() {
	read := make(chan struct{})
	go func(c console) {
		defer close(read)
		buf := make([]byte, readChunk)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				s.publish(append([]byte(nil), buf[:n]...))
			}
			if err != nil {
				break // EOF or EIO: everything on the terminal is gone
			}
		}
		c.closeOutput()
	}(s.con)

	code := s.con.wait()
	select {
	case <-read:
	case <-s.clock.NewTimer(drainGrace, "drain").C:
	}
	s.finish(code)
	if s.onExit != nil {
		s.onExit() // outside s.mu: the manager takes its own lock
	}
}

func (s *Shell) finish(code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exited, s.code = true, code
	s.screen.close() // the drain ends; the screen is still read by a late attach
	close(s.done)
	for v := range s.viewers {
		deliver(v, Event{Exited: true, Code: code})
		v.stop()
	}
	s.viewers = map[*Viewer]struct{}{}
}

func (s *Shell) publish(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seq := s.ring.End()
	s.ring.Write(data)
	s.screen.write(data)
	for v := range s.viewers {
		if !deliver(v, Event{Seq: seq, Data: data}) {
			delete(s.viewers, v)
			v.stop()
		}
	}
}

// deliver never blocks the shell: a full queue means a viewer that fell behind.
func deliver(v *Viewer, e Event) bool {
	select {
	case v.events <- e:
		return true
	default:
		return false
	}
}

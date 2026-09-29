package holder

import (
	"sync"
	"time"

	"github.com/nghyane/tilder/go/internal/clock"
)

// Config is how shells are started. The agent's cmd/ fills it from the
// environment; nothing here reads the environment itself.
type Config struct {
	Shell    string   // e.g. /bin/zsh
	Args     []string // e.g. ["-l"] for a login shell
	Env      []string // the process environment, TERM included
	Dir      string   // the user's home
	RingSize int      // bytes of output kept for replay
	Clock    clock.Clock
	// ExitedTTL is how long an exited shell stays attachable (it reports its
	// exit) before it is forgotten; zero means DefaultExitedTTL.
	ExitedTTL time.Duration
}

// DefaultExitedTTL covers a client that reconnects just after the shell
// exited: it hears the exit instead of starting a new shell under the old id.
const DefaultExitedTTL = time.Minute

// Manager keeps the shells of this machine by id.
type Manager struct {
	cfg Config

	// The mutex protects the following elements.
	mu     sync.Mutex
	shells map[string]*Shell
}

// NewManager starts with no shells.
func NewManager(cfg Config) *Manager { return &Manager{cfg: cfg, shells: map[string]*Shell{}} }

// Open is Start as a Session, for callers that do not care where shells live.
func (m *Manager) Open(id string, cols, rows uint16) (Session, error) {
	return m.Start(id, cols, rows)
}

// OpenIn is Open for a new shell started in the directory dir names (nil:
// the configured one); dir is asked only when the shell does not exist yet.
func (m *Manager) OpenIn(id string, cols, rows uint16, dir func() (string, error)) (Session, error) {
	start := m.cfg.Dir
	if dir != nil && !m.running(id) {
		d, err := dir()
		if err != nil {
			return nil, err
		}
		start = d
	}
	return m.start(id, cols, rows, start)
}

func (m *Manager) running(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.shells[id]
	return ok
}

// Start returns shell id, starting it at cols×rows if it does not exist:
// one code path for a new tab and for a reconnect.
func (m *Manager) Start(id string, cols, rows uint16) (*Shell, error) {
	return m.start(id, cols, rows, m.cfg.Dir)
}

func (m *Manager) start(id string, cols, rows uint16, dir string) (*Shell, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.shells[id]; ok {
		return s, nil
	}
	con, err := startConsole(m.cfg, dir, cols, rows)
	if err != nil {
		return nil, err
	}
	s := &Shell{
		ID: id, con: con, clock: m.cfg.Clock,
		ring: NewRing(m.cfg.RingSize), screen: newScreen(cols, rows), viewers: map[*Viewer]struct{}{}, done: make(chan struct{}),
	}
	// Forget the shell a while after it exits: each one holds a ring of up to
	// RingSize bytes, and every tab now has its own shell (ADR 0014).
	s.onExit = func() { m.reapAfterTTL(id, s) }
	m.shells[id] = s
	go s.pump()
	return s, nil
}

func (m *Manager) reapAfterTTL(id string, s *Shell) {
	ttl := m.cfg.ExitedTTL
	if ttl <= 0 {
		ttl = DefaultExitedTTL
	}
	m.cfg.Clock.AfterFunc(ttl, func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.shells[id] == s { // not a newer shell that took the id
			delete(m.shells, id)
		}
	}, "reap-exited")
}

// closeGrace bounds how long Close waits for killed shells to exit.
const closeGrace = 5 * time.Second

// Close kills every shell and waits, for up to closeGrace, until each has
// exited: a caller that tears down after Close (a test's leak check, the
// agent's exit) finds no shell still dying. Idempotent.
func (m *Manager) Close() {
	m.mu.Lock()
	killed := make([]*Shell, 0, len(m.shells))
	for id, s := range m.shells {
		s.Kill()
		delete(m.shells, id)
		killed = append(killed, s)
	}
	m.mu.Unlock() // not held while waiting: an exiting shell's reap takes it
	if len(killed) == 0 {
		return
	}
	grace := m.cfg.Clock.NewTimer(closeGrace, "close")
	defer grace.Stop()
	for _, s := range killed {
		select {
		case <-s.Done():
		case <-grace.C:
			return
		}
	}
}

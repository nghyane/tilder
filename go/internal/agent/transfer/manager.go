package transfer

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/files"
	"github.com/nghyane/tilder/go/internal/clock"
	"github.com/nghyane/tilder/go/internal/identity"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

const (
	// keepEnded is how long an ended copy is still listed: a tab opened
	// again sees how it went.
	keepEnded = time.Hour
	maxJobs   = 64
	storeDir  = "transfers"
	maxGrant  = 16 * 1024
)

var (
	// ErrNotYet means a grant cannot be judged yet (ADR 0040); Verify wraps
	// it. Its copy is kept and waits, neither run nor thrown away.
	ErrNotYet = errors.New("transfer: the grant cannot be judged yet")
	// ErrBusy means this machine already has as many copies as it takes.
	ErrBusy = errors.New("transfer: too many copies at once")
	// ErrUnknown means no copy has that id.
	ErrUnknown = errors.New("transfer: no such copy")
)

// Manager holds the copies arriving on this machine. Each grant is kept in
// the agent's directory until its copy ends, so a restarted agent resumes it.
type Manager struct {
	Tree *files.Tree
	// Home is the agent's own directory.
	Home string
	// Verify checks a grant: from the owner's device, not removed, for this
	// machine as the destination (link.VerifyPull).
	Verify func(*tilderv1.TransferGrant) (identity.Transfer, error)
	// Connect reaches the grant's source.
	Connect func(*tilderv1.TransferGrant, identity.Transfer) Connect
	Clock   clock.Clock
	Log     *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// The mutex protects the following elements.
	mu      sync.Mutex
	closing bool
	jobs    map[string]*held
	subs    map[int]func(Progress)
	nextSub int
}

type held struct {
	job   *Job
	last  Progress
	ended time.Time
}

// Start resumes the copies a previous run left.
func (m *Manager) Start(ctx context.Context) {
	m.ctx, m.cancel = context.WithCancel(ctx)
	m.mu.Lock()
	m.jobs, m.subs = map[string]*held{}, map[int]func(Progress){}
	m.mu.Unlock()
	names, _ := os.ReadDir(filepath.Join(m.Home, storeDir))
	for _, n := range names {
		id, ok := strings.CutSuffix(n.Name(), ".grant")
		if !ok {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(m.Home, storeDir, n.Name())) //nolint:gosec // G304: the agent's own directory
		g := &tilderv1.TransferGrant{}
		if err == nil && len(raw) <= maxGrant {
			err = proto.Unmarshal(raw, g)
		}
		if err != nil {
			m.forget(id)
			continue
		}
		t, verr := m.Verify(g)
		waits := errors.Is(verr, ErrNotYet)
		if verr != nil {
			// Not judged yet: kept, it waits (Recheck) with its own deadline.
			// No longer good (removed device, expired): only its part is removed.
			if t, verr = identity.ReadTransfer(g.GetStatement()); verr != nil {
				m.forget(id)
				continue
			}
			if !waits {
				t.NotAfter = time.Time{}
			}
		}
		if t.ID() != id {
			m.forget(id)
			continue
		}
		if _, perr := m.start(g, t, raw, t.NotAfter.IsZero()); perr != nil {
			m.Log.Warn("could not resume a copy", slog.String("transfer", id), slog.Any("error", perr))
		}
	}
}

// Revoked ends the copies whose grant a removed device signed (ADR 0040):
// their connections are cut too, but a copy between attempts would only
// learn it at its next one.
func (m *Manager) Revoked(devices []identity.DevicePublic) {
	m.mu.Lock()
	var cut []*Job
	for _, h := range m.jobs {
		if h.ended.IsZero() && slices.Contains(devices, h.job.Grant.Device) {
			cut = append(cut, h.job)
		}
	}
	m.mu.Unlock()
	for _, j := range cut {
		j.Cancel()
	}
}

// Pull starts the copy a device's grant allows, or finds it already running.
func (m *Manager) Pull(g *tilderv1.TransferGrant) (string, error) {
	t, err := m.Verify(g)
	if err != nil {
		return "", err
	}
	raw, err := proto.Marshal(g)
	if err != nil {
		return "", err
	}
	return m.start(g, t, raw, false)
}

// start runs a job for a verified grant; cancelled, it only removes what
// an earlier run left (a grant no longer good).
func (m *Manager) start(g *tilderv1.TransferGrant, t identity.Transfer, raw []byte, cancelled bool) (string, error) {
	id := t.ID()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closing {
		return "", context.Canceled
	}
	if h, ok := m.jobs[id]; ok && h.ended.IsZero() {
		return id, nil
	}
	m.pruneLocked()
	if len(m.jobs) >= maxJobs {
		return "", ErrBusy
	}
	if !cancelled {
		if err := m.keep(id, raw); err != nil {
			return "", err
		}
	}
	j := &Job{Grant: t, Raw: raw, Tree: m.Tree, Connect: m.Connect(g, t), Clock: m.Clock, Log: m.Log}
	j.Recheck = func() error {
		_, err := m.Verify(g)
		return err
	}
	j.OnProgress = func(p Progress) { m.update(id, p) }
	if cancelled {
		j.Cancel()
	}
	m.jobs[id] = &held{job: j, last: Progress{ID: id, Waiting: true}}
	m.wg.Go(func() {
		if p := j.Run(m.ctx); p.Ended {
			m.forget(id)
		}
	})
	return id, nil
}

// keep stores the grant, so a restarted agent resumes the copy.
func (m *Manager) keep(id string, raw []byte) error {
	if !validID(id) {
		return ErrUnknown
	}
	dir := filepath.Join(m.Home, storeDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, id+".grant.tmp")
	if err := os.WriteFile(tmp, raw, 0o600); err != nil { //nolint:gosec // G703: id is checked base64url, never a path
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, id+".grant"))
}

func (m *Manager) forget(id string) {
	if !validID(id) {
		return
	}
	_ = os.Remove(filepath.Join(m.Home, storeDir, id+".grant"))
}

// validID: a grant id is a nonce in base64url, never a path.
func validID(id string) bool {
	return id != "" && len(id) <= 64 && strings.Trim(id, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == ""
}

func (m *Manager) update(id string, p Progress) {
	m.mu.Lock()
	h, ok := m.jobs[id]
	if ok {
		h.last = p
		if p.Ended {
			h.ended = m.Clock.Now()
		}
	}
	subs := make([]func(Progress), 0, len(m.subs))
	for _, s := range m.subs {
		subs = append(subs, s)
	}
	m.mu.Unlock()
	for _, s := range subs {
		s(p)
	}
}

// pruneLocked drops copies ended more than keepEnded ago. m.mu must be held.
func (m *Manager) pruneLocked() {
	now := m.Clock.Now()
	for id, h := range m.jobs {
		if !h.ended.IsZero() && now.Sub(h.ended) > keepEnded {
			delete(m.jobs, id)
		}
	}
}

// List is every copy running, and those ended in the last hour.
func (m *Manager) List() []Progress {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked()
	out := make([]Progress, 0, len(m.jobs))
	for _, h := range m.jobs {
		out = append(out, h.last)
	}
	return out
}

// Cancel stops a running copy and removes what arrived.
func (m *Manager) Cancel(id string) error {
	m.mu.Lock()
	h, ok := m.jobs[id]
	running := ok && h.ended.IsZero() // ended is written under m.mu by update
	m.mu.Unlock()
	if !running {
		return ErrUnknown
	}
	h.job.Cancel()
	return nil
}

// Subscribe tells fn of every copy's progress until the returned func is called.
func (m *Manager) Subscribe(fn func(Progress)) func() {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := m.nextSub
	m.nextSub++
	m.subs[id] = fn
	return func() {
		m.mu.Lock()
		delete(m.subs, id)
		m.mu.Unlock()
	}
}

// Close stops every copy, keeping each to resume, and waits for them.
func (m *Manager) Close() {
	m.mu.Lock()
	m.closing = true
	m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
	m.wg.Wait()
}

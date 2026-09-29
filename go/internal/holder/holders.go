package holder

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/nghyane/tilder/go/internal/clock"
)

// Spawner starts a holder process for shell id (ADR 0005).
type Spawner func(id string, cols, rows uint16, dir string) error

const spawnWait = 3 * time.Second

// Holders is the agent's side of ADR 0005: each shell lives in its own holder
// process, reached over a socket, so an agent that restarts, upgrades or
// crashes finds its shells again. Open reconnects to a living holder before
// it ever starts a new one.
type Holders struct {
	runDir string
	spawn  Spawner
	clock  clock.Clock

	// The mutex protects the following elements.
	mu       sync.Mutex
	sessions map[string]*remote
}

// NewHolders keeps holder sockets in runDir.
func NewHolders(runDir string, spawn Spawner, clk clock.Clock) *Holders {
	return &Holders{runDir: runDir, spawn: spawn, clock: clk, sessions: map[string]*remote{}}
}

// Open is OpenIn in the home.
func (h *Holders) Open(id string, cols, rows uint16) (Session, error) {
	return h.OpenIn(id, cols, rows, nil)
}

// OpenIn returns shell id: the living holder's if there is one, else a new
// holder started at cols×rows, in the directory dir names (nil: the home).
// dir is asked only when a holder starts, so reattaching to a shell never
// fails over a folder since deleted. A socket that answers but will not talk
// to us is an error, never a reason to start another holder over it.
func (h *Holders) OpenIn(id string, cols, rows uint16, dir func() (string, error)) (Session, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	path := SocketPath(h.runDir, id)
	state, probeErr := probe(path)
	switch state {
	case holderAlive:
	case holderAbsent:
		start := ""
		if dir != nil {
			d, err := dir()
			if err != nil {
				return nil, err
			}
			start = d
		}
		if err := h.spawn(id, cols, rows, start); err != nil {
			return nil, fmt.Errorf("start holder: %w", err)
		}
		if err := h.waitFor(path); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("reach holder: %w", probeErr)
	}
	s, ok := h.sessions[id]
	if !ok {
		s = newRemote(path)
		h.sessions[id] = s
	}
	return s, nil
}

type holderState int

const (
	holderAbsent holderState = iota // no socket, or nobody listening on it
	holderAlive                     // a holder that speaks our contract
	holderOther                     // someone listens, but not to us
)

// probe tells a stale socket from a living one the way dtach and abduco do:
// only a refused connection (or no socket) means nobody is there. A holder
// of another contract version answers and is alive, and must be reported,
// not replaced.
func probe(path string) (holderState, error) {
	c, _, _, err := dial(path)
	switch {
	case err == nil:
		_ = c.Close()
		return holderAlive, nil
	case refused(err), errors.Is(err, fs.ErrNotExist):
		return holderAbsent, nil
	default:
		return holderOther, err
	}
}

func (h *Holders) waitFor(path string) error {
	deadline := h.clock.Now().Add(spawnWait)
	for {
		if state, _ := probe(path); state == holderAlive {
			return nil
		}
		if h.clock.Now().After(deadline) {
			return fmt.Errorf("holder did not answer within %s", spawnWait)
		}
		<-h.clock.NewTimer(25*time.Millisecond, "holder-wait").C
	}
}

// Close drops the agent's connections. Holders and their shells live on:
// that is the point.
func (h *Holders) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, s := range h.sessions {
		s.close()
		delete(h.sessions, id)
	}
}

// SocketPath names shell id's socket. The id comes from the network, so it is
// hashed, never used as a path.
func SocketPath(runDir, id string) string {
	sum := sha256.Sum256([]byte("tilder/holder/" + id))
	return filepath.Join(runDir, hex.EncodeToString(sum[:8])+".sock")
}

// RunDir is where holder sockets live: <home>/run, or /tmp/tilder-<uid> when that
// path would pass the ~104-byte limit on a unix socket path (macOS).
func RunDir(home string) string {
	dir := filepath.Join(home, "run")
	if len(SocketPath(dir, "")) > 100 {
		return filepath.Join("/tmp", "tilder-"+strconv.Itoa(os.Getuid()))
	}
	return dir
}

// ExecSpawner starts `<this binary> hold …` in its own session, detached, so
// it outlives the agent: setsid spares it the agent's hangup, and it is never
// waited for.
// underSystemd says the agent runs as a systemd unit (see holderCommand).
func ExecSpawner(runDir string, underSystemd bool) Spawner {
	return func(id string, cols, rows uint16, dir string) error {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		return ExecSpawnerFor(self, runDir, underSystemd)(id, cols, rows, dir)
	}
}

// ExecSpawnerFor is ExecSpawner with an explicit binary (tests build one).
func ExecSpawnerFor(self, runDir string, underSystemd bool) Spawner {
	return func(id string, cols, rows uint16, dir string) error {
		name, args := holderCommand(self, runDir, id, cols, rows, dir, underSystemd)
		return startHolder(name, args)
	}
}

// startDetached starts cmd and reaps it when it exits. setsid does not change
// its parent: the agent is still the one to wait for it, or every holder that
// ended stays a zombie until the agent does. The waiter lives as long as the
// holder, which outlives any request; it is the process table's, not state.
func startDetached(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}

// holderCommand is how a holder starts. An agent run by systemd starts it in a scope of its own, as tmux does for its panes:
// setsid leaves a process in the agent's cgroup, which systemd empties when
// the agent's unit stops or restarts (ADR 0005, 0016). systemd-run --scope
// execs the command, so the holder is still the process started.
func holderCommand(self, runDir, id string, cols, rows uint16, dir string, underSystemd bool) (string, []string) {
	args := []string{"hold", "--run", runDir, "--id", id, "--cols", strconv.Itoa(int(cols)), "--rows", strconv.Itoa(int(rows))}
	if dir != "" {
		args = append(args, "--dir", dir)
	}
	if !underSystemd {
		return self, args
	}
	return "systemd-run", append([]string{"--user", "--scope", "--collect", "--quiet", "--", self}, args...)
}

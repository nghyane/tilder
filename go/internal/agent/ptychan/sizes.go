package ptychan

import (
	"sync"

	"github.com/nghyane/tilder/go/internal/holder"
)

// Sizes decides each shell's size among the clients attached to it (ADR
// 0033), as tmux's default window-size "latest" does: the client that typed
// last decides, and the others draw at that size. With one shell open on a
// laptop and a phone, the last resize winning squeezed the laptop's vim to
// the phone's width and the two fought over it.
//
// The agent decides, not the holder: every client's input and resizes reach
// a holder over one shared control connection, so only the agent knows
// which client sent them, and holders from an earlier build (ADR 0005) get
// the rule too.
type Sizes struct {
	// The mutex protects the following elements.
	mu     sync.Mutex
	shells map[string]*sizing // by shell id
}

// NewSizes is one agent's arbiter, shared by all its pty channels.
func NewSizes() *Sizes { return &Sizes{shells: map[string]*sizing{}} }

type size struct{ cols, rows uint16 }

// sizing is one shell's clients and the size it was last given.
type sizing struct {
	id string

	// mu orders one shell's resizes and is held while one is applied: a
	// resize waiting behind a paste the shell does not read holds up this
	// shell only. Lock order: sizing.mu, then Sizes.mu.
	// The mutex protects the following elements.
	mu      sync.Mutex
	shell   holder.Session
	seats   map[*seat]struct{}
	latest  *seat
	applied size
	// ticks orders the clients' activity, so the one active last takes over
	// when the latest leaves.
	ticks uint64
	gone  bool
}

// seat is one client of a shell.
type seat struct {
	owner *Sizes
	sz    *sizing
	// sizes carries the shell's size to this client, newest only.
	sizes chan size

	// Protected by sz.mu.
	want   size
	active uint64
}

// join seats a client that wants cols×rows. The first client of a shell
// decides its size; a later one only once it types or claims it, so opening
// a tab on the phone does not reflow the laptop's screen.
func (z *Sizes) join(id string, shell holder.Session, want size) *seat {
	for {
		z.mu.Lock()
		sz := z.shells[id]
		if sz == nil {
			sz = &sizing{id: id, seats: map[*seat]struct{}{}}
			z.shells[id] = sz
		}
		z.mu.Unlock()

		sz.mu.Lock()
		if sz.gone {
			sz.mu.Unlock()
			continue // its last client left as this one came: seat it afresh
		}
		st := &seat{owner: z, sz: sz, sizes: make(chan size, 1), want: want}
		sz.shell = shell
		sz.seats[st] = struct{}{}
		sz.touchLocked(st)
		if sz.latest == nil {
			sz.latest = st
		}
		if !sz.applyLocked(sz.latest.want) {
			st.tell(sz.applied) // unchanged: this client still needs to hear it
		}
		sz.mu.Unlock()
		return st
	}
}

// resize records the size the client's screen wants; it applies only if the
// client decides the shell's size. A client that does not is told the size
// the shell keeps: it takes its own ask as the shell's size until told
// otherwise (the console's follow.ts).
func (st *seat) resize(want size) {
	sz := st.sz
	sz.mu.Lock()
	defer sz.mu.Unlock()
	st.want = want
	if sz.latest == st {
		sz.applyLocked(want)
		return
	}
	st.tell(sz.applied)
}

// typed makes the client the one that decides, before its keystroke is
// written, so the program reads it at the size it will draw at. A client
// that already decides changes nothing (tmux's no-op): typing sends no
// resizes.
func (st *seat) typed() {
	sz := st.sz
	sz.mu.Lock()
	defer sz.mu.Unlock()
	sz.touchLocked(st)
	if sz.latest != st {
		sz.latest = st
		sz.applyLocked(st.want)
	}
}

// leave unseats the client; if it decided, the client active last takes over.
func (st *seat) leave() {
	sz := st.sz
	sz.mu.Lock()
	delete(sz.seats, st)
	if sz.latest == st {
		sz.latest = nil
		for other := range sz.seats {
			if sz.latest == nil || other.active > sz.latest.active {
				sz.latest = other
			}
		}
		if sz.latest != nil {
			sz.applyLocked(sz.latest.want)
		}
	}
	empty := len(sz.seats) == 0
	if empty {
		sz.gone = true
	}
	sz.mu.Unlock()
	if empty {
		z := st.owner
		z.mu.Lock()
		if z.shells[sz.id] == sz {
			delete(z.shells, sz.id)
		}
		z.mu.Unlock()
	}
}

// touchLocked marks st as the client active last.
// sz.mu must be held.
func (sz *sizing) touchLocked(st *seat) {
	sz.ticks++
	st.active = sz.ticks
}

// applyLocked gives the shell size want unless it already has it, and tells
// every client. It reports whether it told them.
// sz.mu must be held.
func (sz *sizing) applyLocked(want size) bool {
	if want == sz.applied || want.cols == 0 || want.rows == 0 {
		return false
	}
	if sz.shell.Resize(want.cols, want.rows) != nil {
		return false
	}
	sz.applied = want
	for st := range sz.seats {
		st.tell(want)
	}
	return true
}

// tell hands the client the size, replacing one it has not sent yet.
func (st *seat) tell(s size) {
	if s.cols == 0 || s.rows == 0 {
		return
	}
	select {
	case <-st.sizes:
	default:
	}
	st.sizes <- s
}

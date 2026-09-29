package ptychan

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/nghyane/tilder/go/internal/clock"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// Where says which folder a shell is in now (ADR 0024).
type Where struct {
	// Cwd is process pid's working directory (holder.WorkingDir).
	Cwd func(ctx context.Context, pid int) (string, error)
	// Home is the owner's home: a folder under it is said relative to it.
	Home  string
	Clock clock.Clock
}

// cwdEvery bounds the lookups: on macOS each one runs lsof.
const cwdEvery = 2 * time.Second

// tracker looks a shell's folder up when poked (after output), at most once
// every cwdEvery: at once if it has been quiet, else once the wait is over,
// so the folder a cd led to is never missed.
type tracker struct {
	want chan struct{}
	got  chan *tilderv1.PtyCwd
	done chan struct{}
}

func (w *Where) track(ctx context.Context, pid int) *tracker {
	t := &tracker{want: make(chan struct{}, 1), got: make(chan *tilderv1.PtyCwd, 1), done: make(chan struct{})}
	home := w.Home
	if real, err := filepath.EvalSymlinks(home); err == nil {
		home = real
	}
	go t.run(ctx, w, pid, home)
	t.poke() // where it is at the attach
	return t
}

func (t *tracker) run(ctx context.Context, w *Where, pid int, home string) {
	defer close(t.done)
	last := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.want:
		}
		lookup, cancel := context.WithTimeout(ctx, cwdEvery)
		dir, err := w.Cwd(lookup, pid)
		cancel()
		if err == nil && dir != last {
			last = dir
			select {
			case t.got <- place(home, dir):
			case <-ctx.Done():
				return
			}
		}
		wait := w.Clock.NewTimer(cwdEvery, "ptychan", "cwd")
		select {
		case <-ctx.Done():
			wait.Stop()
			return
		case <-wait.C:
		}
	}
}

func (t *tracker) poke() {
	select {
	case t.want <- struct{}{}:
	default: // one is already waiting
	}
}

// place says dir as the console takes it: relative to the home, or
// absolute and marked when it is outside (shown, never started in).
func place(home, dir string) *tilderv1.PtyCwd {
	rel, err := filepath.Rel(home, dir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return &tilderv1.PtyCwd{Dir: []byte(dir), OutsideHome: true}
	}
	if rel == "." {
		rel = ""
	}
	// The fs channel takes slash paths, whatever the machine's separator.
	return &tilderv1.PtyCwd{Dir: []byte(filepath.ToSlash(rel))}
}

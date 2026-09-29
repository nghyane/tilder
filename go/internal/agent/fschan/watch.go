package fschan

import (
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/coder/quartz"
	"github.com/fsnotify/fsnotify"

	"github.com/nghyane/tilder/go/internal/agent/files"
	"github.com/nghyane/tilder/go/internal/clock"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// Watch limits (ADR 0022, after Syncthing's watch aggregator): events are
// gathered for a moment and sent together; past perDir names in one batch
// the console reads the directory again instead.
const (
	gather      = 250 * time.Millisecond
	perDir      = 128
	maxWatches  = 16
	watchBuffer = 16
)

// watches are one channel's watched directories, over one fsnotify watcher
// made on the first watch.
type watches struct {
	s     *server
	clock clock.Clock

	// The mutex protects the following elements.
	mu     sync.Mutex
	w      *fsnotify.Watcher
	closed bool
	byDir  map[string]*watch
	byID   map[uint32]*watch
}

type watch struct {
	id     uint32
	dir    string
	names  map[string]struct{}
	rescan bool
	timer  *quartz.Timer
}

func newWatches(s *server, clk clock.Clock) *watches {
	return &watches{s: s, clock: clk, byDir: map[string]*watch{}, byID: map[uint32]*watch{}}
}

// add watches path for request id.
func (ws *watches) add(id uint32, path string) {
	real, err := ws.s.tree.WatchPath(path)
	if err != nil {
		ws.s.fail(id, err)
		return
	}
	ws.mu.Lock()
	defer ws.mu.Unlock()
	switch {
	case ws.closed:
		return
	case len(ws.byID) >= maxWatches:
		ws.s.fail(id, limit())
		return
	case ws.byID[id] != nil || ws.byDir[real] != nil:
		ws.s.fail(id, nil) // one watch per id, and per directory
		return
	}
	if ws.w == nil {
		w, werr := fsnotify.NewBufferedWatcher(watchBuffer)
		if werr != nil {
			ws.s.fail(id, limit())
			return
		}
		ws.w = w
		ws.s.wg.Go(func() { ws.run(w) })
	}
	if err := ws.w.Add(real); err != nil {
		ws.s.fail(id, limit()) // inotify out of watches (shared with other programs), or similar
		return
	}
	wt := &watch{id: id, dir: real, names: map[string]struct{}{}}
	ws.byDir[real], ws.byID[id] = wt, wt
	ws.s.send(id, &tilderv1.FsServer{Msg: &tilderv1.FsServer_Ok{Ok: &tilderv1.FsOk{}}})
}

func limit() error { return &files.Error{Code: files.WatchLimit} }

// remove stops the watch of request id.
func (ws *watches) remove(id uint32) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	wt := ws.byID[id]
	if wt == nil {
		return
	}
	delete(ws.byID, id)
	delete(ws.byDir, wt.dir)
	if wt.timer != nil {
		wt.timer.Stop()
	}
	if ws.w != nil {
		_ = ws.w.Remove(wt.dir)
	}
}

// close ends every watch; the channel is going.
func (ws *watches) close() {
	ws.mu.Lock()
	ws.closed = true
	w := ws.w
	for _, wt := range ws.byID {
		if wt.timer != nil {
			wt.timer.Stop()
		}
	}
	ws.byID, ws.byDir = map[uint32]*watch{}, map[string]*watch{}
	ws.mu.Unlock()
	if w != nil {
		_ = w.Close()
	}
}

// run turns the watcher's events into gathered FsChanged messages.
func (ws *watches) run(w *fsnotify.Watcher) {
	for {
		select {
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			ws.event(ev)
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			if errors.Is(err, fsnotify.ErrEventOverflow) {
				ws.lostEvents()
			}
		}
	}
}

func (ws *watches) event(ev fsnotify.Event) {
	// A change of permissions alone changes nothing the console shows.
	if ev.Op == fsnotify.Chmod {
		return
	}
	ws.mu.Lock()
	defer ws.mu.Unlock()
	if wt := ws.byDir[ev.Name]; wt != nil {
		wt.rescan = true // the watched directory itself went or moved
		ws.soonLocked(wt)
		return
	}
	wt := ws.byDir[filepath.Dir(ev.Name)]
	name := filepath.Base(ev.Name)
	if wt == nil || files.IsTemp(name) {
		return
	}
	if len(wt.names) >= perDir {
		wt.rescan = true
	} else {
		wt.names[name] = struct{}{}
	}
	ws.soonLocked(wt)
}

// lostEvents asks every watch for a full look: the kernel dropped events.
func (ws *watches) lostEvents() {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	for _, wt := range ws.byID {
		wt.rescan = true
		ws.soonLocked(wt)
	}
}

// soonLocked sends wt's gathered changes after the gathering window. ws.mu
// must be held.
func (ws *watches) soonLocked(wt *watch) {
	if wt.timer != nil {
		return
	}
	id := wt.id
	wt.timer = ws.clock.AfterFunc(gather, func() { ws.flush(id) }, "fschan", "gather")
}

func (ws *watches) flush(id uint32) {
	ws.mu.Lock()
	wt := ws.byID[id]
	if wt == nil {
		ws.mu.Unlock()
		return
	}
	changed := &tilderv1.FsChanged{Rescan: wt.rescan}
	if !wt.rescan {
		for n := range wt.names {
			changed.Names = append(changed.Names, []byte(n))
		}
	}
	wt.names, wt.rescan, wt.timer = map[string]struct{}{}, false, nil
	ws.mu.Unlock()
	ws.s.send(id, &tilderv1.FsServer{Msg: &tilderv1.FsServer_Changed{Changed: changed}})
}

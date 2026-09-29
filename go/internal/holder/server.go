package holder

import (
	"bufio"
	"errors"
	"net"
	"sync"

	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// Serve answers agents on ln for one shell until ln closes (the holder
// process's side of ADR 0005). Each connection says Hello, may Attach once
// (replay, then the stream), and may send input, resizes and a kill.
//
// When ln closes, Serve closes every connection before it waits for them: an
// agent keeps its control connection open for as long as it runs, so waiting
// for agents to hang up kept a holder alive long after its shell (dtach and
// abduco end with the shell whoever is connected).
func Serve(ln *net.UnixListener, shell *Shell, id string) error {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		conns = map[*net.UnixConn]struct{}{}
	)
	defer func() {
		mu.Lock()
		for c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	}()
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		if samePeer(c) != nil {
			_ = c.Close()
			continue
		}
		mu.Lock()
		conns[c] = struct{}{}
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveConn(c, shell, id)
			mu.Lock()
			delete(conns, c)
			mu.Unlock()
		}()
	}
}

func serveConn(c *net.UnixConn, shell *Shell, id string) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	var w sync.Mutex // the stream goroutine and replies share the socket
	write := func(e *tilderv1.HolderEvent) error {
		w.Lock()
		defer w.Unlock()
		return send(c, e)
	}

	first := &tilderv1.HolderRequest{}
	if receive(r, first) != nil || first.GetHello() == nil {
		return
	}
	welcome := &tilderv1.HolderWelcome{ContractVersion: ContractVersion, ShellId: id, Pid: int32(shell.Pid())} //nolint:gosec // G115: pids fit in int32
	if write(&tilderv1.HolderEvent{Msg: &tilderv1.HolderEvent_Welcome{Welcome: welcome}}) != nil {
		return
	}

	var viewer *Viewer
	defer func() {
		if viewer != nil {
			shell.Detach(viewer)
		}
	}()
	for {
		req := &tilderv1.HolderRequest{}
		if receive(r, req) != nil {
			return
		}
		switch m := req.GetMsg().(type) {
		case *tilderv1.HolderRequest_Attach:
			if viewer != nil {
				return // one attach per connection
			}
			replay, v := shell.Attach(m.Attach.GetSince())
			viewer = v
			if write(replayEvent(replay)) != nil {
				return
			}
			go stream(c, v, write)
		case *tilderv1.HolderRequest_Input:
			_ = shell.Input(m.Input.GetData())
		case *tilderv1.HolderRequest_Resize:
			_ = shell.Resize(clampSize(m.Resize.GetCols()), clampSize(m.Resize.GetRows()))
		case *tilderv1.HolderRequest_Kill:
			shell.Kill()
		default:
			// A newer agent's message: ignored, as on every wire.
		}
	}
}

// stream forwards a viewer's events. When the viewer is dropped (too slow)
// the connection closes and the agent re-attaches from its offset.
func stream(c net.Conn, v *Viewer, write func(*tilderv1.HolderEvent) error) {
	for e := range v.Events() {
		var ev *tilderv1.HolderEvent
		if e.Exited {
			ev = &tilderv1.HolderEvent{Msg: &tilderv1.HolderEvent_Exit{Exit: &tilderv1.Exit{Code: int32(e.Code)}}} //nolint:gosec // G115: exit codes fit in int32
		} else {
			ev = &tilderv1.HolderEvent{Msg: &tilderv1.HolderEvent_Output{Output: &tilderv1.Output{Seq: e.Seq, Data: e.Data}}}
		}
		if write(ev) != nil {
			break
		}
	}
	_ = c.Close()
}

func replayEvent(r Replay) *tilderv1.HolderEvent {
	return &tilderv1.HolderEvent{Msg: &tilderv1.HolderEvent_Replay{Replay: &tilderv1.HolderReplay{
		Data: r.Data, From: r.From, Lost: r.Lost, Exited: r.Exited, Code: int32(r.Code), //nolint:gosec // G115: exit codes fit in int32
		Screen: r.Screen, Cols: uint32(r.Cols), Rows: uint32(r.Rows),
	}}}
}

// clampSize keeps a terminal dimension a PTY accepts.
func clampSize(n uint32) uint16 {
	return uint16(min(max(n, 1), 1000)) //nolint:gosec // G115: clamped to 1000
}

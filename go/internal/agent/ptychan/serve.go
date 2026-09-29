// Package ptychan serves one shell over one message channel (a detached
// WebRTC DataChannel in production): the `pty` half of PROTOCOL §4.
package ptychan

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/files"
	"github.com/nghyane/tilder/go/internal/holder"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

const (
	readBuffer = 64 * 1024
	// Messages stay small: a machine's terminals share one connection (ADR
	// 0018), and Chrome does not interleave SCTP messages, so one large
	// message holds up every other terminal on it (Pion's JS build uses the
	// same 16 KiB as the browsers' common limit).
	maxChunk    = 16 * 1024
	screenChunk = 16 * 1024
	minWindow   = 16 * 1024
	maxWindow   = 1 << 20
)

// Shells is the part of holder.Manager a channel needs.
type Shells interface {
	OpenIn(id string, cols, rows uint16, dir func() (string, error)) (holder.Session, error)
}

// Dirs resolves where a new shell starts: a path under the home, as the fs
// channel takes it, to a real directory (files.Tree.DirPath).
type Dirs func(path string) (string, error)

var errNoAttach = errors.New("ptychan: the first message must be Attach")

// Serve attaches ch to a shell and runs until either side ends. The first
// message must be Attach; output then flows within the client's byte credit,
// and nothing is ever dropped: a client that stops acking stops receiving.
// sizes is shared by the agent's channels (ADR 0033); nil gives this channel
// its own, so its resizes always apply.
func Serve(ctx context.Context, ch io.ReadWriteCloser, shells Shells, dirs Dirs, where *Where, sizes *Sizes) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() { _ = ch.Close() }()

	buf := make([]byte, readBuffer)
	first, err := readMessage(ch, buf)
	if err != nil {
		return err
	}
	attach := first.GetAttach()
	if attach == nil {
		return errNoAttach
	}
	cols, rows := clampSize(attach.GetCols()), clampSize(attach.GetRows())
	shell, dirErr, err := open(shells, dirs, attach, cols, rows)
	if dirErr != nil {
		return refuse(ch, dirErr)
	}
	if err != nil {
		return err
	}
	replay, viewer := shell.Attach(attach.GetSince())
	defer func() { shell.Detach(viewer) }()
	// Seated after the attach, so the screen is taken at the size it was
	// drawn at: the emulator cuts lines when it shrinks, the client's xterm
	// reflows them. The shell's only client sizes it at once (a shell that
	// already ran would otherwise still draw for the last screen, as abduco
	// resizes on attach); with others attached it waits until it types.
	if sizes == nil {
		sizes = NewSizes()
	}
	seat := sizes.join(attach.GetShellId(), shell, size{cols, rows})
	defer seat.leave()

	out := &sender{ch: ch, window: clampWindow(attach.GetWindow()), acks: make(chan uint64, 1)}
	// The screen, not the history, when the client starts afresh; when what
	// it asks for is gone (the ring wrapped: bytes from a cut would land
	// mid-escape); and when it asks beyond the end, which only a new shell
	// under its id explains (the machine restarted): counting from 0, its
	// bytes would look to the client like ones it has, and be dropped.
	fresh := len(replay.Screen) > 0 &&
		(attach.GetSince() == 0 || replay.Lost > 0 || attach.GetSince() > replay.From)
	start := replay.From
	if fresh {
		start = replay.ScreenEnd() // the screen stands for everything before
	}
	out.sent, out.acked = start, start
	reading := make(chan struct{})
	go func() {
		defer close(reading)
		readLoop(ctx, cancel, ch, buf, shell, seat, out.acks)
	}()
	// The reader ends before the seat is left and the shell detached: a
	// message read late must not count a client that has gone.
	defer func() {
		cancel()
		_ = ch.Close()
		<-reading
	}()

	if fresh {
		// A client starting afresh gets the screen, not the history (ADR
		// 0017). A holder of contract 1 sends no screen: history as before.
		if err := out.screen(replay); err != nil {
			return err
		}
	} else {
		out.replaying = true // history the client asked for, not output happening now
		if err := out.output(ctx, replay.From, replay.Data); err != nil {
			return err
		}
		out.replaying = false
	}
	if replay.Exited {
		return out.exit(replay.Code)
	}
	var cwds <-chan *tilderv1.PtyCwd
	poke := func() {}
	if where != nil && where.Cwd != nil && where.Clock != nil && shell.Pid() > 0 {
		t := where.track(ctx, shell.Pid())
		defer func() {
			cancel()
			<-t.done // a lookup in flight ends with ctx; nothing outlives the channel
		}()
		cwds, poke = t.got, t.poke
	}
	return out.stream(ctx, shell, &viewer, seat.sizes, cwds, poke)
}

// stream sends the shell's output as it comes, and its folder when that
// changes; after output the folder is looked up again (poke). *viewer is
// replaced when the holder drops a slow one, so the caller detaches the
// right one.
func (s *sender) stream(ctx context.Context, shell holder.Session, viewer **holder.Viewer, sizes <-chan size, cwds <-chan *tilderv1.PtyCwd, poke func()) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case sz := <-sizes:
			msg := &tilderv1.PtyServer{Msg: &tilderv1.PtyServer_Size{Size: &tilderv1.Resize{Cols: uint32(sz.cols), Rows: uint32(sz.rows)}}}
			if err := write(s.ch, msg); err != nil {
				return err
			}
		case c := <-cwds:
			if err := write(s.ch, &tilderv1.PtyServer{Msg: &tilderv1.PtyServer_Cwd{Cwd: c}}); err != nil {
				return err
			}
		case e, ok := <-(*viewer).Events():
			switch {
			case !ok:
				// The holder dropped this viewer for falling behind while we
				// waited for credit. The ring is the source of truth: take up
				// again from what was sent, without the client ever noticing
				// (a gap beyond the ring shows up as a jump in Seq).
				var replay holder.Replay
				replay, *viewer = shell.Attach(s.sent)
				if err := s.output(ctx, replay.From, replay.Data); err != nil {
					return err
				}
				if replay.Exited {
					return s.exit(replay.Code)
				}
			case e.Exited:
				return s.exit(e.Code)
			default:
				if err := s.output(ctx, e.Seq, e.Data); err != nil {
					return err
				}
				poke()
			}
		}
	}
}

// inputQueue is how many keystroke messages wait for a program that is not
// reading: 4 MiB of the console's 16 KiB pieces.
const inputQueue = 256

// readLoop applies the client's keystrokes, resizes and acks until the
// channel ends. Keystrokes go to the shell on a goroutine of their own: a
// write waits while the program does not read, and Kill, acks and resizes
// must not wait behind it (closing the tab would leave the shell living,
// ADR 0014).
func readLoop(ctx context.Context, cancel context.CancelFunc, ch io.Reader, buf []byte, shell holder.Session, seat *seat, acks chan uint64) {
	defer cancel()
	typed := make(chan []byte, inputQueue)
	// Not waited for: a write stuck on a program that never reads cannot be
	// cancelled, and ends only when the shell reads or exits (Kill). The
	// channel's other goroutines, and the agent's Close, must not hang on it.
	go typeInto(ctx, shell, typed)
	defer close(typed)
	for ctx.Err() == nil {
		msg, err := readMessage(ch, buf)
		if err != nil {
			return
		}
		switch m := msg.GetMsg().(type) {
		case *tilderv1.PtyClient_Input:
			seat.typed()
			select {
			case typed <- m.Input.GetData():
			case <-ctx.Done():
				return
			}
		case *tilderv1.PtyClient_Resize:
			seat.resize(size{clampSize(m.Resize.GetCols()), clampSize(m.Resize.GetRows())})
		case *tilderv1.PtyClient_Claim:
			seat.typed()
		case *tilderv1.PtyClient_Ack:
			latest(acks, m.Ack.GetSeq())
		case *tilderv1.PtyClient_Kill:
			// The tab was closed (ADR 0014). The shell's exit reaches the
			// client through the output loop, which then ends the channel.
			shell.Kill()
		default:
			// A newer client's message this build does not know: ignored (PROTOCOL §1).
		}
	}
}

// typeInto writes the client's keystrokes, in order, until the channel ends.
// A write that fails (the shell exited, killed) stops the typing only: the
// exit reaches the client through the output loop, which then ends the
// channel; ending it here raced that and lost the exit.
func typeInto(ctx context.Context, shell holder.Session, typed <-chan []byte) {
	failed := false
	for data := range typed {
		if failed || ctx.Err() != nil {
			continue // what is left is not typed
		}
		failed = shell.Input(data) != nil
	}
}

// latest keeps only the newest ack: acks are cumulative, older ones add nothing.
func latest(acks chan uint64, seq uint64) {
	select {
	case <-acks:
	default:
	}
	acks <- seq
}

type sender struct {
	ch     io.Writer
	window uint64
	acks   chan uint64
	sent   uint64 // offset after the last byte sent
	acked  uint64 // everything before this is on the client's screen
	// replaying marks the attach catch-up (ADR 0015).
	replaying bool
}

// output sends data (starting at offset seq) in chunks, waiting for credit.
func (s *sender) output(ctx context.Context, seq uint64, data []byte) error {
	for len(data) > 0 {
		for s.sent-s.acked >= s.window {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ack := <-s.acks:
				if ack > s.acked && ack <= s.sent {
					s.acked = ack
				}
			}
		}
		n := min(uint64(len(data)), maxChunk, s.window-(s.sent-s.acked))
		msg := &tilderv1.PtyServer{Msg: &tilderv1.PtyServer_Output{Output: &tilderv1.Output{Seq: seq, Data: data[:n], Replay: s.replaying}}}
		if err := write(s.ch, msg); err != nil {
			return err
		}
		seq += n
		s.sent = seq
		data = data[n:]
	}
	return nil
}

// screen sends a snapshot in parts of at most screenChunk. It holds no
// offsets, so it is not metered by the window; maxScreen bounds it.
func (s *sender) screen(r holder.Replay) error {
	data := r.Screen
	first := true
	for first || len(data) > 0 {
		n := min(len(data), screenChunk)
		part := &tilderv1.Screen{Data: data[:n], Seq: s.sent, Last: n == len(data)}
		if first {
			part.Cols, part.Rows = uint32(r.Cols), uint32(r.Rows)
		}
		if err := write(s.ch, &tilderv1.PtyServer{Msg: &tilderv1.PtyServer_Screen{Screen: part}}); err != nil {
			return err
		}
		data, first = data[n:], false
	}
	return nil
}

func (s *sender) exit(code int) error {
	return write(s.ch, &tilderv1.PtyServer{Msg: &tilderv1.PtyServer_Exit{Exit: &tilderv1.Exit{Code: int32(code)}}}) //nolint:gosec // G115: exit codes fit in int32
}

// open opens the shell attach names. Its folder is looked up only if a
// shell starts; a folder refused comes back apart (dirErr), to be said to the
// client with a stable code, never swapped for the home (ADR 0024).
func open(shells Shells, dirs Dirs, attach *tilderv1.Attach, cols, rows uint16) (s holder.Session, dirErr, err error) {
	var dir func() (string, error)
	if path := attach.GetDir(); len(path) > 0 {
		dir = func() (string, error) {
			if dirs == nil {
				dirErr = &files.Error{Code: files.Denied}
				return "", dirErr
			}
			d, derr := dirs(string(path))
			dirErr = derr
			return d, derr
		}
	}
	s, err = shells.OpenIn(attach.GetShellId(), cols, rows, dir)
	return s, dirErr, err
}

// refuse tells the client why its shell did not start. Anything but the
// codes it knows is Denied: a check that fails never lets the shell through.
func refuse(ch io.Writer, err error) error {
	code := tilderv1.PtyRefused_CODE_DENIED
	switch files.CodeOf(err) {
	case files.NotFound:
		code = tilderv1.PtyRefused_CODE_NOT_FOUND
	case files.NotDir:
		code = tilderv1.PtyRefused_CODE_NOT_DIR
	case files.Invalid:
		code = tilderv1.PtyRefused_CODE_INVALID
	default:
	}
	if werr := write(ch, &tilderv1.PtyServer{Msg: &tilderv1.PtyServer_Refused{Refused: &tilderv1.PtyRefused{Code: code}}}); werr != nil {
		return werr
	}
	return fmt.Errorf("ptychan: start a shell in the folder asked for: %w", err)
}

func readMessage(ch io.Reader, buf []byte) (*tilderv1.PtyClient, error) {
	n, err := ch.Read(buf)
	if err != nil {
		return nil, err
	}
	msg := &tilderv1.PtyClient{}
	if err := proto.Unmarshal(buf[:n], msg); err != nil {
		return nil, fmt.Errorf("ptychan: malformed message: %w", err)
	}
	return msg, nil
}

func write(ch io.Writer, msg proto.Message) error {
	frame, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = ch.Write(frame)
	return err
}

func clampWindow(w uint32) uint64 { return uint64(min(max(w, minWindow), maxWindow)) }

// clampSize keeps a terminal dimension to what a PTY accepts.
func clampSize(v uint32) uint16 { return uint16(min(max(v, 1), 1000)) } //nolint:gosec // G115: clamped to 1..1000

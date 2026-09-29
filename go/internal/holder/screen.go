package holder

import (
	"fmt"
	"io"
	"strings"

	uv "github.com/charmbracelet/ultraviolet"
	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
)

// ScrollbackLines is how much history a snapshot carries above the screen
// (VS Code's pty host keeps 100).
const ScrollbackLines = 1000

// maxScreen bounds a snapshot: output that changes colour on every cell can
// make 1000 lines of history many megabytes. The oldest history goes first.
const maxScreen = 4 << 20

// snapshotModes are the modes a snapshot restores: they change what keys
// and the mouse send, and whether the cursor shows. The alternate screen is
// restored by drawing it, not listed here.
var snapshotModes = []ansi.DECMode{
	ansi.ModeCursorKeys, ansi.ModeAutoWrap, ansi.ModeTextCursorEnable, ansi.ModeNumericKeypad,
	ansi.ModeMouseX10, ansi.ModeMouseNormal, ansi.ModeMouseHighlight, ansi.ModeMouseButtonEvent,
	ansi.ModeMouseAnyEvent, ansi.ModeFocusEvent, ansi.ModeMouseExtSgr, ansi.ModeBracketedPaste,
}

// screen is the terminal as the shell has drawn it (ADR 0017): every byte
// the PTY prints goes through it, so an attach gets the screen, not a replay
// of history that was drawn at another size or has scrolled out of the ring.
// It is not safe for concurrent use; the shell's lock guards it.
type screen struct {
	emu   *vt.Emulator
	modes map[ansi.DECMode]bool
}

func newScreen(cols, rows uint16) *screen {
	s := &screen{emu: vt.NewEmulator(int(cols), int(rows)), modes: map[ansi.DECMode]bool{}}
	s.emu.SetScrollbackSize(ScrollbackLines)
	for _, m := range snapshotModes {
		s.modes[m] = m == ansi.ModeAutoWrap || m == ansi.ModeTextCursorEnable // the defaults
	}
	s.emu.SetCallbacks(vt.Callbacks{
		EnableMode:  func(m ansi.Mode) { s.track(m, true) },
		DisableMode: func(m ansi.Mode) { s.track(m, false) },
	})
	// The emulator writes its answers to terminal queries into a pipe, and
	// its Write blocks until someone reads them. The browser answers the
	// real queries; these are read and dropped.
	go func(r io.Reader) { _, _ = io.Copy(io.Discard, r) }(s.emu)
	return s
}

func (s *screen) track(m ansi.Mode, on bool) {
	if d, ok := m.(ansi.DECMode); ok {
		if _, kept := s.modes[d]; kept {
			s.modes[d] = on
		}
	}
}

func (s *screen) write(p []byte) { _, _ = s.emu.Write(p) }

func (s *screen) resize(cols, rows uint16) { s.emu.Resize(int(cols), int(rows)) }

func (s *screen) size() (cols, rows uint16) {
	return uint16(s.emu.Width()), uint16(s.emu.Height()) //nolint:gosec // G115: sizes come from uint16
}

// close ends the query drain. It closes the pipe, not the emulator: the
// emulator's Close sets a flag its Read reads without a lock.
func (s *screen) close() {
	if pw, ok := s.emu.InputPipe().(*io.PipeWriter); ok {
		_ = pw.Close()
	}
}

// snapshot draws the screen into a reset terminal of the same size, in the
// order xterm's SerializeAddon does: history, the normal screen, the
// alternate screen if it is up, the cursor, then the modes.
//
// While the alternate screen is up the normal screen's cells cannot be read
// (x/vt has no accessor), so only its history is drawn: after vim quits the
// shell's last screenful is missing until the shell redraws.
func (s *screen) snapshot() []byte {
	var b strings.Builder
	b.WriteString("\x1bc") // RIS: nothing of the old screen survives
	lines := make([]string, 0, s.emu.ScrollbackLen()+s.emu.Height())
	if sb := s.emu.Scrollback(); sb != nil {
		for _, l := range sb.Lines() {
			lines = append(lines, l.Render())
		}
	}
	alt := s.emu.IsAltScreen()
	var screen []string
	if alt {
		screen = s.rows()
	} else {
		lines = append(lines, s.rows()...)
	}
	size := 0
	for _, l := range append(lines, screen...) {
		size += len(l) + 2
	}
	history := len(lines) - s.emu.Height()
	if alt {
		history = len(lines)
	}
	for drop := 0; size > maxScreen && drop < history; drop++ {
		size -= len(lines[0]) + 2
		lines = lines[1:]
	}
	if size > maxScreen {
		lines, screen = fitted(lines, screen)
	}
	b.WriteString(strings.Join(lines, "\r\n"))
	if alt {
		b.WriteString(ansi.SetMode(ansi.ModeAltScreenSaveCursor) + "\x1b[H")
		for y, row := range screen {
			fmt.Fprintf(&b, "\x1b[%d;1H%s", y+1, row)
		}
	}
	cur := s.emu.CursorPosition()
	fmt.Fprintf(&b, "\x1b[%d;%dH", cur.Y+1, cur.X+1)
	for _, m := range snapshotModes {
		if s.modes[m] {
			b.WriteString(ansi.SetMode(m))
		} else {
			b.WriteString(ansi.ResetMode(m))
		}
	}
	return []byte(b.String())
}

// fitted brings what is left once every history line is gone under
// maxScreen: the rows' text without its styles, then each row cut short.
// Only the visible rows (and the alternate screen) are left by then, and at
// 1000 × 1000 cells, each in its own colour, they came to ~30 MB: past the
// wire's frame, so a living shell was reported gone at every attach.
func fitted(lines, screen []string) ([]string, []string) {
	plain := func(rows []string) []string {
		out := make([]string, len(rows))
		for i, r := range rows {
			out[i] = ansi.Strip(r)
		}
		return out
	}
	lines, screen = plain(lines), plain(screen)
	size := 0
	for _, l := range append(lines, screen...) {
		size += len(l) + 2
	}
	if size <= maxScreen {
		return lines, screen
	}
	per := maxScreen/(len(lines)+len(screen)) - 2
	cut := func(rows []string) {
		for i, r := range rows {
			if len(r) > per {
				rows[i] = strings.ToValidUTF8(r[:per], "")
			}
		}
	}
	cut(lines)
	cut(screen)
	return lines, screen
}

// rows renders the active screen, one styled string per row.
func (s *screen) rows() []string {
	w, h := s.emu.Width(), s.emu.Height()
	out := make([]string, h)
	line := make(uv.Line, w)
	for y := range h {
		for x := range w {
			if c := s.emu.CellAt(x, y); c != nil {
				line[x] = *c
			} else {
				line[x] = uv.Cell{}
			}
		}
		out[y] = line.Render()
	}
	return out
}

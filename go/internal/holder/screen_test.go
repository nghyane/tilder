//go:build unix

package holder

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/charmbracelet/x/vt"
)

// replayed draws a snapshot into a fresh terminal of the same size, as the
// browser does, and returns that terminal and its tracked modes.
func replayed(t *testing.T, s *screen) *screen {
	t.Helper()
	cols, rows := s.size()
	again := newScreen(cols, rows)
	t.Cleanup(again.close)
	again.write(s.snapshot())
	return again
}

func sameCells(t *testing.T, want, got *screen) {
	t.Helper()
	if want.emu.IsAltScreen() != got.emu.IsAltScreen() {
		t.Fatalf("alternate screen %v, want %v", got.emu.IsAltScreen(), want.emu.IsAltScreen())
	}
	w, h := want.emu.Width(), want.emu.Height()
	for y := range h {
		for x := range w {
			a, b := want.emu.CellAt(x, y), got.emu.CellAt(x, y)
			if a.Content != b.Content || a.Width != b.Width || !a.Style.Equal(&b.Style) {
				t.Fatalf("cell %d,%d is %q %+v, want %q %+v", x, y, b.Content, b.Style, a.Content, a.Style)
			}
		}
	}
	if want.emu.CursorPosition() != got.emu.CursorPosition() {
		t.Fatalf("cursor at %v, want %v", got.emu.CursorPosition(), want.emu.CursorPosition())
	}
}

func TestASnapshotRedrawsTheSameScreen(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		out  string
	}{
		{"plain lines", "hello\r\nworld\r\n$ "},
		{"colours and attributes", "\x1b[1;31mred bold\x1b[0m \x1b[38;2;10;20;30;48;5;200mtrue\x1b[0m\r\n\x1b[4munder\x1b[0m"},
		{"Vietnamese and wide characters", "xin chào thế giới\r\n日本語 😀 ok\r\n"},
		{"a background that runs to the edge", "\x1b[44m    \x1b[0m\r\n"},
		{"scrolled past the screen", strings.Repeat("line\r\n", 30) + "last"},
		{"cursor in the middle", "abc\r\ndef\x1b[1;2H"},
		{"a full-screen program", "shell prompt\r\n\x1b[?1049h\x1b[2J\x1b[H\x1b[7m top bar \x1b[0m\x1b[5;3Hbody\x1b[3;4H"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := newScreen(20, 6)
			defer s.close()
			s.write([]byte(tc.out))
			sameCells(t, s, replayed(t, s))
		})
	}
}

// Keys and the mouse send what the program asked for: a snapshot that lost
// application cursor keys made arrows in vim type letters.
func TestASnapshotRestoresTheModesThatChangeInput(t *testing.T) {
	t.Parallel()
	s := newScreen(20, 6)
	defer s.close()
	s.write([]byte("\x1b[?1h\x1b[?2004h\x1b[?1000h\x1b[?1006h\x1b[?25l"))
	got := replayed(t, s)
	for _, m := range []ansi.DECMode{ansi.ModeCursorKeys, ansi.ModeBracketedPaste, ansi.ModeMouseNormal, ansi.ModeMouseExtSgr} {
		if !got.modes[m] {
			t.Errorf("mode %d lost", m)
		}
	}
	if got.modes[ansi.ModeTextCursorEnable] {
		t.Error("a hidden cursor came back visible")
	}
}

// History is kept, up to ScrollbackLines, whatever the ring still holds.
func TestASnapshotCarriesTheHistoryAboveTheScreen(t *testing.T) {
	t.Parallel()
	s := newScreen(20, 4)
	defer s.close()
	for i := range ScrollbackLines + 50 {
		s.write([]byte("n" + strings.Repeat("x", i%7) + "\r\n"))
	}
	got := replayed(t, s)
	if got.emu.ScrollbackLen() != s.emu.ScrollbackLen() || s.emu.ScrollbackLen() != ScrollbackLines {
		t.Fatalf("history %d lines, want %d (kept %d)", got.emu.ScrollbackLen(), ScrollbackLines, s.emu.ScrollbackLen())
	}
}

// The emulator answers queries into a pipe; nothing may block on it.
func TestQueriesDoNotBlockTheScreen(t *testing.T) {
	t.Parallel()
	s := newScreen(20, 4)
	defer s.close()
	for range 100 {
		s.write([]byte("\x1b[6n\x1b[c\x1b[?2004$p")) // cursor position, device attributes, mode report
	}
	var _ vt.Terminal = s.emu
}

// Output that changes colour on every cell makes history heavy; a snapshot
// stays within maxScreen by dropping the oldest lines, never the screen.
func TestASnapshotStaysWithinItsBound(t *testing.T) {
	t.Parallel()
	s := newScreen(400, 10)
	defer s.close()
	var line strings.Builder
	for i := range 400 {
		fmt.Fprintf(&line, "\x1b[38;2;%d;%d;%d;48;2;%d;%d;%dm#", i%256, 255-i%256, i/2, i/3, i%7, 255-i/2)
	}
	for range ScrollbackLines + 10 {
		s.write([]byte(line.String() + "\r\n"))
	}
	s.write([]byte("\x1b[0mbottom"))
	snap := s.snapshot()
	if len(snap) > maxScreen+64*1024 {
		t.Fatalf("snapshot of %d bytes, bound %d", len(snap), maxScreen)
	}
	if !strings.Contains(string(snap), "bottom") {
		t.Fatal("the screen itself was dropped")
	}
}

// A screen alone past the bound (1000 × 1000 cells, each its own colour,
// the largest size a client may ask for) is sent as plain text, then cut:
// ~30 MB went past the wire's frame and a living shell was reported gone.
func TestAHugeColouredScreenStaysWithinItsBound(t *testing.T) {
	t.Parallel()
	for _, alt := range []bool{false, true} {
		s := newScreen(1000, 1000)
		if alt {
			s.write([]byte(ansi.SetMode(ansi.ModeAltScreenSaveCursor)))
		}
		var line strings.Builder
		for i := range 1000 {
			fmt.Fprintf(&line, "\x1b[38;2;%d;%d;%d;48;2;%d;%d;%dm#", i%256, 255-i%256, i/4, i/5, i%7, 255-i/4)
		}
		for range 1000 {
			s.write([]byte(line.String() + "\r\n"))
		}
		snap := s.snapshot()
		s.close()
		if len(snap) > maxScreen+64*1024 {
			t.Fatalf("alt=%v: snapshot of %d bytes, bound %d", alt, len(snap), maxScreen)
		}
		if !strings.Contains(string(snap), "####") {
			t.Fatalf("alt=%v: the screen's text was lost", alt)
		}
	}
}

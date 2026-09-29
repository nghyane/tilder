package ptychan

import (
	"slices"
	"sync"
	"testing"

	"github.com/nghyane/tilder/go/internal/holder"
)

// recorder is a shell that remembers the sizes it was given.
type recorder struct {
	holder.Session

	// The mutex protects the following elements.
	mu      sync.Mutex
	resizes []size
}

func (r *recorder) Resize(cols, rows uint16) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resizes = append(r.resizes, size{cols, rows})
	return nil
}

func (r *recorder) got() []size {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.resizes)
}

// heard is the last size a client was told, or zero.
func heard(st *seat) size {
	select {
	case s := <-st.sizes:
		return s
	default:
		return size{}
	}
}

var (
	laptop = size{200, 50}
	phone  = size{45, 30}
)

func TestTheClientThatTypedLastDecidesTheShellsSize(t *testing.T) {
	t.Parallel()
	shell := &recorder{}
	z := NewSizes()

	lap := z.join("s", shell, laptop)
	ph := z.join("s", shell, phone)
	// Opening the tab on the phone does not reflow the laptop's screen.
	if got := shell.got(); !slices.Equal(got, []size{laptop}) {
		t.Fatalf("after the phone opened the tab the shell was sized %v, want only the laptop's %v", got, laptop)
	}
	if got := heard(ph); got != laptop {
		t.Fatalf("the phone heard %v, want the shell's size %v", got, laptop)
	}
	_ = heard(lap)

	// The phone types: it decides, and the laptop hears the new size.
	ph.typed()
	ph.typed() // already deciding: no second resize
	if got := shell.got(); !slices.Equal(got, []size{laptop, phone}) {
		t.Fatalf("resizes %v, want the laptop's then the phone's once", got)
	}
	if got := heard(lap); got != phone {
		t.Fatalf("the laptop heard %v, want %v", got, phone)
	}

	// The laptop's window grows while the phone decides: noted, not applied.
	wider := size{220, 50}
	lap.resize(wider)
	if got := len(shell.got()); got != 2 {
		t.Fatalf("a resize from the client that does not decide was applied (%d resizes)", got)
	}
	// It types again: its size as it is now.
	lap.typed()
	if got := shell.got(); got[len(got)-1] != wider {
		t.Fatalf("after the laptop typed the shell is %v, want %v", got[len(got)-1], wider)
	}
}

func TestWhenTheDecidingClientLeavesTheOneActiveLastTakesOver(t *testing.T) {
	t.Parallel()
	shell := &recorder{}
	z := NewSizes()
	lap := z.join("s", shell, laptop)
	tab := z.join("s", shell, size{120, 40})
	ph := z.join("s", shell, phone)
	lap.typed()
	tab.typed() // the tablet was active after the laptop
	ph.typed()
	ph.leave()
	if got := shell.got(); got[len(got)-1] != (size{120, 40}) {
		t.Fatalf("after the phone left the shell is %v, want the tablet's", got[len(got)-1])
	}
	tab.leave()
	lap.leave()
	z.mu.Lock()
	defer z.mu.Unlock()
	if len(z.shells) != 0 {
		t.Fatalf("a shell with no clients is still tracked")
	}
}

func TestShellsAreSizedApart(t *testing.T) {
	t.Parallel()
	a, b := &recorder{}, &recorder{}
	z := NewSizes()
	z.join("a", a, laptop)
	z.join("b", b, phone).typed()
	if !slices.Equal(a.got(), []size{laptop}) || !slices.Equal(b.got(), []size{phone}) {
		t.Fatalf("a %v, b %v: one shell's clients sized another", a.got(), b.got())
	}
}

// A client that does not decide, asking for a size, is told the size the
// shell keeps: it takes its own ask as the shell's size at once (a size told
// back late was mistaken for another device's, and the terminal jumped for
// ever), so it must hear when that ask did not apply.
func TestAClientThatDoesNotDecideHearsTheSizeKept(t *testing.T) {
	t.Parallel()
	shell := &recorder{}
	z := NewSizes()
	lap := z.join("s", shell, laptop)
	ph := z.join("s", shell, phone)
	heard(lap)
	heard(ph)
	ph.resize(size{50, 30}) // the phone's window changed; the laptop decides
	if got := heard(ph); got != laptop {
		t.Fatalf("the phone heard %v, want the laptop's size it keeps", got)
	}
	if got := shell.got(); got[len(got)-1] != laptop {
		t.Fatalf("the shell was resized to %v by a client that does not decide", got[len(got)-1])
	}
	lap.leave()
	ph.leave()
}

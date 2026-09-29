//go:build unix

package holder_test

import (
	"testing"

	"github.com/nghyane/tilder/go/internal/holder"
)

func TestTheRingReplaysByByteOffset(t *testing.T) {
	t.Parallel()
	r := holder.NewRing(8)
	r.Write([]byte("xin chào")) // 9 bytes: "à" is two
	data, from, lost := r.Since(0)
	if string(data) != "in chào" || from != 1 || lost != 1 {
		t.Fatalf("since 0: %q from %d lost %d", data, from, lost)
	}
	data, from, lost = r.Since(4)
	if string(data) != "chào" || from != 4 || lost != 0 {
		t.Fatalf("since 4: %q from %d lost %d", data, from, lost)
	}
	if data, from, _ := r.Since(99); data != nil || from != r.End() {
		t.Fatalf("since past the end: %q from %d", data, from)
	}
}

// Package testutil holds the helpers every tilder test uses: standard timeouts
// (no magic numbers in tests), a context bound to the test, and the goleak
// options shared by each package's TestMain.
package testutil

import (
	"context"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// Standard timeouts. Tests run on a mock clock, so these bound only real
// scheduling, never protocol behaviour.
const (
	WaitShort  = 10 * time.Second
	WaitMedium = 20 * time.Second
)

// Context returns a context cancelled after d or when the test ends.
func Context(t testing.TB, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// GoleakOptions lists goroutines known to outlive tests on purpose.
var GoleakOptions = []goleak.Option{}

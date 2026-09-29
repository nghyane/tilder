// Package clock is the only place in tilder that touches the wall clock.
//
// Everything that waits, expires or stamps a time takes a Clock, so tests run
// on a mock that advances instantly and can trap named timers
// (github.com/coder/quartz). Lint forbids time.Now and time.Sleep elsewhere.
package clock

import "github.com/coder/quartz"

// Clock is the time source every subsystem receives.
type Clock = quartz.Clock

// Real returns the wall clock. Only cmd/ calls it.
func Real() Clock { return quartz.NewReal() }

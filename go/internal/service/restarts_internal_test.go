package service

import (
	"testing"
	"time"
)

// An agent that dies at once is started four times, not forever; one that
// ran a while is started again.
func TestTheMonitorStopsRestartingAnAgentThatCannotRun(t *testing.T) {
	t.Parallel()
	var r restarts
	now := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	for i := range 4 {
		if !r.allow(now.Add(time.Duration(i) * 5 * time.Second)) {
			t.Fatalf("start %d refused", i+1)
		}
	}
	if r.allow(now.Add(20 * time.Second)) {
		t.Fatal("a fifth start within a minute was allowed")
	}
	if !r.allow(now.Add(2 * time.Minute)) {
		t.Fatal("a start after a quiet minute was refused")
	}
}

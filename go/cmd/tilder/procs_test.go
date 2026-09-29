package main

import "testing"

// ADR 0039: the agent runs its Go code on two threads at most; with one per
// core a copy cost twice the CPU and ran slower.
func TestTheAgentRunsOnTwoThreadsAtMost(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		current int
		env     string
		want    int
	}{
		{"a ten-core Mac", 10, "", 2},
		{"a two-core VPS", 2, "", 2},
		{"a one-core VPS", 1, "", 1},
		{"the owner's GOMAXPROCS wins", 8, "8", 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := procsFor(tc.current, tc.env); got != tc.want {
				t.Fatalf("procsFor(%d, %q) = %d, want %d", tc.current, tc.env, got, tc.want)
			}
		})
	}
}

package main

// agentProcs is how many threads run the agent's Go code at once (ADR 0039).
// Pion hands every ~1.2 KB packet between goroutines; with one thread per
// core the runtime spent more time waking idle threads than moving bytes:
// a 512 MiB copy took 2.8 cores at ~110 MiB/s, and 1.5 cores at ~150 MiB/s
// with two, terminals as quick or quicker. One was cheaper still but put
// ~30 ms on every keystroke during a copy.
const agentProcs = 2

// procsFor is the GOMAXPROCS the agent runs with: never more than
// agentProcs, fewer on a smaller machine, and whatever the owner set in the
// GOMAXPROCS environment variable.
func procsFor(current int, env string) int {
	if env != "" || current <= agentProcs {
		return current
	}
	return agentProcs
}

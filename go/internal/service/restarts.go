package service

import "time"

// restarts is the Windows monitor's guard against a restart loop, as
// Syncthing's monitor keeps one: a fifth start within a minute of the first
// of the last four means the agent cannot run, and the monitor stops rather
// than spin (systemd's StartLimitBurst does this on Linux).
type restarts struct{ at [4]time.Time }

// allow records a start at now, or says there have been too many.
func (r *restarts) allow(now time.Time) bool {
	if !r.at[0].IsZero() && now.Sub(r.at[0]) < time.Minute {
		return false
	}
	copy(r.at[:], r.at[1:])
	r.at[len(r.at)-1] = now
	return true
}

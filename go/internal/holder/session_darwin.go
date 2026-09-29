package holder

import "golang.org/x/sys/unix"

// sessionGroups lists the process groups of every process in session sid.
// An interactive shell puts each job in its own group, so signalling only
// the shell's group misses them; the session is what the shell owns.
func sessionGroups(sid int) []int {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil
	}
	seen := map[int]bool{}
	var groups []int
	for _, p := range procs {
		pid := int(p.Proc.P_pid)
		if s, err := unix.Getsid(pid); err != nil || s != sid {
			continue
		}
		pgrp, err := unix.Getpgid(pid)
		if err != nil || seen[pgrp] {
			continue
		}
		seen[pgrp] = true
		groups = append(groups, pgrp)
	}
	return groups
}

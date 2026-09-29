package holder

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// sessionGroups lists the process groups of every process in session sid.
// An interactive shell puts each job in its own group, so signalling only
// the shell's group misses them; the session is what the shell owns.
func sessionGroups(sid int) []int {
	stats, _ := filepath.Glob("/proc/[0-9]*/stat")
	seen := map[int]bool{}
	var groups []int
	for _, path := range stats {
		raw, err := os.ReadFile(path) //nolint:gosec // G304: /proc paths from a glob
		if err != nil {
			continue
		}
		// Fields after "(comm)": state ppid pgrp session …; comm may contain spaces.
		text := string(raw)
		fields := strings.Fields(text[strings.LastIndexByte(text, ')')+1:])
		if len(fields) < 4 {
			continue
		}
		pgrp, err1 := strconv.Atoi(fields[2])
		session, err2 := strconv.Atoi(fields[3])
		if err1 != nil || err2 != nil || session != sid || seen[pgrp] {
			continue
		}
		seen[pgrp] = true
		groups = append(groups, pgrp)
	}
	return groups
}

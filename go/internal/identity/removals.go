package identity

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MachineRemovals is the root's list of removed machines (ADR 0052). A
// registration never expires, so without it a server could bring back a
// machine the owner removed (one sold, its agent kept by someone else) and
// every console would trust it again. Each machine is removed as of a time:
// a registration signed after it (the owner adding the machine back) is
// trusted again, one signed before is not. The list only grows; seq orders
// lists for syncing.
type MachineRemovals struct {
	Root     RootPublic
	Seq      uint64
	Machines []RemovedMachine // sorted by ID, no duplicates
	At       time.Time
}

// RemovedMachine is one machine of the list and when it was removed, in
// Unix seconds, as registrations count time.
type RemovedMachine struct {
	ID string
	At int64
}

// MaxRemovedMachines bounds a list; a longer one is refused before anything
// is allocated for it.
const MaxRemovedMachines = 4096

// ErrMachineRemovals covers every way a list fails to check out.
var ErrMachineRemovals = errors.New("identity: machine removals list is invalid")

// machineIDPattern is a MachineID: 16 bytes, base64url without padding.
var machineIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)

// Statement is what the root signs. Machines must be sorted and unique.
func (r MachineRemovals) Statement() OwnerStatement {
	entries := make([]string, len(r.Machines))
	for i, m := range r.Machines {
		entries[i] = m.ID + ":" + strconv.FormatInt(m.At, 10)
	}
	return OwnerStatement{statement("machine-removals",
		[2]string{"user", UserID(r.Root)},
		[2]string{"seq", strconv.FormatUint(r.Seq, 10)},
		[2]string{"machines", strings.Join(entries, ",")},
		[2]string{"at", strconv.FormatInt(r.At.Unix(), 10)})}
}

// Removes reports whether the list removes machine id for a registration
// signed at registeredAt (Unix seconds): one signed at or before its removal.
func (r MachineRemovals) Removes(id string, registeredAt int64) bool {
	i, found := slices.BinarySearchFunc(r.Machines, id, func(m RemovedMachine, id string) int { return strings.Compare(m.ID, id) })
	return found && registeredAt <= r.Machines[i].At
}

// VerifyMachineRemovals checks a list off the wire against the root it must
// come from: exactly the canonical text (sorted, unique, bounded), signed by
// root.
func VerifyMachineRemovals(text string, sig []byte, root RootPublic) (MachineRemovals, error) {
	if len(text) > 96+MaxRemovedMachines*36 || !strings.HasSuffix(text, "\n") {
		return MachineRemovals{}, ErrMachineRemovals
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	keys := []string{"user", "seq", "machines", "at"}
	if len(lines) != len(keys)+1 || lines[0] != "tilder/machine-removals/v2" {
		return MachineRemovals{}, ErrMachineRemovals
	}
	v := make(map[string]string, len(keys))
	for i, key := range keys {
		k, val, ok := strings.Cut(lines[i+1], "=")
		if !ok || k != key {
			return MachineRemovals{}, ErrMachineRemovals
		}
		v[key] = val
	}
	seq, err1 := strconv.ParseUint(v["seq"], 10, 64)
	at, err2 := strconv.ParseInt(v["at"], 10, 64)
	if err1 != nil || err2 != nil {
		return MachineRemovals{}, ErrMachineRemovals
	}
	r := MachineRemovals{Root: root, Seq: seq, At: time.Unix(at, 0)}
	if v["machines"] != "" {
		entries := strings.Split(v["machines"], ",")
		if len(entries) > MaxRemovedMachines {
			return MachineRemovals{}, ErrMachineRemovals
		}
		for _, e := range entries {
			id, when, ok := strings.Cut(e, ":")
			removedAt, err := strconv.ParseInt(when, 10, 64)
			if !ok || err != nil || !machineIDPattern.MatchString(id) {
				return MachineRemovals{}, ErrMachineRemovals
			}
			r.Machines = append(r.Machines, RemovedMachine{ID: id, At: removedAt})
		}
	}
	// Canonical: sorted by ID with no duplicates, and the text itself.
	if !slices.IsSortedFunc(r.Machines, func(a, b RemovedMachine) int { return strings.Compare(a.ID, b.ID) }) ||
		len(slices.CompactFunc(slices.Clone(r.Machines), func(a, b RemovedMachine) bool { return a.ID == b.ID })) != len(r.Machines) ||
		r.Statement().Text() != text || !root.Verify(OwnerStatement{text: []byte(text)}, sig) {
		return MachineRemovals{}, ErrMachineRemovals
	}
	return r, nil
}

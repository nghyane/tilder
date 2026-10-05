package identity_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nghyane/tilder/go/internal/identity"
)

const (
	machineA = "AAAAAAAAAAAAAAAAAAAAAA"
	machineB = "BBBBBBBBBBBBBBBBBBBBBB"
)

// ADR 0052: a registration signed at or before a machine's removal no
// longer counts; one signed after it (the machine added back) does.
func TestAMachineRemovalListVerifiesAndRemovesAsOfItsTime(t *testing.T) {
	t.Parallel()
	root, err := identity.RootPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	list := identity.MachineRemovals{Root: root.Public(), Seq: 2, At: epoch, Machines: []identity.RemovedMachine{
		{ID: machineA, At: 1_000}, {ID: machineB, At: 2_000},
	}}
	got, err := identity.VerifyMachineRemovals(list.Statement().Text(), root.Sign(list.Statement()), root.Public())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id   string
		reg  int64
		want bool
	}{
		{machineA, 900, true},    // registered before it was removed
		{machineA, 1_000, true},  // the same second: removed
		{machineA, 1_001, false}, // added back after
		{machineB, 1_500, true},
		{"CCCCCCCCCCCCCCCCCCCCCC", 1, false}, // never removed
	} {
		if got.Removes(tc.id, tc.reg) != tc.want {
			t.Errorf("Removes(%s, %d) = %v", tc.id, tc.reg, !tc.want)
		}
	}
}

func TestAMachineRemovalListIsRefused(t *testing.T) {
	t.Parallel()
	root, _ := identity.RootPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	other, _ := identity.RootPrivateFromSeed(bytes.Repeat([]byte{9}, 32))
	good := identity.MachineRemovals{Root: root.Public(), Seq: 1, At: epoch, Machines: []identity.RemovedMachine{{ID: machineA, At: 5}}}
	text := good.Statement().Text()
	unsorted := strings.Replace(identity.MachineRemovals{Root: root.Public(), Seq: 1, At: epoch, Machines: []identity.RemovedMachine{
		{ID: machineA, At: 5}, {ID: machineB, At: 6},
	}}.Statement().Text(), machineA+":5,"+machineB+":6", machineB+":6,"+machineA+":5", 1)
	dup := strings.Replace(text, machineA+":5", machineA+":5,"+machineA+":7", 1)
	badID := strings.Replace(text, machineA, "not-a-machine", 1)
	for name, tc := range map[string]struct {
		text string
		sig  []byte
	}{
		"another root signed it": {text, other.Sign(good.Statement())},
		"a byte changed":         {strings.Replace(text, ":5", ":6", 1), root.Sign(good.Statement())},
		// Signed by the root as they are: refused for their shape, not their signature.
		"not sorted":                {unsorted, root.Sign(identity.OwnerStatementForTest(unsorted))},
		"a machine twice":           {dup, root.Sign(identity.OwnerStatementForTest(dup))},
		"not a machine id":          {badID, root.Sign(identity.OwnerStatementForTest(badID))},
		"no final newline":          {strings.TrimSuffix(text, "\n"), root.Sign(good.Statement())},
		"another kind of statement": {strings.Replace(text, "machine-removals", "revocations", 1), root.Sign(good.Statement())},
	} {
		if _, err := identity.VerifyMachineRemovals(tc.text, tc.sig, root.Public()); !errors.Is(err, identity.ErrMachineRemovals) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

// The text the console builds too (web/src/model/machine-removals.ts): one
// byte off and no signature matches across the two.
func TestAMachineRemovalListIsTheTextTheConsoleBuilds(t *testing.T) {
	t.Parallel()
	root, _ := identity.RootPrivateFromSeed(bytes.Repeat([]byte{1}, 32))
	l := identity.MachineRemovals{Root: root.Public(), Seq: 2, At: time.Unix(7, 0), Machines: []identity.RemovedMachine{
		{ID: machineA, At: 5}, {ID: machineB, At: 6},
	}}
	want := "tilder/machine-removals/v2\nuser=" + identity.UserID(root.Public()) + "\nseq=2\nmachines=" + machineA + ":5," + machineB + ":6\nat=7\n"
	if got := l.Statement().Text(); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

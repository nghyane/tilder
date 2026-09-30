//go:build windows

package state_test

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/nghyane/tilder/go/internal/agent/state"
)

// ADR 0044: on Windows the machine key's folder is its owner's, SYSTEM's and
// Administrators', whatever the folder above allows.
func TestTheHomeIsKeptToItsOwnerOnWindows(t *testing.T) {
	t.Parallel()
	home := filepath.Join(t.TempDir(), ".tilder")
	if _, err := state.MachineKey(home); err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{user.User.Sid.String(): true}
	for _, w := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinBuiltinAdministratorsSid} {
		sid, err := windows.CreateWellKnownSid(w)
		if err != nil {
			t.Fatal(err)
		}
		allowed[sid.String()] = true
	}
	for _, p := range []string{home, filepath.Join(home, "identity.json")} {
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		dacl, _, err := sd.DACL()
		if err != nil || dacl == nil {
			t.Fatalf("%s: no DACL (%v): open to everyone", p, err)
		}
		for i := range uint32(dacl.AceCount) {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, i, &ace); err != nil {
				t.Fatal(err)
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)) //nolint:gosec // G103: the ACE's SID starts at SidStart
			if !allowed[sid.String()] {
				t.Errorf("%s: %s may access it (%s)", p, sid.String(), sd.String())
			}
		}
	}
	if _, err := os.ReadFile(filepath.Join(home, "identity.json")); err != nil { //nolint:gosec // G304: the test's own temp path
		t.Fatalf("the owner lost access: %v", err)
	}
}

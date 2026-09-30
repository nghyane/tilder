//go:build windows

package state

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// privateDir gives the home a protected DACL (ADR 0044): the owner, SYSTEM
// and Administrators only, the set OpenSSH for Windows requires of a private
// key file; mode 0700 means nothing on Windows. Protected, so nothing is
// inherited from a parent a wider group may hold; the ACEs are inherited by
// what is inside, and setting them again is harmless.
func privateDir(dir string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read the process user: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return fmt.Errorf("build the descriptor: %w", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read the descriptor: %w", err)
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

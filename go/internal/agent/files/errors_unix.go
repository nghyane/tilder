//go:build unix

package files

// platformCode is a Code for an error only this platform names; none on
// Unix, where mapErr's syscall errors are the real ones.
func platformCode(error) Code { return 0 }

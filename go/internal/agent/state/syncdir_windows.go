//go:build windows

package state

// syncDir does nothing on Windows (ADR 0044): a directory cannot be opened
// to sync there, the call failed and every save with it; NTFS journals the
// rename that made the file whole.
func syncDir(string) error { return nil }

//go:build unix

package state

// privateDir has nothing to add on Unix: the home is made 0700.
func privateDir(string) error { return nil }

package holder

import "os"

// pollable keeps f as it is: a macOS PTY master cannot be polled, and needs
// no poll to end a blocked write, which returns once the shell's side of the
// terminal is gone.
func pollable(f *os.File) (*os.File, error) { return f, nil }

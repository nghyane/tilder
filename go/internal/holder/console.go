package holder

// console is a shell's terminal and its process, as the platform makes
// them (ADR 0044): a PTY and a session on Unix, a pseudoconsole and a job
// object on Windows. The Shell above it is the same on both.
type console interface {
	// Read is the shell's output; Write, what is typed.
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	resize(cols, rows uint16) error
	pid() int
	// wait blocks until the shell's process ends, and is its exit code.
	wait() int
	// hangup asks the shell and every job it started to end (SIGHUP to the
	// session; closing the pseudoconsole); killAll ends what is left.
	hangup()
	killAll()
	// closeOutput ends reading, once what was left has been drained.
	closeOutput()
}

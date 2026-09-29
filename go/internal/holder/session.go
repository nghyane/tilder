package holder

// Session is a shell as its users see it, wherever its PTY lives: a Shell in
// this process, or a holder process reached over its socket (ADR 0005).
type Session interface {
	// Attach replays from since and subscribes, with nothing lost between.
	Attach(since uint64) (Replay, *Viewer)
	Detach(v *Viewer)
	Input(p []byte) error
	Resize(cols, rows uint16) error
	// Kill ends the shell and everything in its session.
	Kill()
	// Pid is the shell's process, 0 until it is known: where its folder is
	// read from (ADR 0024).
	Pid() int
}

var _ Session = (*Shell)(nil)

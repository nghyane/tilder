package holder

// Ring keeps the last Size bytes of a shell's output, addressed by absolute
// byte offset (PROTOCOL §4 `pty`): a client that reattaches with `since`
// gets exactly what it has not seen, or learns how much fell off the end.
type Ring struct {
	buf  []byte
	size int
	// start is the offset of buf[0]; start+len(buf) is the next byte's offset.
	start uint64
}

// NewRing keeps up to size bytes.
func NewRing(size int) *Ring { return &Ring{size: size} }

// End is the offset of the next byte to be written.
func (r *Ring) End() uint64 { return r.start + uint64(len(r.buf)) }

// Write appends p, dropping the oldest bytes beyond the ring's size.
func (r *Ring) Write(p []byte) {
	r.buf = append(r.buf, p...)
	if over := len(r.buf) - r.size; over > 0 {
		r.buf = append(r.buf[:0:0], r.buf[over:]...)
		r.start += uint64(over)
	}
}

// Since returns everything from offset since on, the offset it starts at,
// and how many requested bytes are no longer kept. A since beyond the end is
// clamped: a client cannot ask for bytes that were never written.
func (r *Ring) Since(since uint64) (data []byte, from, lost uint64) {
	switch {
	case since < r.start:
		return append([]byte(nil), r.buf...), r.start, r.start - since
	case since >= r.End():
		return nil, r.End(), 0
	default:
		return append([]byte(nil), r.buf[since-r.start:]...), since, 0
	}
}

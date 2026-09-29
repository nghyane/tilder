package lanxfer

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
)

// maxFrame bounds one message, checked before anything is read into it:
// `xfer` messages stay under 16 KiB (ADR 0022), as on a data channel.
const maxFrame = 16 << 10

var errFrameTooLarge = errors.New("lanxfer: frame over 16 KiB")

// framed gives a stream a data channel's shape: one Write is one message,
// one Read returns one message whole, so `xfer` runs on it unchanged. Each
// message goes behind its length, 4 bytes big-endian. Reads come from one
// goroutine; writes may come from several.
type framed struct {
	conn net.Conn
	r    *bufio.Reader

	// The mutex protects the following elements.
	mu  sync.Mutex
	out []byte
}

func newFramed(conn net.Conn) *framed {
	return &framed{conn: conn, r: bufio.NewReaderSize(conn, maxFrame+4)}
}

// Read reads the next message into p, which must hold it.
func (f *framed) Read(p []byte) (int, error) {
	var head [4]byte
	if _, err := io.ReadFull(f.r, head[:]); err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n > maxFrame {
		return 0, errFrameTooLarge
	}
	if int(n) > len(p) {
		return 0, io.ErrShortBuffer
	}
	return io.ReadFull(f.r, p[:n])
}

// Write sends p as one message, in one write so it goes as one TLS record.
func (f *framed) Write(p []byte) (int, error) {
	if len(p) > maxFrame {
		return 0, errFrameTooLarge
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.out = binary.BigEndian.AppendUint32(f.out[:0], uint32(len(p))) //nolint:gosec // len(p) ≤ maxFrame, checked above
	f.out = append(f.out, p...)
	if _, err := f.conn.Write(f.out); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (f *framed) Close() error { return f.conn.Close() }

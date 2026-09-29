package holder

import (
	"bufio"
	"io"

	"google.golang.org/protobuf/encoding/protodelim"
	"google.golang.org/protobuf/proto"
)

// ContractVersion is the holder protocol this build speaks (ADR 0005). A
// holder keeps the version it started with; bump only with a way to talk to
// the old one. 2 adds the screen to the replay (ADR 0017); an agent still
// talks to a holder of 1, which sends none.
const (
	ContractVersion = 2
	oldestContract  = 1
)

// maxFrame bounds a message read from the socket. The largest is a replay: a
// whole ring (RingSize, 1 MiB) plus a screen (at most maxScreen). It was
// 1 MiB, which a full ring alone passed, and the agent took the unreadable
// replay for a dead shell.
const maxFrame = 16 << 20

func send(w io.Writer, m proto.Message) error {
	_, err := protodelim.MarshalTo(w, m)
	return err
}

func receive(r *bufio.Reader, m proto.Message) error {
	return protodelim.UnmarshalOptions{MaxSize: maxFrame}.UnmarshalFrom(r, m)
}

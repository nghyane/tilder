package fschan_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/quartz"
	"go.uber.org/goleak"
	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/files"
	"github.com/nghyane/tilder/go/internal/agent/fschan"
	"github.com/nghyane/tilder/go/internal/testutil"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m, testutil.GoleakOptions...) }

// client reads the agent's messages on its own goroutine, as a DataChannel
// buffers them: an unbuffered pipe would deadlock an agent granting credit
// while the client is still sending.
type client struct {
	t     *testing.T
	conn  net.Conn
	inbox chan []byte
}

func newClient(t *testing.T, conn net.Conn) *client {
	c := &client{t: t, conn: conn, inbox: make(chan []byte, 1024)}
	go func() {
		defer close(c.inbox)
		buf := make([]byte, 128*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			c.inbox <- append([]byte(nil), buf[:n]...)
		}
	}()
	return c
}

// serve starts a channel over a home with the agent's directory inside.
func serve(t *testing.T) (*client, string) {
	t.Helper()
	h := t.TempDir()
	if err := os.MkdirAll(filepath.Join(h, ".tilder"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h, ".tilder/identity.json"), []byte("machine key"), 0o600); err != nil {
		t.Fatal(err)
	}
	tree := files.New(h, filepath.Join(h, ".tilder"), quartz.NewMock(t))
	c, s := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- fschan.Serve(ctx, s, tree, quartz.NewReal()) }()
	t.Cleanup(func() {
		cancel()
		_ = c.Close()
		<-done
	})
	_ = c.SetDeadline(time.Now().Add(testutil.WaitShort)) //nolint:forbidigo // net.Pipe deadlines take wall time
	return newClient(t, c), h
}

func (c *client) send(id uint32, msg *tilderv1.FsClient) {
	c.t.Helper()
	msg.ReqId = id
	frame, err := proto.Marshal(msg)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.conn.Write(frame); err != nil {
		c.t.Fatal(err)
	}
}

func (c *client) recv() *tilderv1.FsServer {
	c.t.Helper()
	frame, ok := <-c.inbox
	if !ok {
		c.t.Fatal("the channel closed")
	}
	if len(frame) > 16*1024 {
		c.t.Errorf("a %d-byte message: over 16 KiB holds up the other channels", len(frame))
	}
	msg := &tilderv1.FsServer{}
	if err := proto.Unmarshal(frame, msg); err != nil {
		c.t.Fatal(err)
	}
	return msg
}

func TestAReadStaysInsideItsWindowAndHashesWhatItSent(t *testing.T) {
	t.Parallel()
	c, h := serve(t)
	body := bytes.Repeat([]byte("0123456789abcdef"), 40_000) // 640 KB
	if err := os.WriteFile(filepath.Join(h, "big.log"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	const window = 64 * 1024
	c.send(1, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Read{Read: &tilderv1.FsRead{Path: []byte("big.log"), Window: window}}})
	var got []byte
	var acked uint64
	for {
		msg := c.recv()
		if eof := msg.GetEof(); eof != nil {
			want := sha256.Sum256(body)
			if !bytes.Equal(eof.GetSha256(), want[:]) || !bytes.Equal(got, body) {
				t.Fatalf("got %d bytes, hash %x", len(got), eof.GetSha256())
			}
			return
		}
		got = append(got, msg.GetChunk().GetData()...)
		if uint64(len(got))-acked < window {
			continue
		}
		// A full window unacknowledged: the agent must now wait for us.
		if uint64(len(got))-acked > window {
			t.Fatalf("%d bytes past the last ack: beyond the window", uint64(len(got))-acked)
		}
		quiet, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		select {
		case frame := <-c.inbox:
			cancel()
			t.Fatalf("the agent sent a %d-byte message past a full window", len(frame))
		case <-quiet.Done():
			cancel()
		}
		acked = uint64(len(got))
		c.send(1, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Ack{Ack: &tilderv1.FsAck{Received: acked}}})
	}
}

func TestAWriteFollowsItsCreditAndChecksTheVersion(t *testing.T) {
	t.Parallel()
	c, h := serve(t)
	if err := os.WriteFile(filepath.Join(h, "a.txt"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.send(1, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Stat{Stat: &tilderv1.FsStat{Path: []byte("a.txt")}}})
	etag := c.recv().GetEntry().GetEtag()

	// Someone else writes the file first.
	if err := os.WriteFile(filepath.Join(h, "a.txt"), []byte("theirs!"), 0o600); err != nil {
		t.Fatal(err)
	}
	c.send(2, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Write{Write: &tilderv1.FsWrite{Path: []byte("a.txt"), IfEtag: etag}}})
	if c.recv().GetCredit().GetAccepted() == 0 {
		t.Fatal("no credit")
	}
	c.send(2, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Data{Data: &tilderv1.FsData{Data: []byte("mine")}}})
	c.send(2, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Commit{Commit: &tilderv1.FsCommit{}}})
	conflict := c.recv().GetConflict()
	if conflict == nil || conflict.GetCurrent().GetSize() != uint64(len("theirs!")) {
		t.Fatalf("expected a conflict showing the file as it is now, got %v", conflict)
	}
	if b, _ := os.ReadFile(filepath.Join(h, "a.txt")); string(b) != "theirs!" { //nolint:gosec // G304: the test's temp dir
		t.Fatalf("the refused write changed the file: %q", b)
	}

	// With the current etag it lands.
	c.send(3, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Write{Write: &tilderv1.FsWrite{Path: []byte("a.txt"), IfEtag: conflict.GetCurrent().GetEtag()}}})
	c.recv()
	c.send(3, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Data{Data: &tilderv1.FsData{Data: []byte("mine")}}})
	c.send(3, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Commit{Commit: &tilderv1.FsCommit{}}})
	if ok := c.recv().GetOk(); ok == nil || ok.GetEntry().GetSize() != 4 {
		t.Fatalf("got %v", ok)
	}
}

// A write bigger than the first credit goes through as the agent grants more.
func TestABigWriteGoesThroughAsCreditIsGranted(t *testing.T) {
	t.Parallel()
	c, h := serve(t)
	c.send(1, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Write{Write: &tilderv1.FsWrite{Path: []byte("big.bin")}}})
	credit := c.recv().GetCredit().GetAccepted()
	body := bytes.Repeat([]byte{7}, 3<<20)
	sent := uint64(0)
	for sent < uint64(len(body)) {
		if sent >= credit {
			msg := c.recv()
			if msg.GetCredit() == nil {
				t.Fatalf("waiting for credit, got %v", msg)
			}
			credit = msg.GetCredit().GetAccepted()
			continue
		}
		n := min(uint64(15*1024), credit-sent, uint64(len(body))-sent)
		c.send(1, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Data{Data: &tilderv1.FsData{Data: body[sent : sent+n]}}})
		sent += n
	}
	c.send(1, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Commit{Commit: &tilderv1.FsCommit{}}})
	for {
		msg := c.recv()
		if msg.GetCredit() != nil {
			continue // granted ahead of the last parts
		}
		if msg.GetOk().GetEntry().GetSize() != uint64(len(body)) {
			t.Fatalf("got %v", msg)
		}
		break
	}
	if got, _ := os.ReadFile(filepath.Join(h, "big.bin")); !bytes.Equal(got, body) { //nolint:gosec // G304: the test's temp dir
		t.Fatalf("wrote %d bytes", len(got))
	}
}

func TestTheAgentsDirectoryStaysOutOfReachOverTheChannel(t *testing.T) {
	t.Parallel()
	c, _ := serve(t)
	c.send(1, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Read{Read: &tilderv1.FsRead{Path: []byte(".tilder/identity.json")}}})
	if got := c.recv().GetError().GetCode(); got != tilderv1.FsError_CODE_DENIED {
		t.Fatalf("got %v", got)
	}
	c.send(2, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Read{Read: &tilderv1.FsRead{Path: []byte("../etc/passwd")}}})
	if got := c.recv().GetError().GetCode(); got != tilderv1.FsError_CODE_INVALID {
		t.Fatalf("got %v", got)
	}
}

// A big directory comes in pages that fit a message, every name exactly once.
func TestAListIsPagedBySizeWithoutLosingNames(t *testing.T) {
	t.Parallel()
	c, h := serve(t)
	dir := filepath.Join(h, "many")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for i := range 400 {
		name := fmt.Sprintf("%03d-%s", i, strings.Repeat("x", 100))
		want[name] = true
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	var after []byte
	pages := 0
	for {
		c.send(1, &tilderv1.FsClient{Msg: &tilderv1.FsClient_List{List: &tilderv1.FsList{Path: []byte("many"), After: after, Limit: 1000}}})
		page := c.recv().GetEntries()
		pages++
		for _, e := range page.GetEntries() {
			if seen[string(e.GetName())] {
				t.Fatalf("%q listed twice", e.GetName())
			}
			seen[string(e.GetName())] = true
		}
		if len(page.GetNext()) == 0 {
			break
		}
		after = page.GetNext()
	}
	if len(seen) != len(want) || pages < 2 {
		t.Fatalf("got %d names in %d pages, want %d in several", len(seen), pages, len(want))
	}
}

// Closing the channel drops a write in progress: nothing half-written stays.
func TestClosingTheChannelDropsAWriteInProgress(t *testing.T) {
	t.Parallel()
	h := t.TempDir()
	tree := files.New(h, filepath.Join(h, ".tilder"), quartz.NewMock(t))
	c, s := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- fschan.Serve(context.Background(), s, tree, quartz.NewReal()) }()
	_ = c.SetDeadline(time.Now().Add(testutil.WaitShort)) //nolint:forbidigo // net.Pipe deadlines take wall time
	cl := newClient(t, c)
	cl.send(1, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Write{Write: &tilderv1.FsWrite{Path: []byte("half.txt")}}})
	cl.recv()
	cl.send(1, &tilderv1.FsClient{Msg: &tilderv1.FsClient_Data{Data: &tilderv1.FsData{Data: []byte("half")}}})
	_ = c.Close()
	<-done
	names, _ := os.ReadDir(h)
	if len(names) != 0 {
		t.Fatalf("left behind: %v", names)
	}
}

// A client that opens writes and never finishes them is refused past the
// bound: each held a directory and a temp file open, and enough of them ran
// the agent out of descriptors, every shell on it with it.
func TestOpenWritesAreBoundedPerChannel(t *testing.T) {
	t.Parallel()
	const maxWrites = 8 // the channel's bound
	c, h := serve(t)
	for i := range maxWrites + 1 {
		name := fmt.Sprintf("f%02d.txt", i)
		c.send(uint32(i+1), &tilderv1.FsClient{Msg: &tilderv1.FsClient_Write{Write: &tilderv1.FsWrite{Path: []byte(name)}}})
		reply := c.recv()
		if i < maxWrites && reply.GetCredit().GetAccepted() == 0 {
			t.Fatalf("write %d: %v", i, reply)
		}
		if i == maxWrites && reply.GetError().GetCode() != tilderv1.FsError_CODE_BUSY {
			t.Fatalf("one too many: %v", reply)
		}
	}
	temps, _ := filepath.Glob(filepath.Join(h, ".tilder.*.tmp"))
	if len(temps) > maxWrites {
		t.Fatalf("%d temp files for %d writes allowed", len(temps), maxWrites)
	}
}

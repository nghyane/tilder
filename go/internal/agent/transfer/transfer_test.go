package transfer_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/quartz"
	"go.uber.org/goleak"
	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/files"
	"github.com/nghyane/tilder/go/internal/agent/transfer"
	"github.com/nghyane/tilder/go/internal/agent/xferchan"
	"github.com/nghyane/tilder/go/internal/identity"
	"github.com/nghyane/tilder/go/internal/testutil"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m, testutil.GoleakOptions...) }

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func home(t *testing.T) string {
	t.Helper()
	h := t.TempDir()
	write(t, h, ".tilder/identity.json", []byte("machine key"))
	return h
}

func write(t *testing.T, h, rel string, data []byte) {
	t.Helper()
	p := filepath.Join(h, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func tree(t *testing.T, h string) *files.Tree {
	return files.New(h, filepath.Join(h, ".tilder"), quartz.NewMock(t))
}

// pipe is the destination's end of a connection to a real source; it can cut
// itself after some chunks, spoil one piece, and records the wants sent.
type pipe struct {
	net.Conn
	cutAfter int32 // chunk ends read before the connection drops; 0: never
	// failAck drops the connection instead of sending the ack of chunk
	// failAck-1; 0: never.
	failAck int64
	// onCut runs when cutAfter drops the connection.
	onCut func()
	spoil atomic.Bool
	ends  atomic.Int32
	wants chan *tilderv1.XferWant
}

func (*pipe) Relayed() bool { return false }

func (p *pipe) Read(b []byte) (int, error) {
	n, err := p.Conn.Read(b)
	if err != nil {
		return n, err
	}
	msg := &tilderv1.XferServer{}
	if proto.Unmarshal(b[:n], msg) == nil {
		if piece := msg.GetPiece(); piece != nil && len(piece.GetData()) > 0 && p.spoil.CompareAndSwap(true, false) {
			piece.Data[0] ^= 0xff
			out, _ := proto.Marshal(msg)
			n = copy(b, out)
		}
		if msg.GetChunkEnd() != nil && p.ends.Add(1) == p.cutAfter {
			_ = p.Close()
			if p.onCut != nil {
				p.onCut()
			}
		}
	}
	return n, nil
}

func (p *pipe) Write(b []byte) (int, error) {
	msg := &tilderv1.XferClient{}
	if proto.Unmarshal(b, msg) == nil && msg.GetWant() != nil {
		select {
		case p.wants <- msg.GetWant():
		default:
		}
	}
	if a := msg.GetAck(); a != nil && int64(a.GetIndex())+1 == p.failAck { //nolint:gosec // G115: a test's small index
		_ = p.Close()
		return 0, io.ErrClosedPipe
	}
	return p.Conn.Write(b)
}

// source serves the grant from src's home, one connection per Connect.
type source struct {
	t     *testing.T
	tree  *files.Tree
	grant identity.Transfer
	wg    sync.WaitGroup
	// next shapes the next connection (cut, spoil); then reset.
	mu    sync.Mutex
	next  func(*pipe)
	conns []*pipe
}

func (s *source) connect(ctx context.Context) (transfer.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, srv := net.Pipe()
	p := &pipe{Conn: c, wants: make(chan *tilderv1.XferWant, 1024)}
	s.mu.Lock()
	if s.next != nil {
		s.next(p)
		s.next = nil
	}
	s.conns = append(s.conns, p)
	s.mu.Unlock()
	s.wg.Go(func() { _ = xferchan.Serve(context.Background(), srv, s.tree, s.grant) })
	return p, nil
}

func (s *source) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

func (s *source) conn(i int) *pipe {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns[i]
}

type setup struct {
	src, dst string
	clk      *quartz.Mock
	source   *source
	grant    identity.Transfer
}

// newSetup copies srcPath on one home to dstPath on another.
func newSetup(t *testing.T, srcPath, dstPath string) *setup {
	t.Helper()
	clk := quartz.NewMock(t)
	g := identity.Transfer{
		Src: "machine-a", SrcPath: []byte(srcPath), Dst: "machine-b", DstPath: []byte(dstPath),
		NotAfter: clk.Now().Add(time.Hour), Nonce: bytes.Repeat([]byte{7}, 16),
	}
	s := &setup{src: home(t), dst: home(t), clk: clk, grant: g}
	s.source = &source{t: t, tree: tree(t, s.src), grant: g}
	t.Cleanup(s.source.wg.Wait)
	return s
}

func (s *setup) job(t *testing.T) *transfer.Job {
	return &transfer.Job{
		Grant: s.grant, Raw: []byte("grant"), Tree: tree(t, s.dst), Connect: s.source.connect, Clock: s.clk, Log: quiet,
	}
}

// run runs a job to its end, moving the fake clock past each reconnect wait.
func (s *setup) run(ctx context.Context, t *testing.T, j *transfer.Job) transfer.Progress {
	t.Helper()
	done := make(chan transfer.Progress, 1)
	go func() { done <- j.Run(ctx) }()
	deadline := time.After(testutil.WaitMedium) //nolint:forbidigo // a real pipe
	for {
		select {
		case p := <-done:
			return p
		case <-deadline:
			t.Fatal("the copy did not end")
		case <-time.After(5 * time.Millisecond): //nolint:forbidigo // polling the fake clock's timers
			if _, ok := s.clk.Peek(); ok {
				_, w := s.clk.AdvanceNext()
				w.MustWait(testutil.Context(t, testutil.WaitShort))
			}
		}
	}
}

func sum(t *testing.T, p string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(p) //nolint:gosec // G304: a test's own temp file
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

func noPart(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(dir, files.PartDir)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s is still there: %v", files.PartDir, err)
	}
}

func big(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

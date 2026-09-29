package transfer_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/transfer"
	"github.com/nghyane/tilder/go/internal/agent/xferchan"
	"github.com/nghyane/tilder/go/internal/identity"
	"github.com/nghyane/tilder/go/internal/testutil"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

var errNotAllowed = errors.New("not allowed")

// manager runs a Manager for the setup's destination. Grants are told apart
// by their statement text: the setup's own is allowed, anything else refused.
func (s *setup) manager(t *testing.T, agentDir string) *transfer.Manager {
	t.Helper()
	m := &transfer.Manager{
		Tree: tree(t, s.dst), Home: agentDir, Clock: s.clk, Log: quiet,
		Verify: func(g *tilderv1.TransferGrant) (identity.Transfer, error) {
			if g.GetStatement() != "ok" {
				return identity.Transfer{}, errNotAllowed
			}
			return s.grant, nil
		},
		Connect: func(*tilderv1.TransferGrant, identity.Transfer) transfer.Connect { return s.source.connect },
	}
	m.Start(context.Background())
	t.Cleanup(m.Close)
	return m
}

// ctlClient is a device's end of an `xfer-ctl` channel.
type ctlClient struct {
	t     *testing.T
	conn  net.Conn
	inbox chan *tilderv1.XferCtlServer
}

func openCtl(t *testing.T, m *transfer.Manager) *ctlClient {
	t.Helper()
	c, srv := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); _ = transfer.ServeCtl(context.Background(), srv, m) }()
	cl := &ctlClient{t: t, conn: c, inbox: make(chan *tilderv1.XferCtlServer, 1024)}
	go func() {
		defer close(cl.inbox)
		buf := make([]byte, 64*1024)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			msg := &tilderv1.XferCtlServer{}
			if proto.Unmarshal(buf[:n], msg) == nil {
				cl.inbox <- msg
			}
		}
	}()
	t.Cleanup(func() { _ = c.Close(); <-done })
	return cl
}

func (c *ctlClient) send(msg *tilderv1.XferCtlClient) {
	c.t.Helper()
	frame, _ := proto.Marshal(msg)
	if _, err := c.conn.Write(frame); err != nil {
		c.t.Fatal(err)
	}
}

// until reads messages until one matches.
func (c *ctlClient) until(match func(*tilderv1.XferCtlServer) bool) *tilderv1.XferCtlServer {
	c.t.Helper()
	deadline := time.After(testutil.WaitMedium) //nolint:forbidigo // a real pipe
	for {
		select {
		case m, ok := <-c.inbox:
			if !ok {
				c.t.Fatal("the control channel closed")
			}
			if match(m) {
				return m
			}
		case <-deadline:
			c.t.Fatal("no such control message")
			return nil
		}
	}
}

// A device asks the destination to pull; it hears the copy accepted, its
// progress on its own request, and that it is done.
func TestADeviceStartsACopyAndFollowsItToTheEnd(t *testing.T) {
	t.Parallel()
	s := newSetup(t, "big.bin", "big.bin")
	write(t, s.src, "big.bin", big(3*xferchan.ChunkSize))
	c := openCtl(t, s.manager(t, t.TempDir()))

	c.send(&tilderv1.XferCtlClient{ReqId: 9, Msg: &tilderv1.XferCtlClient_Pull{Pull: &tilderv1.XferPull{Grant: &tilderv1.TransferGrant{Statement: "ok"}}}})
	if a := c.until(func(m *tilderv1.XferCtlServer) bool { return m.GetAccepted() != nil }); a.GetReqId() != 9 || a.GetAccepted().GetId() != s.grant.ID() {
		t.Fatalf("accepted %v", a)
	}
	done := c.until(func(m *tilderv1.XferCtlServer) bool { return m.GetDone() != nil || m.GetFailed() != nil })
	if done.GetDone() == nil || done.GetReqId() != 9 {
		t.Fatalf("the copy ended %v", done)
	}
	if sum(t, filepath.Join(s.src, "big.bin")) != sum(t, filepath.Join(s.dst, "big.bin")) {
		t.Fatal("the copy differs")
	}
	c.send(&tilderv1.XferCtlClient{ReqId: 10, Msg: &tilderv1.XferCtlClient_List{List: &tilderv1.XferList{}}})
	jobs := c.until(func(m *tilderv1.XferCtlServer) bool { return m.GetJobs() != nil }).GetJobs().GetJobs()
	if len(jobs) != 1 || !jobs[0].GetEnded() || jobs[0].GetCode() != tilderv1.XferFailed_CODE_UNSPECIFIED {
		t.Fatalf("list = %v, want the copy, done", jobs)
	}
}

// A grant the machine does not accept starts nothing.
func TestAGrantTheMachineRefusesStartsNothing(t *testing.T) {
	t.Parallel()
	s := newSetup(t, "a.txt", "a.txt")
	write(t, s.src, "a.txt", []byte("a"))
	agentDir := t.TempDir()
	c := openCtl(t, s.manager(t, agentDir))
	c.send(&tilderv1.XferCtlClient{ReqId: 3, Msg: &tilderv1.XferCtlClient_Pull{Pull: &tilderv1.XferPull{Grant: &tilderv1.TransferGrant{Statement: "forged"}}}})
	f := c.until(func(m *tilderv1.XferCtlServer) bool { return m.GetFailed() != nil })
	if f.GetReqId() != 3 || f.GetFailed().GetCode() != tilderv1.XferFailed_CODE_DENIED {
		t.Fatalf("got %v, want denied", f)
	}
	if s.source.count() != 0 {
		t.Fatal("a refused grant reached the source")
	}
	if names, _ := os.ReadDir(filepath.Join(agentDir, "transfers")); len(names) != 0 {
		t.Fatalf("a refused grant was kept: %v", names)
	}
}

// A copy the agent was running when it stopped is taken up by the next run,
// from the grant it kept.
func TestTheNextAgentResumesTheCopiesItFinds(t *testing.T) {
	t.Parallel()
	s := newSetup(t, "big.bin", "big.bin")
	write(t, s.src, "big.bin", big(4*xferchan.ChunkSize))
	agentDir := t.TempDir()
	stopped := make(chan struct{})
	s.source.next = func(p *pipe) { p.cutAfter = 2 } // the first run never finishes
	first := &transfer.Manager{
		Tree: tree(t, s.dst), Home: agentDir, Clock: s.clk, Log: quiet,
		Verify: func(*tilderv1.TransferGrant) (identity.Transfer, error) { return s.grant, nil },
		Connect: func(*tilderv1.TransferGrant, identity.Transfer) transfer.Connect {
			return func(ctx context.Context) (transfer.Conn, error) {
				select {
				case <-stopped:
					<-ctx.Done() // the agent is stopping: wait to be stopped
					return nil, ctx.Err()
				default:
				}
				defer close(stopped)
				return s.source.connect(ctx)
			}
		},
	}
	first.Start(context.Background())
	if _, err := first.Pull(&tilderv1.TransferGrant{Statement: "ok"}); err != nil {
		t.Fatal(err)
	}
	<-stopped
	first.Close()
	if names, _ := os.ReadDir(filepath.Join(agentDir, "transfers")); len(names) != 1 {
		t.Fatalf("the stopped copy's grant was not kept: %v", names)
	}

	second := s.manager(t, agentDir)
	deadline := time.After(testutil.WaitMedium) //nolint:forbidigo // a real pipe
	for ended := false; !ended; {
		for _, p := range second.List() {
			if p.Ended {
				if p.Code != tilderv1.XferFailed_CODE_UNSPECIFIED {
					t.Fatalf("resumed copy ended %+v", p)
				}
				ended = true
			}
		}
		select {
		case <-deadline:
			t.Fatal("the next agent did not finish the copy")
		case <-time.After(5 * time.Millisecond): //nolint:forbidigo // polling the copy's state
		}
	}
	if sum(t, filepath.Join(s.src, "big.bin")) != sum(t, filepath.Join(s.dst, "big.bin")) {
		t.Fatal("the resumed copy differs")
	}
	for { // the grant goes once the copy has ended
		names, _ := os.ReadDir(filepath.Join(agentDir, "transfers"))
		if len(names) == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("a finished copy's grant was kept: %v", names)
		case <-time.After(5 * time.Millisecond): //nolint:forbidigo // polling the agent's directory
		}
	}
}

package transfer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"google.golang.org/protobuf/proto"

	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// ServeCtl answers a device's `xfer-ctl` channel (ADR 0035): Pull starts a
// copy to this machine, List shows the copies it holds, Cancel stops one; the
// progress of every copy follows, on the id of the Pull that started it here,
// else on 0.
func ServeCtl(ctx context.Context, ch io.ReadWriteCloser, m *Manager) error {
	c := &ctl{ch: ch, pulls: map[string]uint32{}}
	stop := m.Subscribe(c.progress)
	defer func() {
		stop()
		_ = ch.Close()
	}()
	quit := context.AfterFunc(ctx, func() { _ = ch.Close() })
	defer quit()
	buf := make([]byte, readBuffer)
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return err
		}
		msg := &tilderv1.XferCtlClient{}
		if err := proto.Unmarshal(buf[:n], msg); err != nil {
			return fmt.Errorf("transfer: malformed control message: %w", err)
		}
		id := msg.GetReqId()
		switch r := msg.GetMsg().(type) {
		case *tilderv1.XferCtlClient_Pull:
			copyID, err := m.Pull(r.Pull.GetGrant())
			if err != nil {
				c.send(id, &tilderv1.XferCtlServer{Msg: &tilderv1.XferCtlServer_Failed{Failed: &tilderv1.XferFailed{Code: pullCode(err)}}})
				continue
			}
			c.mu.Lock()
			c.pulls[copyID] = id
			c.mu.Unlock()
			c.send(id, &tilderv1.XferCtlServer{Msg: &tilderv1.XferCtlServer_Accepted{Accepted: &tilderv1.XferAccepted{Id: copyID}}})
		case *tilderv1.XferCtlClient_List:
			jobs := &tilderv1.XferJobs{}
			for _, p := range m.List() {
				jobs.Jobs = append(jobs.Jobs, progressOf(p))
			}
			c.send(id, &tilderv1.XferCtlServer{Msg: &tilderv1.XferCtlServer_Jobs{Jobs: jobs}})
		case *tilderv1.XferCtlClient_Cancel:
			if err := m.Cancel(r.Cancel.GetId()); err != nil {
				c.send(id, &tilderv1.XferCtlServer{Msg: &tilderv1.XferCtlServer_Failed{Failed: &tilderv1.XferFailed{
					Id: r.Cancel.GetId(), Code: tilderv1.XferFailed_CODE_NOT_FOUND,
				}}})
			}
		default:
			return errors.New("transfer: unknown control message")
		}
	}
}

type ctl struct {
	ch io.Writer
	// writeMu orders frames on the channel; taken after mu, never before.
	writeMu sync.Mutex

	// The mutex protects the following elements.
	mu    sync.Mutex
	pulls map[string]uint32
}

func (c *ctl) send(id uint32, msg *tilderv1.XferCtlServer) {
	msg.ReqId = id
	frame, err := proto.Marshal(msg)
	if err != nil {
		return
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, _ = c.ch.Write(frame)
}

func (c *ctl) progress(p Progress) {
	c.mu.Lock()
	id := c.pulls[p.ID]
	c.mu.Unlock()
	switch {
	case p.Ended && p.Code == tilderv1.XferFailed_CODE_UNSPECIFIED:
		c.send(id, &tilderv1.XferCtlServer{Msg: &tilderv1.XferCtlServer_Done{Done: &tilderv1.XferDone{Id: p.ID}}})
	case p.Ended:
		c.send(id, &tilderv1.XferCtlServer{Msg: &tilderv1.XferCtlServer_Failed{Failed: &tilderv1.XferFailed{Id: p.ID, Code: p.Code}}})
	default:
		c.send(id, &tilderv1.XferCtlServer{Msg: &tilderv1.XferCtlServer_Progress{Progress: progressOf(p)}})
	}
}

func progressOf(p Progress) *tilderv1.XferProgress {
	route := tilderv1.XferRoute_XFER_ROUTE_DIRECT
	if p.Relayed {
		route = tilderv1.XferRoute_XFER_ROUTE_RELAYED
	}
	return &tilderv1.XferProgress{
		Id: p.ID, Bytes: p.Bytes, Total: p.Total, Files: p.Files, FilesDone: p.FilesDone,
		Route: route, Name: p.Name, Waiting: p.Waiting, Ended: p.Ended, Code: p.Code,
	}
}

func pullCode(err error) tilderv1.XferFailed_Code {
	switch {
	case errors.Is(err, ErrBusy):
		return tilderv1.XferFailed_CODE_INTERNAL
	default:
		return tilderv1.XferFailed_CODE_DENIED
	}
}

package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/quartz"
	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/files"
	"github.com/nghyane/tilder/go/internal/agent/link"
	"github.com/nghyane/tilder/go/internal/agent/transfer"
	"github.com/nghyane/tilder/go/internal/identity"
	"github.com/nghyane/tilder/go/internal/identity/identitytest"
	"github.com/nghyane/tilder/go/internal/testutil"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// storedList is the agent's stored list of removed devices, as read at start.
type storedList struct {
	statement string
	sig       []byte
	err       error
}

func (s storedList) Load() (string, []byte, bool, error) {
	return s.statement, s.sig, s.statement != "", s.err
}
func (storedList) Save(string, []byte) error { return nil }

func removing(owner identitytest.Device, devices ...identity.DevicePublic) storedList {
	rev := identity.Revocations{Root: owner.Root.Public(), Seq: 1, At: owner.Cert.NotBefore, Devices: devices}
	return storedList{statement: rev.Statement().Text(), sig: owner.Root.Sign(rev.Statement())}
}

// rerun is an agent started over with a copy of owner's device left from
// its last run, its list of removed devices as stored: startCopies as main
// runs it. dials counts the connections the copy tried.
type rerun struct {
	copies *transfer.Manager
	clk    *quartz.Mock
	grant  string // the stored grant's path
	dials  *atomic.Int32
}

func rerunWith(t *testing.T, owner identitytest.Device, list storedList) rerun {
	t.Helper()
	clk := quartz.NewMock(t)
	now := clk.Now()
	key, err := identity.MachinePrivateFromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	g := identity.Transfer{
		User: owner.Cert.User(), Device: owner.Key.Public(), Src: "machine-a", SrcPath: []byte("proj"),
		Dst: identity.MachineID(key.Public()), DstPath: []byte("proj"), NotAfter: now.Add(time.Hour),
		Nonce: bytes.Repeat([]byte{9}, 16),
	}
	raw, err := proto.Marshal(&tilderv1.TransferGrant{
		Statement: g.Statement().Text(), Signature: owner.Key.Sign(g.Statement()), DeviceCertificate: owner.Certificate(),
	})
	if err != nil {
		t.Fatal(err)
	}
	home, dst := t.TempDir(), t.TempDir()
	grant := filepath.Join(home, "transfers", g.ID()+".grant")
	if err := os.MkdirAll(filepath.Dir(grant), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grant, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	quiet := slog.New(slog.DiscardHandler)
	l := &link.Link{Key: key, Owner: owner.Root.Public(), Clock: clk, Log: quiet, Revocations: list}
	r := rerun{clk: clk, grant: grant, dials: &atomic.Int32{}}
	r.copies = &transfer.Manager{Tree: files.New(dst, filepath.Join(dst, ".tilder"), clk), Home: home, Clock: clk, Log: quiet}
	startCopies(context.Background(), l, r.copies, func(*tilderv1.TransferGrant, identity.Transfer) transfer.Connect {
		return func(context.Context) (transfer.Conn, error) {
			r.dials.Add(1)
			return nil, errors.New("the source is away")
		}
	})
	t.Cleanup(r.copies.Close)
	return r
}

// until waits for ok, polling: the copy runs on its own goroutine.
func until(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.After(testutil.WaitShort) //nolint:forbidigo // the job's own goroutine
	for !ok() {
		select {
		case <-deadline:
			t.Fatalf("never: %s", what)
		case <-time.After(5 * time.Millisecond): //nolint:forbidigo // polling
		}
	}
}

func kept(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}

// ADR 0040: a copy whose device was removed is not resumed when the agent
// starts again, though the list that removed it was only on disk.
func TestARemovedDevicesCopyIsNotResumed(t *testing.T) {
	t.Parallel()
	owner := identitytest.NewDevice(t, 1, 101, quartz.NewMock(t).Now())
	r := rerunWith(t, owner, removing(owner, owner.Key.Public()))
	until(t, "the removed device's grant is thrown away", func() bool { return !kept(r.grant) })
	if n := r.dials.Load(); n != 0 {
		t.Fatalf("the copy dialled its source %d times", n)
	}
}

// A device whose certificate knows a newer list than the agent last saw is
// not taken for removed: its copy goes on.
func TestACopyWhoseCertificateKnowsTheListGoesOn(t *testing.T) {
	t.Parallel()
	owner := identitytest.NewDevice(t, 1, 101, quartz.NewMock(t).Now())
	owner.Cert.RevSeq = 1
	r := rerunWith(t, owner, removing(owner))
	until(t, "the copy dials its source", func() bool { return r.dials.Load() > 0 })
	if !kept(r.grant) {
		t.Fatal("a good copy was thrown away")
	}
}

// A list that cannot be read neither lets a copy run nor throws it away: the
// copy waits for a good list.
func TestACopyWaitsWhileTheListCannotBeRead(t *testing.T) {
	t.Parallel()
	owner := identitytest.NewDevice(t, 1, 101, quartz.NewMock(t).Now())
	r := rerunWith(t, owner, storedList{err: errors.New("the file is spoiled")})
	until(t, "the copy waits", func() bool {
		_, waiting := r.clk.Peek()
		return waiting
	})
	if n := r.dials.Load(); n != 0 {
		t.Fatalf("the copy dialled its source %d times", n)
	}
	if !kept(r.grant) {
		t.Fatal("the copy was thrown away")
	}
}

// A device removed while its copy runs ends the copy, not only its connection.
func TestRemovingADeviceEndsItsRunningCopy(t *testing.T) {
	t.Parallel()
	owner := identitytest.NewDevice(t, 1, 101, quartz.NewMock(t).Now())
	r := rerunWith(t, owner, storedList{})
	until(t, "the copy dials its source", func() bool { return r.dials.Load() > 0 })
	r.copies.Revoked([]identity.DevicePublic{owner.Key.Public()})
	until(t, "the copy ends", func() bool {
		for _, p := range r.copies.List() {
			if p.Ended {
				return true
			}
		}
		return false
	})
}

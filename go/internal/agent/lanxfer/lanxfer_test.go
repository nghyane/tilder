package lanxfer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/coder/quartz"
	"go.uber.org/goleak"
	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/testutil"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m, testutil.GoleakOptions...) }

var loopback = netip.MustParseAddr("127.0.0.1")

// offering runs Offer on one end of a pipe standing in for the `xfer-lan`
// channel; the served connection, if any, comes out of served, and is
// served (as xferchan would) until the connection or the channel closes.
func offering(t *testing.T, clk quartz.Clock, remote netip.Addr) (ch net.Conn, served chan io.ReadWriteCloser, done chan error) {
	t.Helper()
	src, dst := net.Pipe()
	served = make(chan io.ReadWriteCloser, 1)
	done = make(chan error, 1)
	go func() {
		done <- Offer(context.Background(), clk, src, loopback, remote, func(c io.ReadWriteCloser) {
			served <- c
			held(c)
		})
	}()
	t.Cleanup(func() { _ = dst.Close() })
	return dst, served, done
}

func readOffer(t *testing.T, ch net.Conn) *tilderv1.XferLan {
	t.Helper()
	buf := make([]byte, offerMax)
	n, err := ch.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	offer := &tilderv1.XferLan{}
	if err := proto.Unmarshal(buf[:n], offer); err != nil {
		t.Fatal(err)
	}
	return offer
}

func TestACopysMessagesArriveWholeOverTheLAN(t *testing.T) {
	t.Parallel()
	clk := quartz.NewReal()
	ch, served, done := offering(t, clk, loopback)
	conn, err := Dial(context.Background(), clk, ch, loopback)
	if err != nil {
		t.Fatal(err)
	}
	src := <-served
	piece := make([]byte, 15*1024)
	_, _ = rand.Read(piece)
	for _, m := range [][]byte{[]byte("want"), piece} {
		if _, err := src.Write(m); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, maxFrame)
		n, err := conn.Read(got)
		if err != nil || !bytes.Equal(got[:n], m) {
			t.Fatalf("got %d bytes (%v), want %d", n, err, len(m))
		}
	}
	_ = conn.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The copy lives no longer than the WebRTC connection that opened it: the
// grant's device removed cuts that connection, and the TCP one with it.
func TestTheCopyEndsWithItsChannel(t *testing.T) {
	t.Parallel()
	ctx := testutil.Context(t, testutil.WaitShort)
	clk := quartz.NewReal()
	src, dst := net.Pipe()
	served := make(chan io.ReadWriteCloser, 1)
	done := make(chan error, 1)
	go func() {
		done <- Offer(ctx, clk, src, loopback, loopback, func(c io.ReadWriteCloser) {
			served <- c
			held(c)
		})
	}()
	conn, err := Dial(ctx, clk, dst, loopback)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	<-served
	_ = src.Close() // the WebRTC connection goes, on the source's side
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("the copy outlived its channel")
	}
	if _, err := conn.Read(make([]byte, maxFrame)); err == nil {
		t.Fatal("the destination still reads a copy whose channel is gone")
	}
}

// Only the destination holds the token: anyone else on the LAN who finds
// the port gets no copy, and the offer ends rather than waiting for more.
func TestAConnectionWithoutTheTokenGetsNothing(t *testing.T) {
	t.Parallel()
	ch, served, done := offering(t, quartz.NewReal(), loopback)
	offer := readOffer(t, ch)
	attacker := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}} //nolint:gosec // the attacker
	c, err := attacker.DialContext(testutil.Context(t, testutil.WaitShort), "tcp", netip.AddrPortFrom(loopback, portOf(t, offer)).String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	guess := make([]byte, 4+tokenSize)
	binary.BigEndian.PutUint32(guess, tokenSize)
	if _, err := c.Write(guess); err != nil {
		t.Fatal(err)
	}
	if err := <-done; !errors.Is(err, errStranger) {
		t.Fatalf("Offer = %v, want errStranger", err)
	}
	select {
	case <-served:
		t.Fatal("a connection without the token was served")
	default:
	}
}

// A connection from another address is dropped before any handshake, and
// the offer ends on time when the destination never comes.
func TestAStrangersConnectionIsDroppedAndTheOfferRunsOut(t *testing.T) {
	t.Parallel()
	ctx := testutil.Context(t, testutil.WaitShort)
	clk := quartz.NewMock(t)
	trap := clk.Trap().AfterFunc()
	defer trap.Close()
	ch, served, done := offering(t, clk, netip.MustParseAddr("10.9.9.9"))
	offer := readOffer(t, ch)
	trap.MustWait(ctx).MustRelease(ctx)
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(loopback, portOf(t, offer)).String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	read := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 1))
		read <- err
	}()
	select {
	case err := <-read:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("the stranger read %v, want the connection closed", err)
		}
	case <-ctx.Done():
		t.Fatal("the stranger's connection was kept open")
	}
	clk.Advance(acceptWait).MustWait(ctx)
	if err := <-done; err == nil {
		t.Fatal("the offer did not run out")
	}
	select {
	case <-served:
		t.Fatal("a stranger was served")
	default:
	}
}

// The destination holds the source to the certificate its offer named: a
// listener on that port with another key is not the source.
func TestTheDestinationRefusesAnotherCertificate(t *testing.T) {
	t.Parallel()
	other, _, err := certificate(quartz.NewReal().Now())
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{other}, MinVersion: tls.VersionTLS13})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		if c, err := ln.Accept(); err == nil {
			_, _ = c.Read(make([]byte, 64)) // run the handshake
			_ = c.Close()
		}
	}()
	at := netip.MustParseAddrPort(ln.Addr().String())
	offered := sha256.Sum256([]byte("the certificate the source made"))
	frame, _ := proto.Marshal(&tilderv1.XferLan{Port: uint32(at.Port()), CertSha256: offered[:], Token: make([]byte, tokenSize)})
	src, dst := net.Pipe()
	go func() { _, _ = src.Write(frame) }()
	defer func() { _ = src.Close() }()
	if conn, err := Dial(context.Background(), quartz.NewReal(), dst, loopback); err == nil {
		_ = conn.Close()
		t.Fatal("Dial accepted a certificate the offer did not name")
	}
}

func TestAFrameOver16KiBIsRefusedUnread(t *testing.T) {
	t.Parallel()
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	go func() {
		head := binary.BigEndian.AppendUint32(nil, 1<<30)
		_, _ = a.Write(head)
	}()
	if _, err := newFramed(b).Read(make([]byte, maxFrame)); !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("Read = %v, want errFrameTooLarge", err)
	}
	if _, err := newFramed(b).Write(make([]byte, maxFrame+1)); !errors.Is(err, errFrameTooLarge) {
		t.Fatalf("Write = %v, want errFrameTooLarge", err)
	}
}

func portOf(t *testing.T, offer *tilderv1.XferLan) uint16 {
	t.Helper()
	if offer.GetPort() == 0 || offer.GetPort() > 65535 {
		t.Fatalf("offered port %d", offer.GetPort())
	}
	return uint16(offer.GetPort()) //nolint:gosec // checked just above
}

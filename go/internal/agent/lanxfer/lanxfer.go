// Package lanxfer carries a copy's `xfer` messages over TCP when both
// machines are on one LAN (ADR 0039). A data channel sends ~1.2 KB a packet,
// one syscall each: a 512 MiB copy cost ~3.5 s of CPU on each machine, TLS
// over TCP ~0.15 s. The WebRTC connection the grant opened stays: it carries
// the offer (port, certificate hash, token), so the TCP connection is bound
// to it without a new key, as a DTLS fingerprint is bound to a signed SDP.
package lanxfer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/clock"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

const (
	tokenSize = 32
	// acceptWait bounds the source's offer: the destination connects and
	// proves itself within it, or the copy stays on the data channel.
	acceptWait = 10 * time.Second
	// dialWait bounds the destination's side: a firewall that drops the
	// connection costs this much once per copy.
	dialWait = 3 * time.Second
	// A frame the offer comes in: XferLan is ~80 bytes.
	offerMax = 512
)

var (
	errStranger = errors.New("lanxfer: the connection did not prove itself")
	errLate     = errors.New("lanxfer: the destination came too late")
	errOffer    = errors.New("lanxfer: malformed offer")
	errWrongKey = errors.New("lanxfer: not the certificate the source offered")
)

// Offer answers the destination's `xfer-lan` channel: it listens on local,
// sends where and how to connect, and hands the one connection from remote
// that proves itself to serve, which owns it. A connection from another
// address is dropped and the wait goes on; one from remote that fails the
// token ends the offer. ch is closed when Offer returns.
//
// ch stays open while the copy runs and the TCP connection lives no longer
// than it: when the WebRTC connection goes (the grant's device removed, the
// destination gone), so does the copy, as it would on the data channel.
func Offer(ctx context.Context, clk clock.Clock, ch io.ReadWriteCloser, local, remote netip.Addr, serve func(io.ReadWriteCloser)) error {
	defer func() { _ = ch.Close() }()
	cert, sum, err := certificate(clk.Now())
	if err != nil {
		return fmt.Errorf("make the offer's certificate: %w", err)
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", netip.AddrPortFrom(local, 0).String())
	if err != nil {
		return fmt.Errorf("listen for the copy: %w", err)
	}
	defer func() { _ = ln.Close() }()
	at, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil {
		return fmt.Errorf("read the listener's port: %w", err)
	}
	token := make([]byte, tokenSize)
	_, _ = rand.Read(token)
	offer, err := proto.Marshal(&tilderv1.XferLan{Port: uint32(at.Port()), CertSha256: sum[:], Token: token})
	if err != nil {
		return err
	}
	if _, err = ch.Write(offer); err != nil {
		return fmt.Errorf("send the offer: %w", err)
	}
	conn, err := accept(ctx, clk, ln, remote, cert, token)
	if err != nil {
		return err
	}
	_ = ln.Close()
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		held(ch)
		_ = conn.Close()
	}()
	serve(conn)
	_ = ch.Close()
	<-watched
	return nil
}

// held returns once ch closes; what the other side sends on it is dropped.
func held(ch io.Reader) {
	buf := make([]byte, offerMax)
	for {
		if _, err := ch.Read(buf); err != nil {
			return
		}
	}
}

func accept(ctx context.Context, clk clock.Clock, ln net.Listener, remote netip.Addr, cert tls.Certificate, token []byte) (io.ReadWriteCloser, error) {
	// Closing the listener ends a waiting Accept: when the offer runs out, or
	// the copy's connection goes.
	expired := clk.AfterFunc(acceptWait, func() { _ = ln.Close() })
	defer expired.Stop()
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	for {
		c, err := ln.Accept()
		if err != nil {
			return nil, fmt.Errorf("wait for the destination: %w", err)
		}
		from, err := netip.ParseAddrPort(c.RemoteAddr().String())
		if err != nil || from.Addr().Unmap() != remote.Unmap() {
			_ = c.Close() // someone else on the LAN: not worth a handshake
			continue
		}
		return prove(clk, c, cert, token)
	}
}

// prove runs the handshake and reads the token, all within acceptWait.
func prove(clk clock.Clock, c net.Conn, cert tls.Certificate, token []byte) (io.ReadWriteCloser, error) {
	f := newFramed(tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}))
	cut := clk.AfterFunc(acceptWait, func() { _ = f.Close() })
	got := make([]byte, tokenSize)
	n, err := f.Read(got)
	if err != nil || n != tokenSize || subtle.ConstantTimeCompare(got, token) != 1 {
		cut.Stop()
		_ = f.Close()
		return nil, errStranger
	}
	if !cut.Stop() {
		return nil, errLate
	}
	return f, nil
}

// Dial reads the source's offer on ch and connects to it at remote, pinned
// to the certificate the offer named, then proves itself with the token.
// Any error leaves the copy on its data channel, and ch closed. On success
// ch stays open, held by the returned connection, whose Close closes both:
// the source ends the copy when ch goes.
func Dial(ctx context.Context, clk clock.Clock, ch io.ReadWriteCloser, remote netip.Addr) (io.ReadWriteCloser, error) {
	conn, err := dial(ctx, clk, ch, remote)
	if err != nil {
		_ = ch.Close()
		return nil, err
	}
	return &bound{ReadWriteCloser: conn, ch: ch}, nil
}

// bound is the copy's TCP connection with the channel that holds it open.
type bound struct {
	io.ReadWriteCloser
	ch io.Closer
}

func (b *bound) Close() error {
	_ = b.ch.Close()
	return b.ReadWriteCloser.Close()
}

func dial(ctx context.Context, clk clock.Clock, ch io.ReadWriteCloser, remote netip.Addr) (io.ReadWriteCloser, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	expired := clk.AfterFunc(dialWait, cancel)
	defer expired.Stop()
	// Unblocks the offer's read when the wait runs out.
	stop := context.AfterFunc(ctx, func() { _ = ch.Close() })
	defer stop()

	buf := make([]byte, offerMax)
	n, err := ch.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read the offer: %w", err)
	}
	offer := &tilderv1.XferLan{}
	if err = proto.Unmarshal(buf[:n], offer); err != nil || offer.GetPort() == 0 || offer.GetPort() > 65535 ||
		len(offer.GetCertSha256()) != sha256.Size || len(offer.GetToken()) != tokenSize {
		return nil, errOffer
	}
	port := uint16(offer.GetPort()) //nolint:gosec // checked ≤ 65535 above
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(remote, port).String())
	if err != nil {
		return nil, fmt.Errorf("connect to the source: %w", err)
	}
	want := offer.GetCertSha256()
	tc := tls.Client(c, &tls.Config{
		// No CA vouches for this certificate: the offer, which came over the
		// connection the grant opened, names it, and VerifyConnection holds
		// the source to exactly it.
		InsecureSkipVerify: true, //nolint:gosec // pinned in VerifyConnection
		MinVersion:         tls.VersionTLS13,
		VerifyConnection: func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) != 1 {
				return errWrongKey
			}
			got := sha256.Sum256(s.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], want) != 1 {
				return errWrongKey
			}
			return nil
		},
	})
	if err = tc.HandshakeContext(ctx); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("meet the source: %w", err)
	}
	f := newFramed(tc)
	if _, err = f.Write(offer.GetToken()); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("send the token: %w", err)
	}
	return f, nil
}

// certificate makes the one-use certificate an offer names. Its dates do
// not matter (the destination pins its hash) but x509 wants some.
func certificate(now time.Time) (tls.Certificate, [sha256.Size]byte, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, [sha256.Size]byte{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return tls.Certificate{}, [sha256.Size]byte{}, err
	}
	tmpl := &x509.Certificate{SerialNumber: serial, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return tls.Certificate{}, [sha256.Size]byte{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, sha256.Sum256(der), nil
}

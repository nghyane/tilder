package identity

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// MaxTransferLifetime bounds a transfer grant (ADR 0035): a copy the machine
// cannot finish in a day is started again by the owner, not left open.
const MaxTransferLifetime = 24 * time.Hour

// transferNonce is the grant's nonce length: it names the copy, on disk
// (.tilder-part/<id>) and on the wire, so it must not repeat.
const transferNonce = 16

const maxTransferText = 4096

// ErrTransferInvalid covers every way a transfer grant is refused: malformed,
// not signed by its device, not that device's owner, out of date. Callers
// say "not allowed" without saying which.
var ErrTransferInvalid = errors.New("identity: transfer grant rejected")

// Transfer is one of the owner's devices allowing machine Dst to pull SrcPath
// from machine Src, as DstPath, until NotAfter (ADR 0035). DstPath is where
// the copy goes, its name included (the console chose a free one, ADR 0036);
// its directory must exist. Paths are the agent's relative name bytes
// (ADR 0022); machines are their ids.
type Transfer struct {
	User     string
	Device   DevicePublic
	Src      string
	SrcPath  []byte
	Dst      string
	DstPath  []byte
	NotAfter time.Time
	Nonce    []byte
}

// Statement is what the device signs.
func (t Transfer) Statement() DeviceStatement {
	return DeviceStatement{statement("transfer",
		[2]string{"user", t.User},
		[2]string{"device", b64(t.Device.k[:])},
		[2]string{"src_machine", t.Src},
		[2]string{"src_path", b64(t.SrcPath)},
		[2]string{"dst_machine", t.Dst},
		[2]string{"dst_path", b64(t.DstPath)},
		[2]string{"not_after", strconv.FormatInt(t.NotAfter.Unix(), 10)},
		[2]string{"nonce", b64(t.Nonce)})}
}

// ID names the copy: the nonce, as base64url.
func (t Transfer) ID() string { return b64(t.Nonce) }

// VerifyTransfer checks a grant off the wire against the device cert that
// came with it (already verified against the machine's pinned root and its
// removed devices): exactly the canonical form, signed by that device, of
// that device's owner, no longer than MaxTransferLifetime, and valid at now
// within ClockSkew. The signature is checked over the received bytes.
func VerifyTransfer(text string, sig []byte, cert DeviceCert, now time.Time) (Transfer, error) {
	t, err := parseTransfer(text)
	if err != nil {
		return Transfer{}, err
	}
	if t.Device != cert.Device || t.User != cert.User() {
		return Transfer{}, ErrTransferInvalid
	}
	if !t.Device.Verify(DeviceStatement{text: []byte(text)}, sig) {
		return Transfer{}, ErrTransferInvalid
	}
	if now.Add(-ClockSkew).After(t.NotAfter) || t.NotAfter.Sub(now) > MaxTransferLifetime+ClockSkew {
		return Transfer{}, ErrTransferInvalid
	}
	return t, nil
}

// ReadTransfer reads a grant's text without verifying it: only for a grant
// this machine verified before and kept itself, to find and remove what its
// copy left once the grant is no longer good.
func ReadTransfer(text string) (Transfer, error) { return parseTransfer(text) }

// parseTransfer reads the exact canonical form: the kind line, then the
// eight fields in order, nothing else.
func parseTransfer(text string) (Transfer, error) {
	if len(text) > maxTransferText || !strings.HasSuffix(text, "\n") {
		return Transfer{}, ErrTransferInvalid
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	keys := []string{"user", "device", "src_machine", "src_path", "dst_machine", "dst_path", "not_after", "nonce"}
	if len(lines) != len(keys)+1 || lines[0] != "tilder/transfer/v2" {
		return Transfer{}, ErrTransferInvalid
	}
	v := make(map[string]string, len(keys))
	for i, key := range keys {
		k, val, ok := strings.Cut(lines[i+1], "=")
		if !ok || k != key {
			return Transfer{}, ErrTransferInvalid
		}
		v[key] = val
	}
	var t Transfer
	var err error
	t.User, t.Src, t.Dst = v["user"], v["src_machine"], v["dst_machine"]
	if t.Device, err = parseKey(v["device"], DevicePublicFromBytes); err != nil {
		return Transfer{}, ErrTransferInvalid
	}
	src, err1 := fromB64(v["src_path"])
	dst, err2 := fromB64(v["dst_path"])
	nonce, err3 := fromB64(v["nonce"])
	notAfter, err4 := strconv.ParseInt(v["not_after"], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(nonce) != transferNonce {
		return Transfer{}, ErrTransferInvalid
	}
	if t.User == "" || t.Src == "" || t.Dst == "" || t.Src == t.Dst {
		return Transfer{}, ErrTransferInvalid
	}
	t.SrcPath, t.DstPath, t.Nonce, t.NotAfter = src, dst, nonce, time.Unix(notAfter, 0)
	// The canonical form, rebuilt, must be the received text.
	if t.Statement().Text() != text {
		return Transfer{}, ErrTransferInvalid
	}
	return t, nil
}

package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strconv"
	"strings"
	"time"
)

// A join secret is 32 bytes (ADR 0004): the first half is what the
// rendezvous looks the join up by (it sees it, and stores only its hash);
// the second half never reaches the server. The agent proves its machine key
// with the second half, so the console that made the secret knows the key
// that joined is the one on the machine it ran the command on, whatever the
// server says.
const (
	JoinSecretSize = 32
	joinLookupSize = 16
)

// ErrJoinSecret means a join secret is not JoinSecretSize bytes.
var ErrJoinSecret = errors.New("identity: join secret is malformed")

// SplitJoinSecret returns the part the server may see, and the part only
// the console and the agent know.
func SplitJoinSecret(secret []byte) (lookup, auth []byte, err error) {
	if len(secret) != JoinSecretSize {
		return nil, nil, ErrJoinSecret
	}
	return secret[:joinLookupSize], secret[joinLookupSize:], nil
}

// JoinProof binds a machine key to a join secret's private half: the agent
// sends it, the console checks it before its root vouches for the key.
func JoinProof(auth []byte, key MachinePublic) []byte {
	mac := hmac.New(sha256.New, auth)
	mac.Write([]byte("tilder/join-proof/v2\n"))
	mac.Write(key.k[:])
	return mac.Sum(nil)
}

// Registration is the root's word that a machine key is one of the owner's
// machines (ADR 0004): the console trusts a machine key only with it, so a
// rendezvous cannot hand the console a machine of its own.
type Registration struct {
	Root    RootPublic
	Machine MachinePublic
	At      time.Time
}

// Statement is what the root signs.
func (r Registration) Statement() OwnerStatement {
	return OwnerStatement{statement("register",
		[2]string{"user", UserID(r.Root)},
		[2]string{"machine", MachineID(r.Machine)},
		[2]string{"machine_pub", b64(r.Machine.k[:])},
		[2]string{"at", strconv.FormatInt(r.At.Unix(), 10)})}
}

// ErrRegistration covers every way a registration fails to check out.
var ErrRegistration = errors.New("identity: registration is invalid")

// VerifyRegistration checks a registration off the wire against the root it
// must come from: exactly the canonical text, signed by root, not dated after
// now + ClockSkew. The machine id is re-derived from the key it names.
func VerifyRegistration(text string, sig []byte, root RootPublic, now time.Time) (Registration, error) {
	if len(text) > maxCertText || !strings.HasSuffix(text, "\n") {
		return Registration{}, ErrRegistration
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	keys := []string{"user", "machine", "machine_pub", "at"}
	if len(lines) != len(keys)+1 || lines[0] != "tilder/register/v2" {
		return Registration{}, ErrRegistration
	}
	v := make(map[string]string, len(keys))
	for i, key := range keys {
		k, val, ok := strings.Cut(lines[i+1], "=")
		if !ok || k != key {
			return Registration{}, ErrRegistration
		}
		v[key] = val
	}
	raw, err := fromB64(v["machine_pub"])
	if err != nil {
		return Registration{}, ErrRegistration
	}
	machine, err := MachinePublicFromBytes(raw)
	if err != nil {
		return Registration{}, ErrRegistration
	}
	at, err := strconv.ParseInt(v["at"], 10, 64)
	if err != nil {
		return Registration{}, ErrRegistration
	}
	r := Registration{Root: root, Machine: machine, At: time.Unix(at, 0)}
	if r.Statement().Text() != text || !root.Verify(OwnerStatement{text: []byte(text)}, sig) ||
		r.At.After(now.Add(ClockSkew)) {
		return Registration{}, ErrRegistration
	}
	return r, nil
}

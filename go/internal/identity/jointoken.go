package identity

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// The join token (ADR 0020): everything a new machine needs from the
// console, in the one string the owner pastes. It carries the root public
// key whole, not a hash of it (32 bytes is short enough; k3s hashes its CA
// only because a certificate is kilobytes), and a short check, so a string
// cut short or mistyped fails before anything is tried.
const (
	joinTokenPrefix  = "tilder1_"
	joinTokenCheck   = 4
	joinTokenPayload = JoinSecretSize + publicKeySize
	joinTokenDomain  = "tilder/join-token/v1\n" //nolint:gosec // G101: a hash domain, not a credential
)

// ErrJoinToken means a string is not a join token this build reads.
var ErrJoinToken = errors.New("identity: join token is malformed")

// JoinToken is a join secret and the root the machine will pin.
type JoinToken struct {
	// Secret is lookup (the server sees its hash) then auth (it never does).
	Secret [JoinSecretSize]byte
	Root   RootPublic
}

func joinTokenSum(payload []byte) []byte {
	h := sha256.New()
	h.Write([]byte(joinTokenDomain))
	h.Write(payload)
	return h.Sum(nil)[:joinTokenCheck]
}

// String is the token as the console prints it.
func (t JoinToken) String() string {
	root := t.Root.Raw32()
	payload := append(t.Secret[:], root[:]...)
	return joinTokenPrefix + base64.RawURLEncoding.EncodeToString(append(payload, joinTokenSum(payload)...))
}

// ParseJoinToken reads a token, refusing any that is cut short, altered, or
// of another version.
func ParseJoinToken(s string) (JoinToken, error) {
	body, ok := strings.CutPrefix(s, joinTokenPrefix)
	if !ok || base64.RawURLEncoding.DecodedLen(len(body)) != joinTokenPayload+joinTokenCheck {
		return JoinToken{}, ErrJoinToken
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(body)
	if err != nil || len(raw) != joinTokenPayload+joinTokenCheck {
		return JoinToken{}, ErrJoinToken
	}
	payload := raw[:joinTokenPayload]
	if !bytes.Equal(raw[joinTokenPayload:], joinTokenSum(payload)) {
		return JoinToken{}, ErrJoinToken
	}
	var t JoinToken
	copy(t.Secret[:], payload[:JoinSecretSize])
	var root [publicKeySize]byte
	copy(root[:], payload[JoinSecretSize:])
	t.Root = RootPublicFromRaw32(root)
	return t, nil
}

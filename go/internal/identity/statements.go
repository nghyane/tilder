package identity

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// Statements are the only bytes tilder ever signs (PROTOCOL §2): a versioned
// kind line, then key=value lines in a fixed order, values never containing a
// newline. Signing a text statement rather than protobuf bytes keeps what is
// signed identical in Go and TypeScript (vectors/statements.json pins it).
//
// Owner and machine statements are different types, so a machine signature
// can never be checked as an owner's, nor the reverse (the typed-digest idea
// of tailscale.com/types/tkatype).

// OwnerStatement is signed by the owner key.
type OwnerStatement struct{ text []byte }

// MachineStatement is signed by a machine key.
type MachineStatement struct{ text []byte }

// Text is the exact signed bytes, for vectors and debugging.
func (s OwnerStatement) Text() string { return string(s.text) }

// Text is the exact signed bytes, for vectors and debugging.
func (s MachineStatement) Text() string { return string(s.text) }

func statement(kind string, fields ...[2]string) []byte {
	var b strings.Builder
	b.WriteString("tilder/" + kind + "/v2\n")
	for _, f := range fields {
		b.WriteString(f[0] + "=" + f[1] + "\n")
	}
	return []byte(b.String())
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Digest is the SHA-256 of an SDP, as statements carry it.
func Digest(sdp string) []byte {
	sum := sha256.Sum256([]byte(sdp))
	return sum[:]
}

// DeviceHelloStatement is what a device signs to prove its key to the server
// over a fresh nonce; its device-cert comes alongside (ADR 0004).
func DeviceHelloStatement(nonce []byte, key DevicePublic) DeviceStatement {
	return DeviceStatement{statement("device-hello", [2]string{"nonce", b64(nonce)}, [2]string{"key", b64(key.k[:])})}
}

// AgentHelloStatement is what a machine signs to prove its key over a fresh nonce.
func AgentHelloStatement(nonce []byte, key MachinePublic) MachineStatement {
	return MachineStatement{statement("agent-hello", [2]string{"nonce", b64(nonce)}, [2]string{"key", b64(key.k[:])})}
}

// OfferStatement is what a device signs to ask one machine for one session
// with this SDP. The SDP carries the browser's DTLS fingerprint, so signing
// it pins who may complete the connection.
func OfferStatement(machineID string, sessionID []byte, sdp string) DeviceStatement {
	return DeviceStatement{statement("offer",
		[2]string{"machine", machineID},
		[2]string{"session", b64(sessionID)},
		[2]string{"sdp", b64(Digest(sdp))})}
}

// MachineOfferStatement is what a destination machine signs to ask the
// source machine for one session with this SDP, for one copy (ADR 0035). The
// grant's digest binds the connection to that copy: the source serves only
// what that grant names.
func MachineOfferStatement(toMachine, fromMachine string, sessionID []byte, sdp, grant string) MachineStatement {
	return MachineStatement{statement("machine-offer",
		[2]string{"machine", toMachine},
		[2]string{"from", fromMachine},
		[2]string{"session", b64(sessionID)},
		[2]string{"sdp", b64(Digest(sdp))},
		[2]string{"grant", b64(Digest(grant))})}
}

// AnswerStatement is what the machine signs to answer exactly that offer. Binding the offer
// digest means an answer cannot be replayed onto another session.
func AnswerStatement(machineID string, sessionID []byte, offerSDP, answerSDP string) MachineStatement {
	return MachineStatement{statement("answer",
		[2]string{"machine", machineID},
		[2]string{"session", b64(sessionID)},
		[2]string{"offer", b64(Digest(offerSDP))},
		[2]string{"sdp", b64(Digest(answerSDP))})}
}

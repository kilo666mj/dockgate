package protocol

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const tokenPrefix = "dgt1"

// JoinToken is what an operator gives a new agent: a single-use enrollment
// credential plus the SHA-256 pin of the server CA's public key, so the agent
// can trust the server on first contact without a pre-shared CA file.
type JoinToken struct {
	ID     string
	Secret string
	// CAPin is the lowercase hex SHA-256 of the CA certificate's
	// SubjectPublicKeyInfo.
	CAPin string
}

// String encodes the token as dgt1.<id>.<secret>.<ca-pin>.
func (t JoinToken) String() string {
	return strings.Join([]string{tokenPrefix, t.ID, t.Secret, t.CAPin}, ".")
}

// ParseJoinToken decodes a token produced by JoinToken.String.
func ParseJoinToken(s string) (JoinToken, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	if len(parts) != 4 || parts[0] != tokenPrefix {
		return JoinToken{}, errors.New("join token: want dgt1.<id>.<secret>.<ca-pin>")
	}
	t := JoinToken{ID: parts[1], Secret: parts[2], CAPin: parts[3]}
	if t.ID == "" || t.Secret == "" {
		return JoinToken{}, errors.New("join token: empty id or secret")
	}
	if pin, err := hex.DecodeString(t.CAPin); err != nil || len(pin) != 32 {
		return JoinToken{}, fmt.Errorf("join token: CA pin must be 64 hex characters")
	}
	return t, nil
}

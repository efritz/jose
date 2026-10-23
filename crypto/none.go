package crypto

import (
	"crypto"
	"encoding/json"
)

// The upstream package registered a placeholder hash for crypto.Hash(0) in an
// init function so the "none" algorithm had a Hasher. Go 1.27 made
// crypto.RegisterHash panic on an unknown hash function, which crashed every
// binary linking this package at startup. SigningMethodNone never computes a
// digest (Sign and Verify ignore their input), so the registration is dropped.

// Unsecured is the default "none" algorithm.
var Unsecured = &SigningMethodNone{
	Name: "none",
	Hash: crypto.Hash(0),
}

// SigningMethodNone is the default "none" algorithm.
type SigningMethodNone struct {
	Name string
	Hash crypto.Hash
	_    struct{}
}

// Verify helps implement the SigningMethod interface.
func (_ *SigningMethodNone) Verify(_ []byte, _ Signature, _ interface{}) error {
	return nil
}

// Sign helps implement the SigningMethod interface.
func (_ *SigningMethodNone) Sign(_ []byte, _ interface{}) (Signature, error) {
	return nil, nil
}

// Alg helps implement the SigningMethod interface.
func (m *SigningMethodNone) Alg() string {
	return m.Name
}

// Hasher helps implement the SigningMethod interface.
func (m *SigningMethodNone) Hasher() crypto.Hash {
	return m.Hash
}

// MarshalJSON implements json.Marshaler.
// See SigningMethodECDSA.MarshalJSON() for information.
func (m *SigningMethodNone) MarshalJSON() ([]byte, error) {
	return []byte(`"` + m.Alg() + `"`), nil
}

var _ json.Marshaler = (*SigningMethodNone)(nil)

package jws

import (
	"crypto"
	"testing"

	c "github.com/SermoDigital/jose/crypto"
)

// MySigningMethod is the default "none" algorithm.
var MySigningMethod = &TestSigningMethod{
	Name: "SuperSignerAlgorithm1000",
	Hash: crypto.SHA256,
}

type TestSigningMethod struct {
	Name string
	Hash crypto.Hash
}

func (m *TestSigningMethod) Verify(_ []byte, _ c.Signature, _ interface{}) error {
	return nil
}

func (m *TestSigningMethod) Sign(_ []byte, _ interface{}) (c.Signature, error) {
	return nil, nil
}

func (m *TestSigningMethod) Alg() string         { return m.Name }
func (m *TestSigningMethod) Sum(b []byte) []byte { return nil }
func (m *TestSigningMethod) Hasher() crypto.Hash { return m.Hash }

// GetSigningMethod is implicitly tested inside the following two functions.

func TestRegisterSigningMethod(t *testing.T) {

	RegisterSigningMethod(MySigningMethod)

	if GetSigningMethod("SuperSignerAlgorithm1000") == nil {
		t.Error("Expected SuperSignerAlgorithm1000, got nil")
	}

	RemoveSigningMethod(MySigningMethod)
}

func TestRemoveSigningMethod(t *testing.T) {
	RegisterSigningMethod(MySigningMethod)

	if GetSigningMethod("SuperSignerAlgorithm1000") == nil {
		t.Error("Expected SuperSignerAlgorithm1000, got nil")
	}

	RemoveSigningMethod(MySigningMethod)

	if a := GetSigningMethod("SuperSignerAlgorithm1000"); a != nil {
		t.Errorf("Expected nil, got %v", a)
	}
}

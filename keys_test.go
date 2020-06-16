package sshutil

import (
	"errors"
	"testing"
)

type badReader struct {}
var errBadRand = errors.New("no entropy")
func (reader badReader) Read(b []byte) (n int, err error) {
	return 0, errBadRand
}

type goodReader struct {}
func (reader goodReader) Read(b []byte) (n int, err error) {
	emptyKey := make([]byte, len(b))
	copy(b, emptyKey)
	return len(b), nil
}

func TestGenerateKey_Bad(t *testing.T) {
	s, err := GenerateKeyRand(badReader{})
	if s != nil {
		t.Error("expected nil signer")
	}
	if err != errBadRand {
		t.Error("expected error")
	}
}

func TestGenerateKeyRand_Okay(t *testing.T) {
	s, err := GenerateKeyRand(goodReader{})
	if err != nil {
		t.Errorf("error generating key %v", err)
	}
	if s == nil {
		t.Error("expected non-nil key")
	}
	if s.PublicKey().Type() != "ecdsa-sha2-nistp256" {
		t.Error("expected 256 bit ecdsa key")
		t.Errorf("got %s", s.PublicKey().Type())
	}
}

func TestGenerateKey_Okay(t *testing.T) {
	ssh, err := GenerateKey()
	if err != nil {
		t.Errorf("error generating key %v", err)
	}
	if ssh == nil {
		t.Error("expected non-nil key")
	}
}


package sshutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

// LoadHostKeyFromFile returns an ssh.Signer from the key stored at the given
// filesystem path, decrypted using pass.
func LoadHostKeyFromFile(path, pass string) (ssh.Signer, error) {
	// Read host key from a file, parse using x/crypto/ssh.
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParsePrivateKeyWithPassphrase(bytes, []byte(pass))
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateKey creates an in-momory ssh ecdsa p256 key to be used with the
// x/crypto/ssh package.
func GenerateKey() (ssh.Signer, error) {
	return GenerateKeyRand(rand.Reader)
}

// GenerateKeyRand creates  an in-momory ssh ecdsa p256 key to be used with the
// x/crypto/ssh package. Supply an arbitrary rand reader r.
func GenerateKeyRand(r io.Reader) (ssh.Signer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromSigner(priv)
}

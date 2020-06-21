package sshutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

// LoadCertFromKeyFileOpenSSH returns an ssh.Signer from the unencrypted key
// stored at the given filesystem path with a public key that is the ssh
// certificate loaded from the file "<path>-cert.pub". This is how ssh-add looks
// for certs when adding keys to ssh-agent.
func LoadCertFromKeyFileOpenSSH(keypath string) (ssh.Signer, error) {
	certpath := keypath + "-cert.pub"
	return LoadCertFromFiles(keypath, certpath)
}

// LoadCertFromFiles returns an ssh.Signer with private key loaded from the
// unecrypted path keypath and a public cert component loaded from certpath.
func LoadCertFromFiles(keypath, certpath string) (ssh.Signer, error) {
	// Read host key from a file, parse using x/crypto/ssh.
	kb, err := ioutil.ReadFile(keypath)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParsePrivateKey(kb)
	if err != nil {
		return nil, err
	}
	cb, err := ioutil.ReadFile(certpath)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(cb)
	if err != nil {
		return nil, err
	}
	cert := pub.(*ssh.Certificate)
	signer, err := ssh.NewCertSigner(cert, key)
	return signer, nil
}

// LoadKeyFromFile returns an ssh.Signer from the unencrypted key stored
// at the given filesystem path.
func LoadKeyFromFile(path string) (ssh.Signer, error) {
	// Read host key from a file, parse using x/crypto/ssh.
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParsePrivateKey(bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// LoadKeyFromFileWithPass returns an ssh.Signer from the key stored at the
// given filesystem path, decrypted using pass.
func LoadKeyFromFileWithPass(path, pass string) (ssh.Signer, error) {
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

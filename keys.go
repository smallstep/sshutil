package sshutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"os"

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

// LoadCertFromKeyFileEncOpenSSH returns an ssh.Signer from the encrypted key
// stored at the given filesystem path with a public key that is the ssh
// certificate loaded from the file "<path>-cert.pub". This is how ssh-add looks
// for certs when adding keys to ssh-agent.
func LoadCertFromKeyFileEncOpenSSH(keypath string, pass []byte) (ssh.Signer, error) {
	certpath := keypath + "-cert.pub"
	return LoadCertFromFilesEnc(keypath, certpath, pass)
}

// LoadCertFromFiles returns an ssh.Signer with private key loaded from the
// unecrypted path keypath and a public cert component loaded from certpath.
func LoadCertFromFiles(keypath, certpath string) (ssh.Signer, error) {
	// Read host key from a file, parse using x/crypto/ssh.
	kb, err := os.ReadFile(keypath)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParsePrivateKey(kb)
	if err != nil {
		return nil, err
	}
	cb, err := os.ReadFile(certpath)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(cb)
	if err != nil {
		return nil, err
	}
	cert := pub.(*ssh.Certificate)
	return ssh.NewCertSigner(cert, key)
}

// LoadCertFromFilesEnc returns an ssh.Signer with private key loaded from the
// ecrypted key at path keypath and a public cert component loaded from certpath.
func LoadCertFromFilesEnc(keypath, certpath string, pass []byte) (ssh.Signer, error) {
	// Read host key from a file, parse using x/crypto/ssh.
	kb, err := os.ReadFile(keypath)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParsePrivateKeyWithPassphrase(kb, pass)
	if err != nil {
		return nil, err
	}
	cb, err := os.ReadFile(certpath)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(cb)
	if err != nil {
		return nil, err
	}
	cert := pub.(*ssh.Certificate)
	return ssh.NewCertSigner(cert, key)
}

// LoadKeyFromFile returns an ssh.Signer from the unencrypted key stored
// at the given filesystem path.
func LoadKeyFromFile(path string) (ssh.Signer, error) {
	// Read host key from a file, parse using x/crypto/ssh.
	bytes, err := os.ReadFile(path)
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
	bytes, err := os.ReadFile(path)
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

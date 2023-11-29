package sshutil

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestServer(t *testing.T) {
	ln, err := net.Listen("tcp", "localhost:")
	if err != nil {
		t.Fatalf("err listening on localhost: %v", err)
	}

	subject := &Server{}
	subject.Channel("echo", ChannelHandlerFunc(echo))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		// Blocks until Close/Shutdown is called
		err := subject.Serve(ln)
		if !errors.Is(err, ErrServerClosed) {
			t.Errorf("Got incorrect error: %v, expecting %v", err, ErrServerClosed)
		}
		t.Log("server done")
		wg.Done()
	}()

	signer, err := GenerateKey()
	if err != nil {
		subject.Close()
		t.Fatalf("couldn't generate client key")
	}
	fp := ssh.FingerprintSHA256(signer.PublicKey())
	t.Logf("Client public key fingerprint '%s'", fp)

	config := &ssh.ClientConfig{
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", ln.Addr().String(), config)
	//client, err := ssh.Dial("tcp", "localhost:2022", config)
	if err != nil {
		subject.Close()
		t.Fatalf("error dialing server: %v", err)
	}
	stream, reqs, err := client.OpenChannel("echo", nil)
	if err != nil {
		subject.Close()
		t.Fatalf("error opening channel: %v", err)
	}
	go ssh.DiscardRequests(reqs)

	msg := []byte("ssh test")
	_, err = stream.Write(msg)
	if err != nil {
		t.Fatalf("unexpected error writing test message")
	}
	stream.CloseWrite()

	reply := make([]byte, len(msg))
	_, err = stream.Read(reply)
	if err != nil {
		t.Fatalf("unexpected error reading test message")
	}
	if !bytes.Equal(msg, reply) {
		t.Errorf("unexpected reply from server: '%s'", reply)
	}
	stream.Close()

	subject.Shutdown()
	wg.Wait()

	client.Close()
	subject.Idle.Wait()
}

func echo(stream Channel, reqs <-chan *ssh.Request) {
	go ssh.DiscardRequests(reqs)
	io.Copy(stream, stream)
}

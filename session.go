package sshutil

import (
	"fmt"
	"io"
	"log"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// SessionFunc is called when a new ssh "session" channel is established.
type SessionFunc func(session *Session)

// SessionRequestHandler is like the server global request handler but
// includes a Session parameter so that infor can be sent to the session's
// data channels.
type SessionRequestHandler interface {
	ServeRequest(s *Session, r *ssh.Request)
}

// SessionReqHandlerFunc is ye ol' http/handler adapter type.
// https://golang.org/src/net/http/server.go#L2004
type SessionReqHandlerFunc func(s *Session, req *ssh.Request)

// ServeRequest calls f(r).
func (f SessionReqHandlerFunc) ServeRequest(s *Session, r *ssh.Request) {
	f(s, r)
}

// DefaultSessionHandler is an echo terminal.
func DefaultSessionHandler() *SessionHandler {
	return NewSessionHandler(defaultSessionFunc)
}

// NewSessionHandler returns SessionHandler with common request handling setup.
func NewSessionHandler(fn SessionFunc) *SessionHandler {
	sh := &SessionHandler{
		SessionFunc:     fn,
		RequestHandlers: make(map[string]SessionRequestHandler),
	}
	sh.RequestHandlers["shell"] = Ack()
	sh.RequestHandlers["pty-req"] = Ack()
	sh.RequestHandlers["env"] = SessionReqHandlerFunc(func(s *Session, req *ssh.Request) {
		var env Env
		err := ssh.Unmarshal(req.Payload, &env)
		if err != nil {
			e := fmt.Errorf("error unmarshaling env payload: %v", err)
			s.Errors <- e
			return
		}
		s.Envs <- env
		Ack().ServeRequest(s, req)
	})
	sh.RequestHandlers["signal"] = SessionReqHandlerFunc(func(s *Session, req *ssh.Request) {
		var p struct{ Signal ssh.Signal }
		err := ssh.Unmarshal(req.Payload, &p)
		if err != nil {
			e := fmt.Errorf("error unmarshaling signal payload: %v", err)
			s.Errors <- e
		}
		s.Signals <- p.Signal
	})
	sh.DefaultHandler = Discard()
	return sh
}

// SessionHandler can be used with a Server to spawn session handling loging on
// incomming "session" channels.
type SessionHandler struct {
	L               log.Logger
	RequestHandlers map[string]SessionRequestHandler
	DefaultHandler  SessionRequestHandler
	SessionFunc     SessionFunc
}

// Session represents an ssh channel of type "session". In general, a session
// means the execution of a remote command, with reqpect to the client.
type Session struct {
	Channel
	Terminal *terminal.Terminal
	Lines    chan string
	Envs     chan Env
	Signals  chan ssh.Signal
	Errors   chan error
	L        *log.Logger
}

// ServeChannel sets up a session, b and kicks off request processing.
func (sh *SessionHandler) ServeChannel(channel Channel, requests <-chan *ssh.Request) {
	s := &Session{
		Channel:  channel,
		Terminal: terminal.NewTerminal(channel, "> "),
		Envs:     make(chan Env),
		Lines:    make(chan string),
		Signals:  make(chan ssh.Signal),
		L:        channel.Conn.Server.L,
	}
	defer s.Close()
	go func() {
		for {
			line, err := s.Terminal.ReadLine()
			if err != nil && err == io.EOF {
				s.Lines <- ""
				return
			}
			s.Lines <- line
		}
	}()
	go sh.process(s, requests)
	sh.SessionFunc(s)
}

func defaultSessionFunc(session *Session) {
	environment := make(map[string]string)
	for {
		select {
		case <-session.Context.Done():
			session.Terminal.SetPrompt("")
			session.Terminal.Write([]byte("\nGoodbye!\n"))
			return
		case env := <-session.Envs:
			environment[env.Key] = env.Value
		case sig := <-session.Signals:
			session.L.Printf("Got signal: %s", sig)
			switch sig {
			case ssh.SIGTERM:
				return
			case ssh.SIGUSR1:
				var msg strings.Builder
				for k, v := range environment {
					row := fmt.Sprintf("%s=%s\n", k, v)
					msg.WriteString(row)
				}
				session.Terminal.Write([]byte(msg.String()))
			}
		case line := <-session.Lines:
			if line == "" {
				return
			}
			out := fmt.Sprintf("%s\n", line)
			session.Terminal.Write([]byte(out))
		}
	}
}

// Env is the payload data sent during an "env" request.
type Env struct{ Key, Value string }

func (sh *SessionHandler) process(session *Session, requests <-chan *ssh.Request) {
	for req := range requests {
		h, exists := sh.RequestHandlers[req.Type]
		if !exists {
			h = sh.DefaultHandler
		}
		h.ServeRequest(session, req)
	}
}

// Ack affirmatively acknowleges a request. Ack does not send a payload.
func Ack() SessionRequestHandler {
	return SessionReqHandlerFunc(func(_ *Session, req *ssh.Request) {
		req.Reply(true, nil)
	})
}

// Reject responsed negatively to a request. Reject does not send a payload.
func Reject() SessionRequestHandler {
	return SessionReqHandlerFunc(func(_ *Session, req *ssh.Request) {
		req.Reply(false, nil)
	})
}

// Discard replies false to requests that want a reply, otherwise it ignores
// the request.
func Discard() SessionRequestHandler {
	return SessionReqHandlerFunc(func(_ *Session, req *ssh.Request) {
		if req.WantReply {
			req.Reply(false, nil)
		}
	})
}

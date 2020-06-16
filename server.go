package sshutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// Server does ssh.
//
// The zero value of Server is a valid Server. If the config is not specified,
// the DefaultServerConfig() is used and an ephemeral host key is generated on
// Server initialization.
type Server struct {
	Addr   string
	Config *ssh.ServerConfig

	ConnectionHook ConnectionHook
	HandshakeHook  HandshakeHook
	DepartureHook  DepartureHook

	GlobalRequests        map[string]RequestHandler
	DefaultRequestHandler RequestHandler

	ChannelHandlers       map[string]ChannelHandler
	DefaultChannelHandler ChannelHandler

	L *log.Logger

	Idle        sync.WaitGroup

	mu          sync.RWMutex
	once        sync.Once
	ctx         context.Context
	listeners   map[io.Closer]struct{}
	connections map[string]io.Closer
	shutdown    uint64
	closed      uint64
	cancel      context.CancelFunc
}

var logger = log.New(os.Stderr, "ssh: ", log.LstdFlags)

// ConnectionHook allows for custom connection logic after a connection is
// established but prior to the SSH handshake. A non-nil error means c will
// be closed and no handshake will be performed.
type ConnectionHook func(c net.Conn) (net.Conn, error)

// HandshakeHook allows execution of code right after a successful handshake
// on a new connection. The full ssh.ServerConn is provided to the hook whereas
// the ssh.AuthLogCallback hook available in the server config only provides
// connection metadata.
type HandshakeHook func(conn *ServerConn) error

// DepartureHook allows execution of code during teardown of an authenticated
// connection (handshake completed). The provided connection may already be
// closed if the peer departed of their own volition.
type DepartureHook func(conn *ServerConn)

// RequestHandler is called for incoming global requests.
type RequestHandler interface {
	ServeRequest(r *ssh.Request)
}

// RequestHandlerFunc is ye ol' http/handler adapter type.
// https://golang.org/src/net/http/server.go#L2004
type RequestHandlerFunc func(r *ssh.Request)

// ServeRequest calls f(r).
func (f RequestHandlerFunc) ServeRequest(r *ssh.Request) {
	f(r)
}

// ChannelHandler is called for each new ssh stream. When the provided context
// is canceled, the ctx.Done chan will have data ready.
type ChannelHandler interface {
	ServeChannel(stream Channel, requests <-chan *ssh.Request)
}

// ChannelHandlerFunc is ye ol' http/handler adapter type.
// https://golang.org/src/net/http/server.go#L2004
type ChannelHandlerFunc func(stream Channel, requests <-chan *ssh.Request)

// ServeChannel calls f(stream, requests).
func (f ChannelHandlerFunc) ServeChannel(stream Channel, requests <-chan *ssh.Request) {
	f(stream, requests)
}

// DefaultServerConfig allows public key auth from any client presenting a key
// or certificate.
// TODO rename this "InsecureOpenServerConfig"?
func DefaultServerConfig() *ssh.ServerConfig {
	return &ssh.ServerConfig{
		PublicKeyCallback: allowAllPublicKeys,
	}
}

func allowAllPublicKeys(meta ssh.ConnMetadata, pubkey ssh.PublicKey) (*ssh.Permissions, error) {
	return &ssh.Permissions{
		// Record the public key used for authentication.
		Extensions: map[string]string{
			"pubkey-fp": ssh.FingerprintSHA256(pubkey),
		},
	}, nil
}

// init must be called prior to serving connections. init is safe to be called
// arbitrarily. If init returns an error the server should not proceed with
// serving connections and convey such to the caller.
func (srv *Server) init() error {
	var failure error
	srv.once.Do(func() {
		if srv.L == nil {
			srv.L = logger
		}

		srv.listeners = make(map[io.Closer]struct{})
		srv.connections = make(map[string]io.Closer)
		srv.ctx, srv.cancel = context.WithCancel(context.Background())

		if srv.Config == nil {
			// copy the default config
			config := DefaultServerConfig()

			// Use an ephemeral key.
			signer, err := GenerateKey()
			if err != nil {
				failure = err
				return
			}
			f := ssh.FingerprintSHA256(signer.PublicKey())
			srv.L.Printf("Server ephermeral key '%s'", f)
			config.AddHostKey(signer)
			srv.Config = config
		}

		if srv.ConnectionHook == nil {
			srv.ConnectionHook = defaultConncectionHook
		}
		if srv.HandshakeHook == nil {
			srv.HandshakeHook = defaultHandshakeHook
		}
		if srv.DepartureHook == nil {
			srv.DepartureHook = defaultDepartureHook
		}
		if srv.DefaultRequestHandler == nil {
			srv.DefaultRequestHandler = RequestHandlerFunc(defaultRequestFunc)
		}
		if srv.GlobalRequests == nil {
			srv.GlobalRequests = make(map[string]RequestHandler)
		}
		// Setting a DefaultChannelHandler would cause every type of
		// channel to be accepted. Instead, add a default session
		// handler.
		if srv.ChannelHandlers == nil {
			srv.ChannelHandlers = make(map[string]ChannelHandler)
			srv.ChannelHandlers["session"] = DefaultSessionHandler()
		}
	})
	return failure
}

// ErrServerClosed is returned from ListenAndServe and Serve when either
// method returnd due to a call to Close or Shutdown.
var ErrServerClosed = errors.New("ssh: Server closed")

// ListenAndServe blocks listening on Server.Addr. If Addr is empty, the
// server listens on localhost:22, the ssh port. The returned error is never
// nil. After Shutdown or Close, this method returns ErrServerClosed.
func (srv *Server) ListenAndServe() error {
	if srv.ShutdownCalled() {
		return ErrServerClosed
	}
	addr := srv.Addr
	if addr == "" {
		addr = ":22"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return srv.Serve(ln)
}

// Serve blocks accepting connections on the provided listener. Serve always
// returns a non-nil error and closes listener. After Shutdown or Close, the
// returned error is ErrServerClosed.
func (srv *Server) Serve(listener net.Listener) error {
	// Synchonize on an initialized Server
	if err := srv.init(); err != nil {
		listener.Close()
		return err
	}
	if err := srv.trackListener(listener); err != nil {
		listener.Close()
		return err
	}
	defer srv.forgetListener(listener)

	srv.L.Printf("Server commence listening on %s", listener.Addr())

	// Delay inspired by net/http:
	var delay time.Duration
	delayedTryAgain := func(err error) {
		if delay == 0 {
			delay = 5 * time.Millisecond
		} else {
			delay *= 2
		}
		if max := 1 * time.Second; delay > max {
			delay = max
		}
		srv.L.Printf("ssh: Accept error: %v; retrying in %v", err, delay)
		time.Sleep(delay)
	}

	// Accept loop:
	for {
		conn, err := listener.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Temporary() {
				delayedTryAgain(ne)
				continue
			}
			addr := listener.Addr().String()
			srv.L.Printf("Server finished listening on %s", addr)
			if srv.ShutdownCalled() {
				return ErrServerClosed
			}
			return err
		}
		srv.Idle.Add(1)
		c, err := srv.ConnectionHook(conn)
		if err != nil {
			conn.Close()
			srv.Idle.Done()
			continue
		}
		go srv.handshake(c)
	}
}

func defaultConncectionHook(conn net.Conn) (net.Conn, error) {
	return conn, nil
}

// ShutdownCalled reports whether the server is Shutdown or not.
func (srv *Server) ShutdownCalled() bool {
	return atomic.LoadUint64(&srv.shutdown) == 1
}

// Shutdown stops any listen loops from accepting new connections and closes
// all tracked listeners. Active connections are not closed.
func (srv *Server) Shutdown() error {
	if !atomic.CompareAndSwapUint64(&srv.shutdown, 0, 1) {
		return ErrServerClosed
	}
	// First call to Shutdown. Stop listen loops:
	for l := range srv.listeners {
		err := l.Close()
		if err != nil {
			return err
		}
	}
	// Notify handlers so they can wind down gracefully.
	srv.cancel()
	return nil
}

// CloseCalled reports whether the server is Closed or not. A closed server
// does not allow new connections to be tracked.
func (srv *Server) CloseCalled() bool {
	return atomic.LoadUint64(&srv.closed) == 1
}

// Close stops the server immediately. Close calls Shutdown and then procedes
// to close any open connections. ...A close handler allows you inject custom
// teardown logic on an open ssh stream...
func (srv *Server) Close() error {
	err := srv.Shutdown()
	if err != nil && err != ErrServerClosed {
		return err
	}
	if !atomic.CompareAndSwapUint64(&srv.closed, 0, 1) {
		return ErrServerClosed
	}
	// First call to Close. Drain connections forcibly:
	for _, c := range srv.connections {
		err := c.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (srv *Server) handshake(c net.Conn) {
	// Before use, a handshake must be performed on the incoming net.Conn.
	ssh, channels, global, err := ssh.NewServerConn(c, srv.Config)
	if err != nil {
		srv.L.Printf("Server handshake failure '%v'", err)
		c.Close()
		srv.Idle.Done()
		return
	}
	ctx, cancel := context.WithCancel(srv.ctx)
	conn := &ServerConn{
		ServerConn: ssh,
		Context:    connectionContext(ctx, ssh),
		Server:     srv,
	}
	defer srv.Idle.Done()
	defer conn.Close()
	defer cancel()
	if err := srv.trackConnection(conn); err != nil {
		return
	}
	defer srv.forgetConnection(conn)
	if err := srv.HandshakeHook(conn); err != nil {
		return
	}
	defer srv.DepartureHook(conn)

	// Process the global requests
	go srv.handleRequests(global)

	// Process the channels
	srv.ssh(conn, channels)

}

func defaultHandshakeHook(conn *ServerConn) error {
	pk := conn.Permissions.Extensions["pubkey-fp"]
	conn.Server.L.Printf("Server peer accession '%s'", pk)
	return nil
}

func defaultDepartureHook(conn *ServerConn) {
	pk := conn.Permissions.Extensions["pubkey-fp"]
	conn.Server.L.Printf("Server peer egression '%s'", pk)
}

type ctxKey int

const (
	_ ctxKey = iota
	// CtxKeyClientVersion retrieves the client version string associated with
	// the connection.
	CtxKeyClientVersion

	// CtxKeyLocalAddr retrieves the address on which the incomming connection
	// was accepted.
	CtxKeyLocalAddr

	// CtxKeyPermissions retrieves the permissions set during authentication.
	// The ssh.Permissions type is used to convey information up the stack.
	CtxKeyPermissions

	// CtxKeyRemoteAddr retrieve the address of the client with which the server
	// is communicating.
	CtxKeyRemoteAddr

	// CtxKeyServerVersion retrieves the server version string the Server sent to
	// the client during the ssh handshake.
	CtxKeyServerVersion

	// CtxKeySessionID retrieves a string that is unique per-connection.
	CtxKeySessionID
)

func connectionContext(ctx context.Context, conn *ssh.ServerConn) context.Context {
	ctx = context.WithValue(ctx, CtxKeyClientVersion, string(conn.ClientVersion()))
	ctx = context.WithValue(ctx, CtxKeyLocalAddr, conn.LocalAddr())
	ctx = context.WithValue(ctx, CtxKeyPermissions, conn.Permissions)
	ctx = context.WithValue(ctx, CtxKeyRemoteAddr, conn.RemoteAddr())
	ctx = context.WithValue(ctx, CtxKeyServerVersion, string(conn.ServerVersion()))
	ctx = context.WithValue(ctx, CtxKeySessionID, conn.SessionID())
	return ctx
}

// ServerConn is a facade that decorates an embedded ssh.ServerConn with an
// associated context and a reference to the server instance.
type ServerConn struct {
	*ssh.ServerConn
	Context context.Context
	Server  *Server
}

func (srv *Server) ssh(conn *ServerConn, channels <-chan ssh.NewChannel) {
	for candidate := range channels {
		t := candidate.ChannelType()
		srv.mu.RLock()
		handler, ok := srv.ChannelHandlers[t]
		srv.mu.RUnlock()
		if !ok {
			handler = srv.DefaultChannelHandler
		}
		if handler == nil {
			unknown := ssh.UnknownChannelType
			err := candidate.Reject(unknown, "unknown channel type")
			if err != nil {
				log.Printf("reject %s: %v", t, err)
			}
			continue
		}
		channel, requests, err := candidate.Accept()
		if err != nil {
			srv.L.Printf("accept %s: %v", t, err)
			continue
		}
		ctx, cancel := context.WithCancel(conn.Context)
		defer cancel()
		stream := Channel{
			Channel: channel,
			Context: ctx,
			Conn:    conn,
		}
		go handler.ServeChannel(stream, requests)
	}
}

// Channel is a facade that decorates an embedded ssh.Channel with a context
// and a referrence to the server instance.
type Channel struct {
	ssh.Channel
	Context context.Context
	Conn    *ServerConn
}

func (srv *Server) handleRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		srv.mu.RLock()
		handler, ok := srv.GlobalRequests[req.Type]
		srv.mu.RUnlock()
		if !ok {
			handler = srv.DefaultRequestHandler
		}
		handler.ServeRequest(req)
	}
}

// discard request
func defaultRequestFunc(req *ssh.Request) {
	if req.WantReply {
		req.Reply(false, nil)
	}
}

// GlobalRequest registers a handler to be called on incomming global requests
// of type reqType. Only one handler may be registered for a given reqType. It
// is an error if this method is called twice with the same reqType.
func (srv *Server) GlobalRequest(reqType string, h RequestHandler) error {
	err := srv.init()
	if err != nil {
		return err
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	_, exists := srv.GlobalRequests[reqType]
	if exists {
		return fmt.Errorf("ssh: request name '%s' already registered", reqType)
	}
	srv.GlobalRequests[reqType] = h
	return nil
}

// Channel registers a handler for incomming channels named name.
func (srv *Server) Channel(name string, handler ChannelHandler) error {
	err := srv.init()
	if err != nil {
		return err
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	_, exists := srv.ChannelHandlers[name]
	if exists {
		return fmt.Errorf("ssh: channel name '%s' already registered", name)
	}
	srv.ChannelHandlers[name] = handler
	return nil
}

func (srv *Server) trackListener(ln net.Listener) error {
	if srv.ShutdownCalled() {
		return ErrServerClosed
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	_, exists := srv.listeners[ln]
	if exists {
		return errors.New("ssh: listener already registered")
	}
	srv.listeners[ln] = struct{}{}
	return nil
}

func (srv *Server) forgetListener(ln net.Listener) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.listeners, ln)
}

func (srv *Server) trackConnection(c *ServerConn) error {
	if srv.CloseCalled() {
		return ErrServerClosed
	}
	id := string(c.SessionID())
	srv.mu.Lock()
	defer srv.mu.Unlock()
	_, exists := srv.connections[id]
	if exists {
		return errors.New("ssh: connection already registered")
	}
	srv.connections[id] = c
	return nil

}

func (srv *Server) forgetConnection(c *ServerConn) {
	id := string(c.SessionID())
	srv.mu.Lock()
	defer srv.mu.Unlock()
	delete(srv.connections, id)
}

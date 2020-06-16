# sshutil

A [single-dependency][gomod] utility package that provides a [`net/http`][net-http] style SSH server.

`sshutil` is part of the [Smallstep][smallstep] crypto suite ([step][], [step-ca][], etc.).

[gomod]: https://github.com/smallstep/sshutil/blob/master/go.mod
[net-http]: https://golang.org/pkg/net/http/
[smallstep]: https://smallstep.com/docs
[step]: https://github.com/smallstep/cli
[step-ca]: https://github.com/smallstep/certificates

## Why sshutil?

The sshutil package depends solely on the Go [`x/crypto`][crypto] module.
Go's [`x/crypto/ssh`][crypto-ssh] package provides convenient support for both the [ssh wire protocol][rfc4253] and the [ssh authentication protocol][rfc4252].
The authentication protocol implementation is scoped to single connections.
A small, but tedious, amount of work is required to implement a full connection-tracking server.
`sshutil` fills in the gap.

[crypto]: https://pkg.go.dev/golang.org/x/crypto
[crypto-ssh]: https://pkg.go.dev/golang.org/x/crypto/ssh
[rfc4252]: https://tools.ietf.org/html/rfc4252
[rfc4253]: https://tools.ietf.org/html/rfc4253

## Examples

### Hello SSH

```golang
package main

import "go.step.sm/sshutil"

func() hello(stream sshutil.Session) {
	stream.Terminal.Write([]byte("Hello SSH\n")
}

func main() {
	server := &sshutil.Server{ Addr: ":2022" }
	server.Channel("session", sshutil.NewSessionHandler(hello))
	server.ListenAndServe()
}
```

Output:
```
$ ./main
$ ssh localhost -p 2022
Hello SSH
Server closed remote connection to localhost.
```

### Echo server

The default session handler is an echo server.
Easily configure a persistent host key.

```golang
package main

import (
	"log"

	"go.step.sm/sshutil"
)

func main() {
	server := &sshutil.Server{
		Addr: ":2022",
		Config: sshutil.DefaultServerConfig(),
	}

	key, err := sshutil.LoadHostKeyFromFile("example/server.key", "")
	if err != nil {
		log.Fatalf("error loading key: %v", err)
	}
	server.Config.AddHostKey(key)

	err = server.ListenAndServe()
	log.Print(err)
}
```

Output:
```
$ ssh localhost -p 2022
> echo
echo
> ^D
Client closed connection to localhost.
```


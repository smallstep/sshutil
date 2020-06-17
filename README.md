# sshutil

A [single-dependency][gomod] utility package that provides a [`net/http`][net-http] style SSH server.

`sshutil` is part of the [Smallstep][smallstep] crypto suite ([step][], [step-ca][], etc.).

[gomod]: https://github.com/smallstep/sshutil/blob/master/go.mod
[net-http]: https://golang.org/pkg/net/http/
[smallstep]: https://smallstep.com/docs
[step]: https://github.com/smallstep/cli
[step-ca]: https://github.com/smallstep/certificates

## Why sshutil?

The `sshutil` package depends solely on the Go [`x/crypto`][crypto] module.
The [`x/crypto/ssh`][crypto-ssh] package provides convenient support for the [ssh wire protocol][rfc4253], the [ssh authentication protocol][rfc4252], and the [ssh connection protocol][rfc4254].
SSH, and thus the `x/crypto` implementation, is natually scoped to a single connection—whereas servers generally need to accept many connections.
A small, but tedious, amount of work is required to implement a full connection-tracking server for use in applications.
`sshutil` fills in the gap.

[crypto]: https://pkg.go.dev/golang.org/x/crypto
[crypto-ssh]: https://pkg.go.dev/golang.org/x/crypto/ssh
[rfc4252]: https://tools.ietf.org/html/rfc4252
[rfc4253]: https://tools.ietf.org/html/rfc4253
[rfc4254]: https://tools.ietf.org/html/rfc4254

## Get

```
$ go get go.step.sm/sshutil
```

## Examples

Example can be found in the [examples][] directory.
Run with:

```
$ go run go.step.sm/example/<name>
$ go run ./example/<name>
```

[examples]: https://github.com/smallstep/sshutil/tree/master/example


### Hello SSH

[`hello`](https://github.com/smallstep/sshutil/tree/master/example/hello/main.go)

```golang
package main

import "go.step.sm/sshutil"

func() hello(stream sshutil.Session) {
	stream.Terminal.Write([]byte("Hello SSH\n")
}

func main() {
	server := &sshutil.Server{Addr: ":2022"}
	server.Channel("session", sshutil.NewSessionHandler(hello))
	server.ListenAndServe()
}
```

Output:
```
$ go run ./example/hello
$ ssh localhost -p 2022
Hello SSH
Server closed remote connection to localhost.
```

### Echo server

The default session handler is an echo server.
Easily configure a persistent host key.

[`hostkey`](https://github.com/smallstep/sshutil/tree/master/example/hostkey/main.go)

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
$ go run ./example/hostkey
$ ssh localhost -p 2022
> echo
echo
> ^D
Client closed connection to localhost.
```

## Test

```
$ go test
```

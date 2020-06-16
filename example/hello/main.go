package main

import (
	"log"

	"go.step.sm/sshutil"
)

func hello(session *sshutil.Session) {
	defer session.Close()
	session.Terminal.Write([]byte("Hello SSH\n"))
}

func main() {
	server := &sshutil.Server{Addr: ":2022"}
	server.Channel("session", sshutil.NewSessionHandler(hello))
	err := server.ListenAndServe()
	log.Print(err)
}

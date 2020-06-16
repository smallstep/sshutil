package main

import (
	"log"

	"go.step.sm/sshutil"
)

func main() {
	server := &sshutil.Server{
		Addr: ":2022",
		// Specifying a config will cause the ephemeral host key
		// initialization to be skipped.
		Config: sshutil.DefaultServerConfig(),
	}
	key, err := sshutil.LoadHostKeyFromFile("example/server.key", "")
	if err != nil {
		log.Fatalf("error loading key: %v", err)
	}
	server.Config.AddHostKey(key)

	// The default session handle with no session func is an echo server
	server.Channel("session", sshutil.DefaultSessionHandler())
	err = server.ListenAndServe()
	log.Print(err)
}

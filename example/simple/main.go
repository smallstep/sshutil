package main

import (
	"log"

	"go.step.sm/sshutil"
)

func main() {
	server := &sshutil.Server{ Addr: ":2022" }
	err := server.ListenAndServe()
	log.Print(err)
}

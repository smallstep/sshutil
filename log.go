package sshutil

import (
	"log"
	"os"
)

var logger = log.New(os.Stderr, "sshutil: ", log.LstdFlags)

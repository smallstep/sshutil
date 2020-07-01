package sshutil

import (
	"log"
	"os"
)

var lflags = log.Ldate | log.Ltime | log.Lmsgprefix
var logger = log.New(os.Stderr, "sshutil: ", lflags)

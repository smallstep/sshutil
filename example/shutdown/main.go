
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.step.sm/sshutil"
)


func main() {
	server := &sshutil.Server{
		Addr: ":2022",
		Config: sshutil.DefaultServerConfig(),
		L: log.New(os.Stderr, "", log.LstdFlags),
	}
	{ // scope err
	key, err := sshutil.LoadKeyFromFile("example/server.key")
	if err != nil {
		log.Fatalf("error loading key: %v", err)
	}
	server.Config.AddHostKey(key)
	}

	// os.Interrupt (syscall.SIGINT) comes from ^C
	// syscall.SIGTERM is a nice `kill <pid>`
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	done := make(chan error, 1)
	go func() {
		err := server.ListenAndServe()
		done<- err
	}()
	<-signals

	fmt.Println()
	log.Println("Server shutting down!")

	// On first interrupt, attempt a graceful shutdown. Wait until a second
	// interrupt, or until 10 seconds elapse, to forcibly close.
	ctx := context.Background()
	ctx, cancel := context.WithTimeout(ctx, 10 * time.Second)
	go func() {
		<-signals
		cancel()
	}()
	// Once all clients disconnect, ShutdownAndWait will return. Check the
	// error to determine if the method returned due to a second interrupt,
	// and, if so, forcibly close the server's connections so the program
	// can terminate.
	if err := server.ShutdownAndWait(ctx); err != nil {
		switch {
		case errors.Is(err, context.Canceled):
			log.Println("Process interrupted.")
		case errors.Is(err, context.DeadlineExceeded):
			log.Println("Waited too long.")
		default:
			log.Printf("Unexpected error during shutdown: %v", err)
		}
		log.Println("Closing remaining connections...")
		if err := server.Close(); err != nil {
			log.Printf("Unexpected error closing server: %v", err)
		}
		// Wait till the connections have all finished cleaning up so
		// the logs look nice.
		server.Idle.Wait()
	}
	err := <-done
	if err != sshutil.ErrServerClosed {
		log.Printf("Unexpected error from serve loop: %v", err)
	}
	log.Println("Done.")
}

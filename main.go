package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Runninginsilence1/scanner/cmd"
)

func main() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("Received signal, exiting...")
		os.Exit(0)
	}()

	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

package main

import (
	"time"
)

func main() {
	// Start server in a goroutine
	go Server("8080")

	// Wait for server to start
	time.Sleep(500 * time.Millisecond)

	// Run client
	Client()
}

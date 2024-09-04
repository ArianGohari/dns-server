package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	fmt.Printf("Starting DNS Server...\n")
	time.Sleep(1 * time.Second)
	fmt.Printf("Meow\n")

	// Listen on port 53 for UDP packets
	pc, err := net.ListenPacket("udp", ":53")
	if err != nil {
		panic(err)
	}

	// Close packet connection when server is stopped
	defer pc.Close()

	for {
		// Create 512 byte buffer, write packet into it, origin address and packet size
		buf := make([]byte, 512)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			fmt.Printf("Read error from %s: %s", addr.String(), err)
			continue
		}

		// Resolve dns query from given packet in a goroutine
		go HandlePacket(pc, addr, buf[:n])
	}
}

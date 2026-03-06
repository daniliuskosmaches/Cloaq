// NOTICE

// Project Name: Cloaq
// Copyright © 2026 Neil Talap and/or its designated Affiliates.

// This software is licensed under the Dragonfly Public License (DPL) 1.0.

// All rights reserved. The names "Neil Talap" and any associated logos or branding
// are trademarks of the Licensor and may not be used without express written permission,
// except as provided in Section 7 of the License.

// For commercial licensing inquiries or permissions beyond the scope of this
// license, please create an issue in github.

package main

import (
	network "cloaq/src"
	"cloaq/src/routing"
	"cloaq/src/tun"
	"fmt"
	"log"
	"os"
	"runtime"
)

func main() {
	if len(os.Args) < 2 {
		log.Println("Usage: cloaq <command>")
		return
	}

	switch os.Args[1] {
	case "run":
		runCommand()
	case "settings":
		settingsCommand()
	case "help":
		helpCommand()
	default:
		log.Println("Unknown command:", os.Args[1])
	}
}

func runCommand() {
	fmt.Println("Starting Cloaq...")
	fmt.Println("GOOS:", runtime.GOOS, "GOARCH:", runtime.GOARCH)

	_, err := network.GenerateIdentity()
	if err != nil {
		fmt.Println("Identity generation error:", err)
		return
	}

	dev, err := tun.InitDevice()
	if err != nil {
		fmt.Println("Tunnel init error:", err)
		return
	}

	if dev == nil {
		fmt.Println("Tunnel initialized (no device object returned on this OS yet).")
		fmt.Println("Cloaq running.")
		select {}
	}

	defer dev.Close()

	fmt.Println("Tunnel ready:", dev.Name())

	// Start tunnel processing
	if err := dev.Start(); err != nil {
		fmt.Println("Tunnel start error:", err)
		return
	}

	fmt.Println("Reading packets from tunnel...")

	// Read packets from TUN
	go func() {
		if err := network.ReadLoop(dev); err != nil {
			fmt.Println("ReadLoop error:", err)
		}
	}()

	// Initialize router (defined in src/router.go)
	router := &routing.Router{}

	// Example static routes
	_ = router.AddRoute("2001:db8:1::/64", "eth0")
	_ = router.AddRoute("2001:db8:2::/64", "eth1")

	log.Println("IPv6 TUN gateway created")

	// Start IPv6 packet listener (defined in src/routing/listener.go)
	go routing.CreateIPv6PacketListener(dev)

	// Prevent program from exiting
	select {}
}

func helpCommand() {
	log.Println("help text")
}

func settingsCommand() {
	log.Println("settings text")
}

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
	"log"
	"os"
	"runtime"

	"cloaq/src/tun"

	network "cloaq/src"
	routing "cloaq/src/routing"
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
	log.Println("Starting Cloaq...")
	log.Println("GOOS:", runtime.GOOS, "GOARCH:", runtime.GOARCH)

	// Initialize the identity for this node
	identity, err := network.GenerateIdentity()
	if err != nil {
		log.Fatal("identity creation failed: ", err)
	}
	// Logging the pubkey of the identity
	log.Println("Current node's pubkey: ", string(identity.PublicKey.Bytes()))

	// Initialization of the VNIC on the node
	dev, err := tun.InitDevice()
	if err != nil {
		log.Fatal("Tunnel init error:", err)
	}
	defer dev.Close()

	log.Println("VNIC has been initialized:", dev.Name())

	// Start VNIC processing
	if err := dev.Start(); err != nil {
		log.Fatal("VNIC start error:", err)
	}

	log.Println("Reading packets from the VNIC...")

	// Read packets from VNIC
	go func() {
		if err := network.ReadLoop(dev); err != nil {
			log.Println("ReadLoop error:", err)
		}
	}()

	// Initialize the router
	router := &routing.Router{}

	// Example static routes
	_ = router.AddRoute("2001:db8:1::/64", "eth0")
	_ = router.AddRoute("2001:db8:2::/64", "eth1")

	log.Println("IPv6 TUN gateway created")

	// Prevent program from exiting
	select {}
}

func helpCommand() {
	log.Println("help text")
}

func settingsCommand() {
	log.Println("settings text")
}

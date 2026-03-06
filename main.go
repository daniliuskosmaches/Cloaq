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
	"cloaq/src/commands"
	"flag"
	"fmt"

	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		log.Println("Usage: cloaq <command>")
		return
	}
	port := flag.Int("port", 8080, "Port to listen on")
	peers := flag.String("peers", "", "Comma-separated list of peer addresses")
	err := flag.CommandLine.Parse(os.Args[2:])
	if err != nil {
		return
	}

	fmt.Printf("Starting Cloaq on port %d...\n", *port)

	switch os.Args[1] {
	case "run":
		commands.RunCommand(*port, *peers)
	case "settings":
		commands.SettingsCommand()
	case "help":
		commands.HelpCommand()
	default:
		log.Println("Unknown command:", os.Args[1])
	}
}

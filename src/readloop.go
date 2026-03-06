// NOTICE

// Project Name: Cloaq
// Copyright © 2026 Neil Talap and/or its designated Affiliates.

// This software is licensed under the Dragonfly Public License (DPL) 1.0.

// All rights reserved. The names "Neil Talap" and any associated logos or branding
// are trademarks of the Licensor and may not be used without express written permission,
// except as provided in Section 7 of the License.

// For commercial licensing inquiries or permissions beyond the scope of this
// license, please create an issue in github.

package network

import (
	"log"

	"cloaq/src/tun"
)

// Reads packets from Tunnel, FOR NOW it's just logs basic info (IPv4/IPv6)
func ReadLoop(dev tun.Device) error {

	buf := make([]byte, 65535)

	for {
		n, err := dev.Read(buf)
		if err != nil {
			log.Println("readloop error:", err)
			return err
		}

		pkt := buf[:n]
		if len(pkt) < 1 {
			continue
		}

		ver := pkt[0] >> 4
		switch ver {
		case 6:
			log.Println("ipv6 packet:", len(pkt), "bytes")
		case 4:
			log.Println("ipv4 packet:", len(pkt), "bytes")
		default:
			log.Println("unknown packet version", ver, ":", len(pkt), "bytes")
		}
	}
}

func safeRuntime(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[RECOVERY] %s panicked: %v", name, r)
		}
	}()
	fn()
}

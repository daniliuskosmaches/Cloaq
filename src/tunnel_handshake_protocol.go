// NOTICE

// Project Name: Cloaq
// Copyright © 2026 Neil Talap and/or its designated Affiliates.

// This software is licensed under the Dragonfly Public License (DPL) 1.0.

// All rights reserved. The names "Neil Talap" and any associated logos or branding
// are trademarks of the Licensor and may not be used without express written permission,
// except as provided in Section 7 of the License.

// For commercial licensing inquiries or permissions beyond the scope of this
// license, please create an issue in github.

// ----------------------------------------------------------------------------------------------------------------------------------

// Tunnel Handshake Protocol

//    Implement a basic Diffie-Hellman handshake over the existing UDP Transport.
//    Securely establish shared symmetric keys between two nodes using their public identities.
//    Log successful secure channel establishment and verify key derivation.

// This would also require a go test suite, that would test the connection between the two nodes.
// Simulated Peers, use a single Go test that initializes two Transport instances on different local ports (e.g., :9001 and :9002).

/*
How It Works
Key Exchange Process

    Agreement on Public Values: Both parties agree on a large prime number p and a base g.

    Private Key Generation: Each party generates a private key:
        Alice chooses a private key a.
        Bob chooses a private key b.

    Public Key Calculation: Each party computes their public key:
        Alice computes A=gamodp.
        Bob computes B=gbmodp.

    Exchange Public Keys: Alice sends A to Bob, and Bob sends B to Alice.

    Shared Secret Calculation: Each party computes the shared secret:
        Alice calculates s=Bamodp.
        Bob calculates s=Abmodp.

Both arrive at the same shared secret s without directly transmitting it.
*/

package network

import (
	"bytes"
	"flag"
	"log"
	"net"
	"testing"
)

const (
	MSG_PUBLIC_KEY      = 0x01
	INSTANCE_A_PORT int = 9001
	INSTANCE_B_PORT int = 9002
)

func TestTunnel(t *testing.T) {
	args := []string{}
	key := []byte{78, 69, 73, 76, 80, 73, 68, 79, 82, 65, 83}

	_, _, identityA, err := createNode(INSTANCE_A_PORT, args)
	if err != nil {
		t.Fatal(err)
	}

	_, _, identityB, err := createNode(INSTANCE_B_PORT, args)
	if err != nil {
		t.Fatal(err)
	}

	transportA, err := NewTransport(":9001", key)
	if err != nil {
		t.Fatal(err)
	}

	transportB, err := NewTransport(":9002", key)
	if err != nil {
		t.Fatal(err)
	}

	incomingA := make(chan []byte, 10)
	incomingB := make(chan []byte, 10)

	go transportA.Listen(incomingA)
	go transportB.Listen(incomingB)

	addrA, _ := net.ResolveUDPAddr("udp", "127.0.0.1:9001")
	addrB, _ := net.ResolveUDPAddr("udp", "127.0.0.1:9002")

	resultA := make(chan []byte)
	resultB := make(chan []byte)

	// Run both sides concurrently
	go DiffieHellmanHandshake(t, transportA, identityA, addrB, incomingA, resultA)
	go DiffieHellmanHandshake(t, transportB, identityB, addrA, incomingB, resultB)

	keyA := <-resultA
	keyB := <-resultB

	log.Println("secure channel established")

	if !bytes.Equal(keyA, keyB) {
		t.Fatal("shared keys do not match")
	}

	log.Println("shared key matches")

}

func createNode(instance_port int, args []string) (*int, *string, *Identity, error) {
	fs := flag.NewFlagSet("runInstanceOne", flag.ExitOnError)

	port := fs.Int("port", instance_port, "port to listen on")
	peers := fs.String("peers", "", "comma-separated peers")

	err := fs.Parse(args)
	if err != nil {
		return nil, nil, nil, err
	}

	identity, err := GenerateTestIdentity()
	if err != nil {
		log.Print("error: ", err)
		return nil, nil, nil, err
	}

	log.Println("current node's pubkey: ", string(identity.PublicKey.Bytes()))

	return port, peers, identity, nil
}

func encodePublicKey(pub []byte) []byte {
	return append([]byte{MSG_PUBLIC_KEY}, pub...)
}

func decodeMessage(data []byte) (byte, []byte) {
	if len(data) < 1 {
		return 0, nil
	}
	return data[0], data[1:]
}

func DiffieHellmanHandshake(
	t *testing.T,
	transport *Transport,
	self *Identity,
	peerAddr *net.UDPAddr,
	incoming chan []byte,
	result chan []byte,
) {
	// Send our public key
	err := transport.SendTo(peerAddr.String(), encodePublicKey(self.PublicKey.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	for {
		select {
		case msg := <-incoming:
			msgType, payload := decodeMessage(msg)

			if msgType != MSG_PUBLIC_KEY {
				continue
			}

			// Derive shared key
			peerPub, err := ParsePublicKey(payload)
			shared, err := self.DeriveSharedKey(peerPub)
			if err != nil {
				t.Fatal(err)
			}

			result <- shared
			return
		}
	}
}

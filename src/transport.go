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
	"cloaq/src/utils"
	"net"
	"sync/atomic"
)

type Transport struct {
	conn      *net.UDPConn
	sentBytes uint64
	key       []byte
}

func NewTransport(listenAddr string, key []byte) (*Transport, error) {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	return &Transport{
		conn: conn,
		key:  key,
	}, nil
}

func (t *Transport) SendTo(addr string, data []byte) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}

	finalFrame, err := utils.Encapsulate(data, t.key)
	if err != nil {
		return err
	}

	n, err := t.conn.WriteToUDP(finalFrame, udpAddr)
	if err != nil {
		return err
	}

	atomic.AddUint64(&t.sentBytes, uint64(n))
	return nil
}

func (t *Transport) Listen(incoming chan<- []byte) {
	buf := make([]byte, 65535)
	for {
		n, _, err := t.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		packet := make([]byte, n)
		copy(packet, buf[:n])
		incoming <- packet
	}
}

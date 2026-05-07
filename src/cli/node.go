package cli

import (
	network "cloaq/src"

	"cloaq/src/monitor"
	"cloaq/src/tun"
	"cloaq/src/utils"
	"encoding/hex"
	"log"
	"sync/atomic"
)

type CloaqNode struct {
	ID        string
	Interface *tun.LinuxDevice
	Transport *network.Transport
	Identity  *network.Identity
	Peers     []string
	Metrics   *monitor.Monitor
}

func NewCloaqNode(peers []string) (*CloaqNode, error) {
	id, err := network.CreateOrLoadIdentity()
	if err != nil {
		return nil, err
	}

	tr, err := network.NewTransport(":9000", id.PrivateKey.Bytes())
	if err != nil {
		return nil, err
	}

	dev, err := tun.InitDevice("cloaq0")
	if err != nil {
		return nil, err
	}

	return &CloaqNode{
		ID:        hex.EncodeToString(id.PublicKey.Bytes()),
		Interface: dev,
		Transport: tr,
		Identity:  id,
		Peers:     peers,
		Metrics:   &monitor.Monitor{},
	}, nil
}

func (n *CloaqNode) Run(packetChan chan utils.Packet) {
	utils.SafeRuntime("Monitor", func() {
		err := n.Metrics.Execute(nil)
		if err != nil {
			return
		}
	})

	utils.SafeRuntime("ReadLoop", func() {
		err := network.ReadLoop(n.Interface, packetChan)
		if err != nil {
			return
		}
	})
}

func (n *CloaqNode) ProcessPacket(pkt utils.Packet) {
	if len(n.Peers) == 0 {
		return
	}

	target := n.Peers[0]
	onionedData, _ := utils.Encapsulate(pkt.Data, n.Identity.PrivateKey.Bytes())

	err := n.Transport.SendTo(target, onionedData)
	if err == nil {
		atomic.AddUint64(&monitor.BytesSent, uint64(len(onionedData)))
		log.Printf("[sent] %d bytes -> %s", len(onionedData), target)
	}
}

func (n *CloaqNode) Shutdown() {
	log.Println("\n[!] Graceful shutdown...")
	if n.Interface != nil {
		err := n.Interface.Close()
		if err != nil {
			return
		}
	}
	if n.Transport != nil {
		err := n.Transport.Close()
		if err != nil {
			return
		}
	}
}

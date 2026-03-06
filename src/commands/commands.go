package commands

import (
	network "cloaq/src"
	"cloaq/src/routing"
	"cloaq/src/tun"
	"log"
	"runtime"
	"time"
)

func RunCommand(port int, peers string) {
	log.Println("starting cloaq...")
	log.Println("goos:", runtime.GOOS, "goarch:", runtime.GOARCH)
	log.Println("starting tunnel on port", port, "with peers:", peers)

	// Initialize the identity for this node
	identity, err := network.GenerateIdentity()
	if err != nil {
		log.Fatal("identity creation failed: ", err)
	}
	// Logging the pubkey of the identity
	log.Println("current node's pubkey: ", string(identity.PublicKey.Bytes()))

	// Initialization of the VNIC on the node
	dev, err := tun.InitDevice()
	if err != nil {
		log.Fatal("tunnel init error:", err)
	}
	defer func() {
		err := dev.Close()
		if err != nil {
			log.Println("error closing device:", err)
		}
	}()

	log.Println("vnic has been initialized:", dev.Name())

	// Start VNIC processing
	if err := dev.Start(); err != nil {
		log.Fatal("vnic start error:", err)
	}

	log.Println("reading packets from the vnic...")

	startMonitor()
	log.Println("monitor started")

	// setting up readloop
	go func() {
		if err := network.ReadLoop(dev); err != nil {
			log.Println("readloop error:", err)
		}
	}()

	// Initialize the router
	router := &routing.Router{}

	// Example static routes
	_ = router.AddRoute("2001:db8:1::/64", "eth0")
	_ = router.AddRoute("2001:db8:2::/64", "eth1")

	log.Println("ipv6 tun gateway created")

	// Prevent program from exiting
	select {}
}

func HelpCommand() {
	log.Println("help text")
}

func SettingsCommand() {
	log.Println("settings text")
}

func startMonitor() {
	go func() {
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)

			log.Println("[monitor] alloc:", m.Alloc/1024/1024, "mb, sys:", m.Sys/1024/1024, "mb, goroutines:", runtime.NumGoroutine())

			time.Sleep(10 * time.Second)
		}
	}()
}

//go:build linux

package tun

import (
	"cloaq/src/tun/lintun"
	"os"
	"os/exec"
	"syscall"
)

type linuxDevice struct {
	name string
	f    *os.File
}

func (t *linuxDevice) Name() string                { return t.name }
func (t *linuxDevice) Start() error                { return nil }
func (t *linuxDevice) Close() error                { return t.f.Close() }
func (t *linuxDevice) Write(p []byte) (int, error) { return t.f.Write(p) }
func (t *linuxDevice) File() *os.File              { return t.f }

// InitDevice creates a L3 TUN on Linux
func InitDevice() (Device, error) {
	name := "cloaq0"
	f, err := lintun.CreateTUN(name)
	if err != nil {
		return nil, err
	}

	err = exec.Command("ip", "link", "set", name, "up").Run()
	if err != nil {
		return nil, err
	}

	// добавим ipv6 адрес, чтобы ядро начало слать пакеты в этот туннель
	err = exec.Command("ip", "-6", "addr", "add", "fc00::1/64", "dev", name).Run()
	if err != nil {
		return nil, err
	}

	return &linuxDevice{name: name, f: f}, nil

}

func (d *linuxDevice) Read(buf []byte) (int, error) {
	n, err := syscall.Read(int(d.f.Fd()), buf)
	if err != nil {
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
			return 0, nil
		}
		return 0, err
	}
	return n, nil
}

package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
	"os"
	"strconv"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang port_block ../../source/ebpfprog/port_block.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

func main() {
	if len(os.Args) < 3 {
		fmt.Printf("Usage: %s <interface> <port>\n", os.Args[0])
		fmt.Printf("  interface: network interface to attach to (e.g., eth0, lo)\n")
		fmt.Printf("  port: TCP port to block (e.g., 8080)\n")
		os.Exit(1)
	}

	interfaceName := os.Args[1]
	portVal, err := strconv.Atoi(os.Args[2])
	if err != nil || portVal <= 0 || portVal > 65535 {
		log.Fatalf("Invalid port number: %s", os.Args[2])
	}
	port := uint16(portVal)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	spec, err := loadPort_block()
	if err != nil {
		log.Fatalf("Loading eBPF program: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Creating eBPF collection: %v", err)
	}
	defer coll.Close()

	key := uint32(0)
	if err := coll.Maps["config_map"].Put(key, port); err != nil {
		log.Fatalf("Setting blocked port in map: %v", err)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("Getting interface %s: %v", interfaceName, err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   coll.Programs["drop_tcp_port"],
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("Attaching TC program: %v", err)
	}
	defer l.Close()

	fmt.Printf("eBPF program attached to interface %s (egress)\n", interfaceName)
	fmt.Printf("Blocking TCP traffic to port %d\n", port)
	fmt.Println("Press Ctrl+C to stop...")

	select {}
}

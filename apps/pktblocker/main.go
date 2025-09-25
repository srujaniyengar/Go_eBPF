/*
 * ==============================================================
 *   Go + eBPF Program: Block TCP Traffic on a Specific Port
 * ==============================================================
 *
 * Purpose:
 * --------
 * This userspace Go program manages an eBPF traffic control (TCX)
 * filter that drops all outgoing TCP traffic targeting a specific
 * TCP port on a given network interface.
 *
 * Key Features:
 * -------------
 *   - Dynamically attaches an eBPF program (`port_block.c`) to the
 *     chosen network interface at the **egress** hook.
 *   - Uses a BPF map (`config_map`) to configure the blocked TCP port.
 *   - Blocks all packets destined for the configured port, while
 *     allowing all other traffic to pass.
 *   - Stays attached until the program is interrupted (Ctrl+C).
 *
 * How It Works:
 * -------------
 * 1. The program accepts two command-line arguments:
 *        <interface> <port>
 *
 *    Example:
 *        sudo ./portblock eth0 8080
 *
 *    - This attaches the eBPF program to the `eth0` interface.
 *    - It configures the BPF map so that TCP traffic to port 8080
 *      is dropped.
 *
 * 2. The eBPF program (`drop_tcp_port`) inspects each egress packet:
 *    - If the packet is IPv4 + TCP, it extracts the TCP header.
 *    - It checks whether the destination port matches the configured
 *      blocked port.
 *    - If so, it drops the packet (TC_ACT_SHOT).
 *    - Otherwise, the packet passes normally (TC_ACT_OK).
 * ==============================================================
 */

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
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

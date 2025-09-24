package main

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang filter_by_proc ../../source/ebpfprog/filter_by_proc.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu

func findProcessByName(processName string) (int, error) {
	cmd := exec.Command("pgrep", "-f", processName)
	output, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("process '%s' not found: %v", processName, err)
	}
	pidStr := strings.TrimSpace(string(output))
	lines := strings.Split(pidStr, "\n")
	if len(lines) == 0 {
		return 0, fmt.Errorf("no process found with name '%s'", processName)
	}
	pid, err := strconv.Atoi(lines[0])
	if err != nil {
		return 0, fmt.Errorf("invalid PID: %v", err)
	}
	return pid, nil
}

func monitorProcess(processName string, targetPid *int) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		pid, err := findProcessByName(processName)
		if err != nil {
			log.Printf("Process monitoring: %v", err)
			*targetPid = 0
			continue
		}
		if pid != *targetPid {
			log.Printf("Process PID changed: %d -> %d", *targetPid, pid)
			*targetPid = pid
		}
	}
}

func main() {
	if len(os.Args) < 4 {
		fmt.Printf("Usage: %s <interface> <process_name> <port>\n", os.Args[0])
		fmt.Printf("  interface: network interface to attach to (e.g., eth0, lo)\n")
		fmt.Printf("  process_name: name of the process to filter (e.g., 'myprocess')\n")
		fmt.Printf("  port: TCP port to allow for the process (e.g., 4040)\n")
		os.Exit(1)
	}

	interfaceName := os.Args[1]
	processName := os.Args[2]
	portVal, err := strconv.Atoi(os.Args[3])
	if err != nil || portVal <= 0 || portVal > 65535 {
		log.Fatalf("Invalid port number: %s", os.Args[3])
	}
	port := uint16(portVal)

	targetPid, err := findProcessByName(processName)
	if err != nil {
		log.Fatalf("Finding process: %v", err)
	}
	fmt.Printf("Found process '%s' with PID: %d\n", processName, targetPid)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	spec, err := loadFilter_by_proc()
	if err != nil {
		log.Fatalf("Loading eBPF program: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Creating eBPF collection: %v", err)
	}
	defer coll.Close()

	key := uint32(0)
	if err := coll.Maps["allowed_port_map"].Put(key, port); err != nil {
		log.Fatalf("Setting allowed port in map: %v", err)
	}
	if err := coll.Maps["target_pid_map"].Put(key, uint32(targetPid)); err != nil {
		log.Fatalf("Setting target PID in map: %v", err)
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("Getting interface %s: %v", interfaceName, err)
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   coll.Programs["filter_process_port"],
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("Attaching TC program: %v", err)
	}
	defer l.Close()

	fmt.Printf("eBPF program attached to interface %s (egress)\n", interfaceName)
	fmt.Printf("Filtering process '%s' (PID: %d) - allowing only port %d\n", processName, targetPid, port)
	fmt.Println("Press Ctrl+C to stop...")

	// Monitor process in the background
	go monitorProcess(processName, &targetPid)

	// Update PID in map periodically
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := coll.Maps["target_pid_map"].Put(key, uint32(targetPid)); err != nil {
				log.Printf("Error updating target PID: %v", err)
			}
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	fmt.Println("Detaching eBPF program...")
}

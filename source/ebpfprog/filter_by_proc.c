/* 
 * eBPF Traffic Control (tc) program to filter TCP traffic by process and port.
 *
 * Overview:
 * ----------
 * This program attaches to the TC ingress hook and filters packets
 * based on both the TCP port and the process ID (PID) of the application.
 *
 * Logic:
 * ------
 * 1. Parse the Ethernet header and verify the packet is IPv4.
 * 2. Parse the IPv4 header and ensure the protocol is TCP.
 * 3. Extract and validate the TCP header.
 * 4. Look up two values from BPF maps:
 *      - allowed_port_map: the single TCP port that the target process is allowed to use
 *      - target_pid_map: the PID of the process being filtered
 * 5. Retrieve the current process PID using bpf_get_current_pid_tgid().
 * 6. If the packet is not associated with the target PID, let it pass.
 * 7. If the source or destination port matches the allowed port, let it pass.
 * 8. Otherwise, drop the packet.
 *
 * Maps:
 * -----
 *   allowed_port_map: 
 *      - key: always 0
 *      - value: __u16 (the only allowed TCP port for the process)
 *
 *   target_pid_map:
 *      - key: always 0
 *      - value: __u32 (the PID of the process to restrict)
 *
 * Return codes:
 * -------------
 *   - TC_ACT_SHOT: Drop the packet
 *   - TC_ACT_OK:   Allow the packet
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} allowed_port_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_pid_map SEC(".maps");

SEC("tc")
int filter_process_port(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    __u32 key = 0;
    __u16 *allowed_port = bpf_map_lookup_elem(&allowed_port_map, &key);
    if (!allowed_port)
        return TC_ACT_OK;
    __u32 *target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target_pid)
        return TC_ACT_OK;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    if (pid != *target_pid)
        return TC_ACT_OK;

    __u16 dport = bpf_ntohs(tcp->dest);
    __u16 sport = bpf_ntohs(tcp->source);

    if (sport == *allowed_port || dport == *allowed_port)
        return TC_ACT_OK;

    return TC_ACT_SHOT;
}

char _license[] SEC("license") = "GPL";

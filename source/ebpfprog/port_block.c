/*
 * eBPF Traffic Control (tc) program for dropping TCP packets on a configurable port.
 *
 * Overview:
 * ----------
 * This program attaches to the TC ingress hook and inspects network packets.
 * It performs the following steps:
 *   1. Parse the Ethernet header and ensure the packet is IPv4.
 *   2. Parse the IPv4 header and check if the packet uses TCP as the transport protocol.
 *   3. Extract the TCP header and validate boundaries to ensure packet safety.
 *   4. Look up a target TCP destination port from a BPF map (config_map).
 *   5. If the packet’s TCP destination port matches the configured value, drop the packet.
 *   6. Otherwise, allow the packet to pass.
 *
 * Map:
 * ----
 *   config_map: A BPF array map with a single entry that stores the TCP port to filter.
 *   - key: always 0
 *   - value: __u16 (destination TCP port to drop)
 *
 * Return codes:
 * -------------
 *   - TC_ACT_SHOT: Drop the packet
 *   - TC_ACT_OK:   Let the packet pass
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
} config_map SEC(".maps");

SEC("tc")
int drop_tcp_port(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    if (ip->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) {
        return TC_ACT_OK;
    }

    __u32 key = 0;
    __u16 *target_port = bpf_map_lookup_elem(&config_map, &key);
    if (!target_port) {
        return TC_ACT_OK;
    }

    if (bpf_ntohs(tcp->dest) == *target_port) {
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

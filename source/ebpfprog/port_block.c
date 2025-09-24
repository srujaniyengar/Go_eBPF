#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// BPF map to hold the target TCP port to be dropped.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} config_map SEC(".maps");

// TC program to filter and drop packets on a specific TCP port.
SEC("tc")
int drop_tcp_port(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // L2
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return TC_ACT_OK;
    }

//only ipv4
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return TC_ACT_OK;
    }

    // TCP
    if (ip->protocol != IPPROTO_TCP) {
        return TC_ACT_OK;
    }

    // L4
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end) {
        return TC_ACT_OK; // Not a valid TCP segment
    }

    // Retrieve the target port from the configuration map.
    __u32 key = 0;
    __u16 *target_port = bpf_map_lookup_elem(&config_map, &key);
    if (!target_port) {
        return TC_ACT_OK;
    }

    // cmp destination with target
    if (bpf_ntohs(tcp->dest) == *target_port) {
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct ip_port {
    u32 ip;
    u16 port;
};

#define MAX_COMM_HISTORY 5

struct communication {
    struct ip_port outbound[MAX_COMM_HISTORY];
    struct ip_port inbound[MAX_COMM_HISTORY];
    uint32_t outboundc; // Counter for outbound
    uint32_t inboundc; // Counter for inbound
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ip_port);
    __type(value, struct communication);
} comms SEC(".maps");

#define ETH_P_IP 0x0800

__always_inline struct communication *get_comms(struct ip_port tuple) {
    struct communication *comm = bpf_map_lookup_elem(&comms, &tuple);

    // Create one if non-existent
    if (!comm) {
        struct communication def = {0};
        bpf_map_update_elem(&comms, &tuple, &def, 0);
        comm = bpf_map_lookup_elem(&comms, &tuple);
    }

    return comm;
}

__always_inline void add_outbound(struct ip_port src, struct ip_port dst) {
    struct communication *comm = get_comms(src);
    if (!comm)
        return;

    // Check if already added
    // TODO: Use hash table?
    for (uint32_t i = 0; i < MAX_COMM_HISTORY; i++) {
        struct ip_port *out = &comm->outbound[i];
        if (out->ip == dst.ip && out->port == dst.port)
            return;
    }

    if (comm->outboundc < MAX_COMM_HISTORY)
        comm->outbound[comm->outboundc++] = dst;
}


__always_inline void add_inbound(struct ip_port dst, struct ip_port src) {
    struct communication *comm = get_comms(dst);
    if (!comm)
        return;

    // Check if already added
    // TODO: Use hash table?
    for (uint32_t i = 0; i < MAX_COMM_HISTORY; i++) {
        struct ip_port *in = &comm->inbound[i];
        if (in->ip == src.ip && in->port == src.port)
            return;
    }

    if (comm->inboundc < MAX_COMM_HISTORY)
        comm->inbound[comm->inboundc++] = src;
}

// Check if either the inbound array or outbound array are full
__always_inline int check_array_full(struct ip_port tuple) {
    struct communication *comm = get_comms(tuple);
    if (!comm)
        return -1;

    return comm->inboundc == MAX_COMM_HISTORY
        || comm->outboundc == MAX_COMM_HISTORY;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    u64 nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return XDP_ABORTED;

    // Only IPv4 for now
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + nh_off;
    if (iph + 1 > data_end)
        return XDP_ABORTED;

    // if (iph->protocol != IPPROTO_UDP)
    //     return XDP_PASS;

    nh_off = sizeof(*iph);
    struct udphdr *udph = (void *)(long)iph + nh_off;
    if (udph + 1 > data_end)
        return XDP_ABORTED;

    nh_off = sizeof(*udph);
    unsigned char *payload = (unsigned char *)(long)udph + nh_off;
    if (payload + 1 > data_end)
        return XDP_ABORTED;

    uint64_t datalen = (long)data_end - (long)payload;

    // Identify QUIC traffic through the Fixed bit
    if (!(payload[0] & 0x40))
        return XDP_PASS;

    // Minimum size requirement
    if (datalen < 1000)
        return XDP_PASS;

    // Drop any packets with a multiple of 1200
    // NOTE: Really bad rule
    // if (datalen % 1200)
    //     return XDP_DROP;

    struct ip_port src = {0};
    src.ip = iph->saddr;
    src.port = udph->source;

    struct ip_port dst = {0};
    dst.ip = iph->daddr;
    dst.port = udph->dest;

    add_inbound(dst, src);
    add_outbound(src, dst);

    // Rule check
    if (check_array_full(src) || check_array_full(dst)) {
        struct event_fanning evt = {};
        evt.srcip = iph->saddr;
        evt.dstip = iph->daddr;
        evt.srcport = udph->source;
        evt.dstport = udph->dest;
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
        return XDP_DROP;
    }

    return XDP_PASS;
}

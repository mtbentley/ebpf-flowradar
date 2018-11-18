#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <linux/in6.h>
#include <stdint.h>
#include <linux/version.h>
#include "bpf_helpers.h"
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define NUM_HASHES 8

#define DEBUG 1
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
					 ##__VA_ARGS__);			\
		})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

/* vlan header.  Not often used (or well tested) */
struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

/* A bunch of maps.  They are just counters for testing */
struct bpf_map_def SEC("maps") eth_proto_count = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(uint16_t),
	.value_size = sizeof(uint64_t),
	.max_entries = 64,
};

struct bpf_map_def SEC("maps") ip_proto_count = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(uint16_t),
	.value_size = sizeof(uint64_t),
	.max_entries = 64,
};

struct bpf_map_def SEC("maps") sport_count = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(uint16_t),
	.value_size = sizeof(uint64_t),
	.max_entries = 64,
};

struct bpf_map_def SEC("maps") dport_count = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(uint16_t),
	.value_size = sizeof(uint64_t),
	.max_entries = 64,
};

struct bpf_map_def SEC("maps") sip_count = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint64_t),
	.max_entries = 64,
};

struct bpf_map_def SEC("maps") dip_count = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(uint32_t),
	.value_size = sizeof(uint64_t),
	.max_entries = 64,
};

/* Information on the "five tuple" used to identify flows */
struct five_tuple {
	__be32 saddr;
	__be32 daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t proto;
};

/* A simple hash function, based on rs hash here: http://www.partow.net/programming/hashfunctions/
 * Splits up ip addrs into two 16 bit uints and starts with k as a seed
 * Returns a 16 bit uint
 * TODO: make it better
 */
static __always_inline
uint16_t hash(uint16_t host, uint8_t k, struct five_tuple *ft) {
    uint32_t a = 63689;
    uint32_t b = 378551;

    uint16_t saddr1 = (uint16_t)(ft->saddr >> 16);
    uint16_t saddr2 = (uint16_t)(ft->saddr & 0x0000ffff);
    uint16_t daddr1 = (uint16_t)(ft->daddr >> 16);
    uint16_t daddr2 = (uint16_t)(ft->daddr & 0x0000ffff);

    uint32_t hash = k;
    hash = hash * a + host;
    a = a * b;
    hash = hash * a + saddr1;
    a = a * b;
    hash = hash * a + saddr2;
    a = a * b;
    hash = hash * a + daddr1;
    a = a * b;
    hash = hash * a + daddr2;
    a = a * b;
    hash = hash * a + ft->sport;
    a = a * b;
    hash = hash * a + ft->dport;
    a = a * b;
    hash = hash * a + ft->proto;


    // We've been doing math on a uint32, so xor the high and low bits together
    uint16_t h1 = (uint16_t)(hash & 0x0000ffff);
    uint16_t h2 = (uint16_t)(hash >> 16);
    return h1 ^ h2;;
}

static __always_inline
uint8_t hash8(uint16_t host, uint8_t k, struct five_tuple *ft) {
    uint16_t h16 = hash(host, k, ft);
    uint8_t h8 = h16 % UINT8_MAX;

    return h8;
}

/* Parse ethernet headers
 * Takes the header and end location, and puts the proto and l3_offset in
 * the proper params.  l3_offset is the location of the next header (likely ip)
 */
static __always_inline
int16_t parse_eth(struct ethhdr *eth, void *data_end, uint16_t *eth_proto,
		uint64_t *l3_offset)
{
	uint16_t eth_type;
	uint64_t offset;

	offset = sizeof(*eth);
    // this test is neede to satisfy the verifier, so it knows we won't do any
    // out of bounds accesses
	if ((void *)eth + offset > data_end)
		return -1;

	eth_type = eth->h_proto;

	// ETH_P_8921Q is single tag, ETH_P_8021AD is double tag
	if (eth_type == htons(ETH_P_8021Q) || eth_type == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan;

		vlan = (void *)eth + offset;
		offset += sizeof(*vlan);
		if ((void *)eth + offset > data_end)
			return -1;

		eth_type = vlan->h_vlan_encapsulated_proto;
	}
	// a wild double tag appeared!
	if (eth_type == htons(ETH_P_8021Q)) {
		struct vlan_hdr *vlan2;

		vlan2 = (void *)eth + offset;
		offset += sizeof(*vlan2);
		if ((void *)eth + offset > data_end)
			return -1;

		eth_type = vlan2->h_vlan_encapsulated_proto;
	}

    // ntohs converts network byteorder to host byteorder (for 16 bit value)
	*eth_proto = ntohs(eth_type);
	*l3_offset = offset;
	return 0;
}

/* Parse an ipv4 header
 * Takes the context and l3 offset and outputs the proto and l4_offset, and
 * puts the source and dast addrs in ft
 * l4_offset is the location in ctx of the next header (tcp, udp, icmp, etc)
 */
static __always_inline
int16_t parse_ipv4(struct xdp_md *ctx, uint64_t l3_offset, uint16_t *ip_proto,
		uint32_t *l4_offset, struct five_tuple *ft)
{
	uint64_t offset;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct iphdr *iph = data + l3_offset;

	offset = l3_offset + sizeof(*iph);

    // We need to satisfy that the header start is in the packet
	if (data + l3_offset > data_end)
		return -1;

    // We need to satisfy that the header end is in the packet
	if ((void *)iph + sizeof(*iph) > data_end)
		return -1;

	uint8_t hdr_len = iph->ihl;

    // ihl cannot be less than 5 (20 bytes)
	if (hdr_len < 5)
		return -1;

	int32_t data_len = data_end - (void *)iph;

	uint16_t tot_len = ntohs(iph->tot_len);
    // The header length can't be less than 20 bytes
	if (tot_len < 20)
		return -1;

    // Warn if the data len (calculated from the data end) is different from
    // what's expected from the header
	if (data_len != tot_len) {
		bpf_debug("WARN: packet end does not match total length\n");
	}

    // Satisfy the verifier that ihl is in this range
    // TODO: is this necessary?
	uint8_t ihl = (iph->ihl);
	if (ihl < 5)
		ihl = 5;
	if (ihl > 15)
		ihl = 15;
	offset = ihl*4 + l3_offset;

	*l4_offset = offset;
	*ip_proto = iph->protocol;
	ft->saddr = iph->saddr;
	ft->daddr = iph->daddr;

	return 0;
}


/* Parse tcp and udp packets
 * This was multiple functions, but the verifier didn't like it
 * Takes cts, the proto, and the l4_offset, and puts the sport and dport in ft
 */
static __always_inline
int16_t parse_tcp_udp(struct xdp_md *ctx, uint16_t proto, uint32_t l4_offset, struct five_tuple *ft)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

    // Satisfy that the header start in in data
	if (data + l4_offset > data_end) {
		bpf_debug("Packet l4_offset outside data_end\n");
		return -1;
	}
	if (proto == IPPROTO_TCP) {
		struct tcphdr *thdr = data + l4_offset;

        // Satisfy that the header end is in data
		if ((void *)thdr + sizeof(*thdr) > data_end) {
			bpf_debug("TCP Packet header ends outside data_end\n");
			return -1;
		}

		ft->sport = ntohs(thdr->source);
		ft->dport = ntohs(thdr->dest);
		return 0;
	} else if (proto == IPPROTO_UDP) {
		struct udphdr *uhdr = data + l4_offset;

        // Satisfy that the header end is in the data
		if ((void *)uhdr + sizeof(*uhdr) > data_end) {
			bpf_debug("UPD Packet header ends outside data_end\n");
			return -1;
		}

		ft->sport = ntohs(uhdr->source);
		ft->dport = ntohs(uhdr->dest);
		return 0;
	}

	return -1;
}

/* Increment a map value at key
 * if the key is not in the map, initialize it to 1
 */
static __always_inline
void increment_map(struct bpf_map_def *map, void *key)
{
	long *value;
	value = bpf_map_lookup_elem(map, key);
	if (value) {
		__sync_fetch_and_add(value, 1);
	} else {
		long v;
		v = 1;
		bpf_map_update_elem(map, key, &v, BPF_NOEXIST);
	}
}

/* The main program.
 * TODO: rename this?
 */
SEC("prog")
int xdp_pass(struct xdp_md *ctx)
{
	uint64_t l3_offset = 0;
	uint16_t eth_proto = 0;
	uint32_t l4_offset = 0;
	uint16_t ip_proto = 0;
	
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;

	if (parse_eth(eth, data_end, &eth_proto, &l3_offset)) {
		bpf_debug("Cannot parse eth header");
		return XDP_PASS;
	}

	increment_map(&eth_proto_count, &eth_proto);

	int16_t parse_ip = 0;
	struct five_tuple ft;
	switch (eth_proto) {
		case ETH_P_IP:
			parse_ip = parse_ipv4(ctx, l3_offset, &ip_proto, &l4_offset, &ft);
			break;
		case ETH_P_IPV6:
            // TODO: IPv6 support?
		case ETH_P_ARP:
		default:
			return XDP_PASS;
	}
	if (parse_ip) {
		bpf_debug("ERROR: error parsing IP header\n");
		return XDP_PASS;
	}

	increment_map(&ip_proto_count, &ip_proto);

	ft.proto = ip_proto;

	uint16_t parse_data = 0;
	switch (ip_proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			parse_data = parse_tcp_udp(ctx, ip_proto, l4_offset, &ft);
			break;
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
		default:
			return XDP_PASS;
	}
	if (parse_data) {
		bpf_debug("ERROR: error parsing data header\n");
		return XDP_PASS;
	}
	increment_map(&sport_count, &ft.sport);
	increment_map(&dport_count, &ft.dport);
	increment_map(&sip_count, &ft.saddr);
	increment_map(&dip_count, &ft.daddr);

    uint8_t hashes[NUM_HASHES];
#pragma unroll
    for (int i=0; i<NUM_HASHES; i++) {
        hashes[i] = hash8(0x1011, i, &ft);
        bpf_debug("Hash %i: 0x%x\n", i, hashes[i]);
    }

	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
uint32_t _version SEC("version") = LINUX_VERSION_CODE;

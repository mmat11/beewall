#define BPF_NO_PRESERVE_ACCESS_INDEX 0 /* workaround vmlinux.h attributes */

#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

/* https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_ether.h
 */
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

typedef enum { IP4, IP6 } L3Proto;
typedef enum { ICMP, TCP, UDP } L4Proto;

typedef struct __attribute__((packed)) {
	/* Protocols */
	L3Proto l3proto;
	L4Proto l4proto;

	/* IPV4 */
	__u32 saddr;
	__u32 daddr;

	/* IPV6 */
	struct in6_addr saddr6;
	struct in6_addr daddr6;

	/* TCP,UDP */
	__u16 sport;
	__u16 dport;

	/* Meta */
	bool abort;
} Packet;

typedef struct __attribute__((packed)) {
	L3Proto l3proto;
	L4Proto l4proto;
	__u16 dport;
} OuterKey;

typedef struct __attribute__((packed)) {
	__u32 prefixlen;
	__u8 data[16];
} LpmKey;

struct lpm_t {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, LpmKey);
	__type(value, __u8); /* unused */
	__uint(max_entries, 65535);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} lpm SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
	__uint(key_size, sizeof(OuterKey));
	__uint(max_entries, 65535);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__array(values, struct lpm_t);
} ingress_rules SEC(".maps");

static __always_inline enum xdp_action handle_packet(Packet *);
static __always_inline void parse_ip(struct xdp_md *, struct ethhdr *, Packet *);
static __always_inline void parse_ip6(struct xdp_md *, struct ethhdr *, Packet *);
static __always_inline void parse_tcp(struct xdp_md *, struct iphdr *, Packet *);
static __always_inline void parse_udp(struct xdp_md *, struct iphdr *, Packet *);
static __always_inline void parse_tcp6(struct xdp_md *, struct ipv6hdr *, Packet *);
static __always_inline void parse_udp6(struct xdp_md *, struct ipv6hdr *, Packet *);

SEC("xdp")
int ingress(struct xdp_md *ctx) {
	void *data     = (void *)(__s64)ctx->data;
	void *data_end = (void *)(__s64)ctx->data_end;
	/* TODO: parse vlan? */
	struct ethhdr *eth = data;

	/* sanity check */
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	Packet pkt = {};

	pkt.abort = false;
	switch (bpf_ntohs(eth->h_proto)) {
	case ETH_P_IP: {
		pkt.l3proto = IP4;
		parse_ip(ctx, eth, &pkt);
		break;
	}
	case ETH_P_IPV6: {
		pkt.l3proto = IP6;
		parse_ip6(ctx, eth, &pkt);
		break;
	}
	default:
		goto end;
	}

	if (pkt.abort)
		goto end;

	return handle_packet(&pkt);
end:
	/* don't handle any other protocol */
	return XDP_PASS;
}

static __always_inline void parse_ip(struct xdp_md *ctx, struct ethhdr *eth, Packet *pkt) {
	void *data_end   = (void *)(__s64)ctx->data_end;
	struct iphdr *ip = (struct iphdr *)(eth + 1);

	/* sanity check */
	if ((void *)(ip + 1) > data_end) {
		pkt->abort = true;
		return;
	}

	pkt->saddr = ip->saddr;
	pkt->daddr = ip->daddr;

	switch (ip->protocol) {
	case IPPROTO_ICMP: {
		pkt->l4proto = ICMP;
		break;
	}
	case IPPROTO_TCP: {
		pkt->l4proto = TCP;
		parse_tcp(ctx, ip, pkt);
		break;
	}
	case IPPROTO_UDP: {
		pkt->l4proto = UDP;
		parse_udp(ctx, ip, pkt);
		break;
	}
	default:
		pkt->abort = true;
	}
}

static __always_inline void parse_ip6(struct xdp_md *ctx, struct ethhdr *eth, Packet *pkt) {
	void *data_end     = (void *)(__s64)ctx->data_end;
	struct ipv6hdr *ip = (struct ipv6hdr *)(eth + 1);

	/* sanity check */
	if ((void *)(ip + 1) > data_end) {
		pkt->abort = true;
		return;
	}

	pkt->saddr6 = ip->saddr;
	pkt->daddr6 = ip->daddr;

	switch (ip->nexthdr) {
	case IPPROTO_ICMP: {
		pkt->l4proto = ICMP;
		break;
	}
	case IPPROTO_TCP: {
		pkt->l4proto = TCP;
		parse_tcp6(ctx, ip, pkt);
		break;
	}
	case IPPROTO_UDP: {
		pkt->l4proto = UDP;
		parse_udp6(ctx, ip, pkt);
		break;
	}
	default:
		pkt->abort = true;
	}
}

static __always_inline void parse_tcp(struct xdp_md *ctx, struct iphdr *ip, Packet *pkt) {
	void *data_end     = (void *)(__s64)ctx->data_end;
	struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

	/* sanity check */
	if ((void *)(tcp + 1) > data_end) {
		pkt->abort = true;
		return;
	}

	pkt->sport = bpf_ntohs(tcp->source);
	pkt->dport = bpf_ntohs(tcp->dest);
}

static __always_inline void parse_tcp6(struct xdp_md *ctx, struct ipv6hdr *ip, Packet *pkt) {
	void *data_end     = (void *)(__s64)ctx->data_end;
	struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

	/* sanity check */
	if ((void *)(tcp + 1) > data_end) {
		pkt->abort = true;
		return;
	}

	pkt->sport = bpf_ntohs(tcp->source);
	pkt->dport = bpf_ntohs(tcp->dest);
}

static __always_inline void parse_udp(struct xdp_md *ctx, struct iphdr *ip, Packet *pkt) {
	void *data_end     = (void *)(__s64)ctx->data_end;
	struct udphdr *udp = (struct udphdr *)(ip + 1);

	/* sanity check */
	if ((void *)(udp + 1) > data_end) {
		pkt->abort = true;
		return;
	}

	pkt->sport = bpf_ntohs(udp->source);
	pkt->dport = bpf_ntohs(udp->dest);
}

static __always_inline void parse_udp6(struct xdp_md *ctx, struct ipv6hdr *ip, Packet *pkt) {
	void *data_end     = (void *)(__s64)ctx->data_end;
	struct udphdr *udp = (struct udphdr *)(ip + 1);

	/* sanity check */
	if ((void *)(udp + 1) > data_end) {
		pkt->abort = true;
		return;
	}

	pkt->sport = bpf_ntohs(udp->source);
	pkt->dport = bpf_ntohs(udp->dest);
}

static __always_inline enum xdp_action handle_packet(Packet *pkt) {
	OuterKey outer_key = {
		.l3proto = pkt->l3proto,
		.l4proto = pkt->l4proto,
		.dport   = pkt->dport,
	};

	struct lpm_map *lpm = bpf_map_lookup_elem(&ingress_rules, &outer_key);
	if (lpm) {
		LpmKey lpm_key = {};

		switch (pkt->l3proto) {
		case IP4:
			lpm_key.prefixlen = 32;
		case IP6:
			lpm_key.prefixlen = 128;
		};

		__builtin_memcpy(lpm_key.data, &(pkt->saddr), sizeof(pkt->saddr));

		if (bpf_map_lookup_elem(lpm, &lpm_key)) {
			return XDP_PASS;
		}
	}

	return XDP_DROP;
}

char __license[] SEC("license") = "Dual MIT/GPL";

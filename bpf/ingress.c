#define BPF_NO_PRESERVE_ACCESS_INDEX 0 /* workaround vmlinux.h attributes */

#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

/* https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_ether.h
 */
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define MAX_RULES 2048

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
	__u32 saddr;
	__u32 saddr6[4];
	__u16 dport;
} IngressRule;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, IngressRule);
	__type(value, __u8); // unused
	__uint(max_entries, MAX_RULES);
} ingress_rules SEC(".maps");

static __always_inline enum xdp_action handle_packet(Packet *);
static __always_inline void parse_ip(struct xdp_md *, struct ethhdr *, Packet *);
static __always_inline void parse_ip6(struct xdp_md *, struct ethhdr *, Packet *);
/* use void* instead of iphdr/ipv6hdr since it's gonna get casted anyway */
static __always_inline void parse_l4(struct xdp_md *, void *, Packet *, bool);
static __always_inline void parse_tcp(struct xdp_md *, void *, Packet *);
static __always_inline void parse_udp(struct xdp_md *, void *, Packet *);

SEC("xdp")
int beewall_ingress(struct xdp_md *ctx) {
	void *data     = (void *)(__s64)ctx->data;
	void *data_end = (void *)(__s64)ctx->data_end;
	/* TODO: parse vlan? */
	struct ethhdr *eth = data;

	/* sanity check */
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	Packet pkt = {};
	int hproto = bpf_ntohs(eth->h_proto);

	pkt.abort = false;
	switch (hproto) {
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

	parse_l4(ctx, ip, pkt, false);
	pkt->saddr = ip->saddr;
	pkt->daddr = ip->daddr;
}

static __always_inline void parse_ip6(struct xdp_md *ctx, struct ethhdr *eth, Packet *pkt) {
	void *data_end     = (void *)(__s64)ctx->data_end;
	struct ipv6hdr *ip = (struct ipv6hdr *)(eth + 1);

	/* sanity check */
	if ((void *)(ip + 1) > data_end) {
		pkt->abort = true;
		return;
	}

	parse_l4(ctx, ip, pkt, true);
	pkt->saddr6 = ip->saddr;
	pkt->daddr6 = ip->daddr;
}

static __always_inline void parse_l4(struct xdp_md *ctx, void *ip, Packet *pkt, bool v6) {
	__u8 proto;

	if (v6) {
		proto = ((struct ipv6hdr *)ip)->nexthdr;
	} else {
		proto = ((struct iphdr *)ip)->protocol;
	}

	switch (proto) {
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

static __always_inline void parse_tcp(struct xdp_md *ctx, void *ip, Packet *pkt) {
	void *data_end     = (void *)(__s64)ctx->data_end;
	struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

	/* sanity check */
	if ((void *)(tcp + 1) > data_end) {
		pkt->abort = true;
		return;
	}

	pkt->sport = tcp->source;
	pkt->dport = tcp->dest;
}

static __always_inline void parse_udp(struct xdp_md *ctx, void *ip, Packet *pkt) {
	void *data_end     = (void *)(__s64)ctx->data_end;
	struct udphdr *udp = (struct udphdr *)(ip + 1);

	/* sanity check */
	if ((void *)(udp + 1) > data_end) {
		pkt->abort = true;
		return;
	}

	pkt->sport = udp->source;
	pkt->dport = udp->dest;
}

static __always_inline enum xdp_action handle_packet(Packet *pkt) {
	IngressRule comparablePkt = {
		.l3proto = pkt->l3proto,
		.l4proto = pkt->l4proto,
		.dport   = pkt->dport,
	};

	switch (pkt->l3proto) {
	case IP4:
		comparablePkt.saddr = pkt->saddr;
	case IP6:
		// todo: fixme
		comparablePkt.saddr6[0] = 0;
		comparablePkt.saddr6[1] = 0;
		comparablePkt.saddr6[2] = 0;
		comparablePkt.saddr6[3] = 0;
	}

	if ((__u8 *)bpf_map_lookup_elem(&ingress_rules, &comparablePkt)) {
		bpf_printk("PASS");
		return XDP_PASS;
	}
	bpf_printk("DROP");
	return XDP_DROP;
}

char __license[] SEC("license") = "Dual MIT/GPL";

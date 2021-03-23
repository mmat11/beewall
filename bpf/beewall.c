#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"


/* https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_ether.h */
#define ETH_P_IP	0x0800
#define ETH_P_IPV6	0x86DD

typedef enum { IP4, IP6 } L3Proto;
typedef enum { ICMP, TCP, UDP } L4Proto;

typedef struct {
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

static __always_inline enum xdp_action handle_packet(Packet*);
static __always_inline void parse_ip(struct xdp_md*, struct ethhdr*, Packet*);
static __always_inline void parse_ip6(struct xdp_md*, struct ethhdr*, Packet*);
/* use void* instead of iphdr/ipv6hdr since it's gonna get casted anyway */
static __always_inline void parse_tcp(struct xdp_md*, void*, Packet*);
static __always_inline void parse_udp(struct xdp_md*, void*, Packet*);

SEC("xdp")
int beewall_ingress(struct xdp_md *ctx) {
  	Packet pkt = {};
	void *data = (void *)(__s64)ctx->data;
	void *data_end = (void *)(__s64)ctx->data_end;

	/* TODO: parse vlan? */
	struct ethhdr *eth = data;

	/* sanity check */
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

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
	void *data = (void *)(__s64)ctx->data;
	void *data_end = (void *)(__s64)ctx->data_end;

	struct iphdr *ip = (struct iphdr *)(eth + 1);

	/* sanity check */
	if ((void *)(ip + 1) > data_end) {
		pkt->abort = true;
		return;
	}

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

	pkt->saddr = ip->saddr;
	pkt->daddr = ip->daddr;
}

static __always_inline void parse_ip6(struct xdp_md *ctx, struct ethhdr *eth, Packet *pkt) {
	void *data = (void *)(__s64)ctx->data;
	void *data_end = (void *)(__s64)ctx->data_end;

	struct ipv6hdr *ip = (struct ipv6hdr *)(eth + 1);

	/* sanity check */
	if ((void *)(ip + 1) > data_end) {
		pkt->abort = true;
		return;
	}

	switch (ip->nexthdr) {
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

	pkt->saddr6 = ip->saddr;
	pkt->daddr6 = ip->daddr;
}

static __always_inline void parse_tcp(struct xdp_md *ctx, void *ip, Packet *pkt) {
	void *data = (void *)(__s64)ctx->data;
	void *data_end = (void *)(__s64)ctx->data_end;

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
	void *data = (void *)(__s64)ctx->data;
	void *data_end = (void *)(__s64)ctx->data_end;

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
	/* TODO: compare and drop/pass */
	return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";

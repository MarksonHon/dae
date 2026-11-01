/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 *
 * Observation-only TC programs for direct (pass-through) traffic accounting.
 *
 * They are attached before tproxy on the LAN interfaces (lower TCX priority),
 * never modify packets or marks, and always return TC_ACT_UNSPEC so the chain
 * continues into tproxy. They only count flows that tproxy has already
 * recorded in conn_state_map as direct pass-through: a stateful flow whose
 * first packet was handled by dae. Packets without a state entry are not
 * counted.
 *
 * conn_state_map is shared with tproxy.c and is reached through
 * CollectionOptions.MapReplacements, so the key and value layouts below must
 * mirror control/kern/tproxy.c exactly.
 */

#include "headers/errno-base.h"
#include "headers/if_ether_defs.h"
#include "headers/pkt_cls_defs.h"
#include "headers/socket_defs.h"
#include "headers/upai_in6_defs.h"
#include "headers/vmlinux.h"

#include "headers/bpf_core_read.h"
#include "headers/bpf_endian.h"
#include "headers/bpf_helpers.h"

#define DIRECT_STATS_CONTINUE TC_ACT_UNSPEC

#ifndef BIT
#define BIT(nr) (1UL << (nr))
#endif

#define IPV6_BYTE_LENGTH 16
#define TASK_COMM_LEN 16
#define ROUTING_EPOCH_SLOT_RESULT_SHIFT 41
#define ROUTING_EPOCH_SLOT_RESULT_MASK 0x3
#define MAX_CONN_STATE_NUM (65536 * 4)

// Keys of direct_stats_map. Userspace reads the sums across CPUs.
enum direct_stats_key {
	DIRECT_STATS_UPLOAD_BYTES = 0,
	DIRECT_STATS_UPLOAD_PACKETS = 1,
	DIRECT_STATS_DOWNLOAD_BYTES = 2,
	DIRECT_STATS_DOWNLOAD_PACKETS = 3,
	DIRECT_STATS_KEY_NUM = 4,
};

union ip6 {
	__u8 u6_addr8[16];
	__be16 u6_addr16[8];
	__be32 u6_addr32[4];
	__be64 u6_addr64[2];
};

struct tuples_key {
	union ip6 sip;
	union ip6 dip;
	__u16 sport;
	__u16 dport;
	__u8 l4proto;
};

union routing_meta {
	struct {
		__u32 mark;
		__u8 outbound;
		__u8 must;
		__u8 dscp;
		__u8 has_routing;
	} data;
	__u64 raw;
} __attribute__((aligned(8)));

// Mirrors struct conn_state in control/kern/tproxy.c. Keep field order and
// types identical: the map value is shared between the two objects.
struct conn_state {
	bool is_wan_ingress_direction;
	__u8 state;
	__u64 last_seen_ns;
	union routing_meta meta;
	__u8 mac[6];
	__u8 padding[2];
	__u8 pname[TASK_COMM_LEN];
	__u32 pid;
	__u8 routing_epoch_slot;
	__u8 direct_passthrough;
	__u16 datapath_generation;
};

// Read-only from this object. Replaced by the tproxy map at load time.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_CONN_STATE_NUM);
	__type(key, struct tuples_key);
	__type(value, struct conn_state);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} conn_state_map SEC(".maps");

// Per-packet increments must not share one cacheline across CPUs.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, DIRECT_STATS_KEY_NUM);
	__type(key, __u32);
	__type(value, __u64);
} direct_stats_map SEC(".maps");

// Builds the tuple of the packet at l3_off in the same representation as
// tproxy's get_tuples. Non-first IP fragments and L4 protocols other than
// TCP/UDP are rejected, as they have no state entry to match.
static __always_inline int
direct_stats_parse_tuple(struct __sk_buff *skb, __u32 l3_off,
			 struct tuples_key *key)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u8 *p = data + l3_off;
	__u8 l4proto;
	__u32 l4_off;

	if ((void *)(p + 1) > data_end)
		return -1;

	__builtin_memset(key, 0, sizeof(*key));

	if ((p[0] >> 4) == 4) {
		struct iphdr *iph = (void *)p;

		if ((void *)(iph + 1) > data_end)
			return -1;
		if (iph->ihl < 5)
			return -1;
		// Only the first fragment carries the L4 header.
		if (iph->frag_off & bpf_htons(0x1fff))
			return -1;
		l4proto = iph->protocol;
		l4_off = l3_off + iph->ihl * 4;

		key->sip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		key->sip.u6_addr32[3] = iph->saddr;
		key->dip.u6_addr32[2] = bpf_htonl(0x0000ffff);
		key->dip.u6_addr32[3] = iph->daddr;
	} else if ((p[0] >> 4) == 6) {
		struct ipv6hdr *ip6h = (void *)p;

		if ((void *)(ip6h + 1) > data_end)
			return -1;
		// Extension headers are not walked: such flows are skipped.
		l4proto = ip6h->nexthdr;
		l4_off = l3_off + sizeof(struct ipv6hdr);

		__builtin_memcpy(&key->sip, &ip6h->saddr, IPV6_BYTE_LENGTH);
		__builtin_memcpy(&key->dip, &ip6h->daddr, IPV6_BYTE_LENGTH);
	} else {
		return -1;
	}

	if (l4proto == IPPROTO_TCP) {
		struct tcphdr *tcph = data + l4_off;

		if ((void *)(tcph + 1) > data_end)
			return -1;
		key->sport = tcph->source;
		key->dport = tcph->dest;
	} else if (l4proto == IPPROTO_UDP) {
		struct udphdr *udph = data + l4_off;

		if ((void *)(udph + 1) > data_end)
			return -1;
		key->sport = udph->source;
		key->dport = udph->dest;
	} else {
		return -1;
	}
	key->l4proto = l4proto;
	return 0;
}

// A state entry counts only when tproxy marked it as a LAN-originated direct
// pass-through. Local-socket entries carry a pid and are excluded.
static __always_inline bool
direct_stats_is_direct_lan_flow(const struct conn_state *st)
{
	return st->direct_passthrough == 1 && !st->is_wan_ingress_direction &&
	       st->pid == 0;
}

static __always_inline void
direct_stats_add(__u32 bytes_key, __u32 packets_key, __u64 len)
{
	__u64 *v;

	v = bpf_map_lookup_elem(&direct_stats_map, &bytes_key);
	if (v)
		*v += len;
	v = bpf_map_lookup_elem(&direct_stats_map, &packets_key);
	if (v)
		*v += 1;
}

// Upload: the packet is the LAN-originated direction, so its tuple is the
// state key as-is.
static __always_inline int
direct_stats_lan_ingress(struct __sk_buff *skb, __u32 l3_off)
{
	struct tuples_key key;
	struct conn_state *st;

	if (direct_stats_parse_tuple(skb, l3_off, &key))
		return DIRECT_STATS_CONTINUE;
	st = bpf_map_lookup_elem(&conn_state_map, &key);
	if (st && direct_stats_is_direct_lan_flow(st))
		direct_stats_add(DIRECT_STATS_UPLOAD_BYTES,
				 DIRECT_STATS_UPLOAD_PACKETS, skb->len);
	return DIRECT_STATS_CONTINUE;
}

// Download: the reply's tuple is the reverse of the state key.
static __always_inline int
direct_stats_lan_egress(struct __sk_buff *skb, __u32 l3_off)
{
	struct tuples_key key, rkey;
	struct conn_state *st;

	if (direct_stats_parse_tuple(skb, l3_off, &key))
		return DIRECT_STATS_CONTINUE;
	rkey = key;
	rkey.sip = key.dip;
	rkey.dip = key.sip;
	rkey.sport = key.dport;
	rkey.dport = key.sport;
	st = bpf_map_lookup_elem(&conn_state_map, &rkey);
	if (st && direct_stats_is_direct_lan_flow(st))
		direct_stats_add(DIRECT_STATS_DOWNLOAD_BYTES,
				 DIRECT_STATS_DOWNLOAD_PACKETS, skb->len);
	return DIRECT_STATS_CONTINUE;
}

SEC("tc/direct_stats_lan_ingress_l2")
int direct_stats_lan_ingress_l2(struct __sk_buff *skb)
{
	return direct_stats_lan_ingress(skb, 14);
}

SEC("tc/direct_stats_lan_ingress_l3")
int direct_stats_lan_ingress_l3(struct __sk_buff *skb)
{
	return direct_stats_lan_ingress(skb, 0);
}

SEC("tc/direct_stats_lan_egress_l2")
int direct_stats_lan_egress_l2(struct __sk_buff *skb)
{
	return direct_stats_lan_egress(skb, 14);
}

SEC("tc/direct_stats_lan_egress_l3")
int direct_stats_lan_egress_l3(struct __sk_buff *skb)
{
	return direct_stats_lan_egress(skb, 0);
}

SEC("license") const char __license[] = "Dual BSD/GPL";

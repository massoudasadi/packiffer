// +build ignore

#include "bpf_helpers.h"

#define MAX_RULES 16

// Ethernet header
struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));

// TCP header
struct tcphdr {
  __u16	source;
	__u16	dest;
	__u32	seq;
	__u32	ack_seq;
	__u16	res1:4,
	doff:4,
	fin:1,
	syn:1,
	rst:1,
	psh:1,
	ack:1,
	urg:1,
	ece:1,
	cwr:1;
	__u16	window;
	__u16	check;
	__u16	urg_ptr;
} __attribute__((packed));

// UDP header
struct udphdr {
	__u16	source;
	__u16	dest;
	__u16	len;
	__u16	check;
};

BPF_MAP_DEF(matches) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(matches);


BPF_MAP_DEF(blacklist) = {
    .map_type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(__u64),
    .value_size = sizeof(__u32),
    .max_entries = MAX_RULES,
};
BPF_MAP_ADD(blacklist);

// XDP program //
SEC("xdp")
int firewall(struct xdp_md *ctx) {

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end) {
    // Malformed Ethernet header
    return XDP_ABORTED;
  }

  if (ether->h_proto != 0x08U) {  // htons(ETH_P_IP) -> 0x08U
    // Non IPv4 traffic
    return XDP_PASS;
  }

  data += sizeof(*ether);
  struct iphdr *ip = data;
  if (data + sizeof(*ip) > data_end) {
    // Malformed IPv4 header
    return XDP_ABORTED;
  }

  // if (ip->protocol == 0x06) // htons(IPPROTO_TCP) -> 0x06
  // {

  //   data += sizeof(*ip);
  //   struct tcphdr *tcp = data;
  //   if (data + sizeof(*tcp) > data_end) {
  //     // Malformed TCP header
  //     return XDP_ABORTED;
  //   }



  // }
  
  struct {
    __u32 prefixlen;
    __u32 saddr;
  } key;

  key.prefixlen = 32;
  key.saddr = ip->saddr;

  __u64 *rule_idx = bpf_map_lookup_elem(&blacklist, &key);
  if (rule_idx) {
    __u32 index = *(__u32*)rule_idx;
    __u64 *counter = bpf_map_lookup_elem(&matches, &index);
    if (counter) {
      (*counter)++;
    }
    return XDP_DROP;
  }

  return XDP_PASS;

}

char _license[] SEC("license") = "GPLv2";
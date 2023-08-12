#include <stdbool.h>
#include <stdint.h>

#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} pipe SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(key_size, sizeof(uint32_t));
  __uint(value_size, sizeof(uint8_t));
  __uint(max_entries, 6);
} smac SEC(".maps");

struct callback_ctx {
  struct ethhdr *eth;
};

static __u64 copy_to_h_source(void *map, __u32 *key, __u8 *val,
                              struct callback_ctx *data) {
  data->eth->h_source[*key] = *val;
  return 0;
}

SEC("classifier")
int probe(struct __sk_buff *skb) {
  if (bpf_skb_pull_data(skb, 0) < 0) {
    return TC_ACT_OK;
  }

  uint8_t *head = (uint8_t *)(long)skb->data;
  uint8_t *tail = (uint8_t *)(long)skb->data_end;

  if (head + sizeof(struct ethhdr) > tail) {
    return TC_ACT_OK;
  }

  struct ethhdr *eth = (struct ethhdr *)head;

  uint32_t offset;

  if (eth->h_proto != bpf_htons(ETH_P_PPP_SES) &&
      eth->h_proto != bpf_htons(ETH_P_PPP_DISC)) {
    return TC_ACT_OK;
  }

  offset = sizeof(struct ethhdr);

  if (head + offset > tail) {
    return TC_ACT_OK;
  }

  // bpf_printk("%u:%u:%u:%u:%u:%u", eth->h_source[0],
  //            eth->h_source[1], eth->h_source[2],
  //            eth->h_source[3], eth->h_source[4],
  //            eth->h_source[5]);
  struct callback_ctx data;
  data.eth = eth;
  bpf_for_each_map_elem(&smac, copy_to_h_source, &data, 0);

  // bpf_perf_event_output(skb, &pipe, BPF_F_CURRENT_CPU, &x, 6 *
  // sizeof(uint8_t));

  return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";

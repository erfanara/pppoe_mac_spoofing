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

  unsigned char new_mac[] = {176, 72, 122, 207, 172, 150};
  memcpy(eth->h_source, new_mac, sizeof(new_mac));

  uint64_t x = (uint64_t)eth->h_source;
  if (bpf_perf_event_output(skb, &pipe, BPF_F_CURRENT_CPU, &x,
                            sizeof(uint64_t)) < 0) {
    return TC_ACT_OK;
  }
  return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual MIT/GPL";

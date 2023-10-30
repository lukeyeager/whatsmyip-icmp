#include <linux/bpf.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

#define trace_printk(fmt, ...)                                                 \
  do {                                                                         \
    char _fmt[] = fmt;                                                         \
    bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);                       \
  } while (0)

#define OFFSET_IP (sizeof(struct ethhdr))
#define OFFSET_ICMP (OFFSET_IP + sizeof(struct iphdr))
#define OFFSET_ICMP_DATA (OFFSET_ICMP + sizeof(struct icmphdr))

char __license[] SEC("license") = "GPL";

// map key is (ip_saddr, icmp_id, icmp_seq)
struct map_key {
  __u32 ip_saddr;
  __u16 icmp_id;
  __u16 icmp_seq;
};
// map value is the ICMP data needed for the TIME_EXCEEDED msg
struct ttl_exceeded_payload {
  struct iphdr ip;
  __u8 data[8];
};
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct map_key);
  __type(value, struct ttl_exceeded_payload);
  __uint(max_entries, 64);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
} payload_map SEC(".maps");

SEC("ingress")
int _ingress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  // ensure packet is long enough
  if (data + OFFSET_ICMP_DATA > data_end)
    return TC_ACT_UNSPEC;

  // ergonomic way to access headers later
  struct {
    struct ethhdr *eth;
    struct iphdr *ip;
    struct icmphdr *icmp;
  } pkt = {
      .eth = data,
      .ip = data + OFFSET_IP,
      .icmp = data + OFFSET_ICMP,
  };

  // validate that this is an ICMP_ECHO packet
  if (pkt.eth->h_proto != __constant_htons(ETH_P_IP))
    return TC_ACT_UNSPEC;
  if (pkt.ip->protocol != IPPROTO_ICMP)
    return TC_ACT_UNSPEC;
  if (pkt.icmp->type != ICMP_ECHO)
    return TC_ACT_UNSPEC;

  trace_printk("PING FROM: %d.%d", pkt.ip->saddr & 0xFF,
               (pkt.ip->saddr >> 8) & 0xFF);
  trace_printk("              %d.%d", (pkt.ip->saddr >> 16) & 0xFF,
               (pkt.ip->saddr >> 24) & 0xFF);

  // load the payload onto the stack
  struct ttl_exceeded_payload payload;
  if (bpf_skb_load_bytes(skb, OFFSET_IP, &payload, sizeof(payload)) != 0) {
    trace_printk("ERR bpf_skb_load_bytes() failed");
    return TC_ACT_UNSPEC;
  }

  // save the payload to the map
  struct map_key key = {
      .ip_saddr = pkt.ip->saddr,
      .icmp_id = pkt.icmp->un.echo.id,
      .icmp_seq = pkt.icmp->un.echo.sequence,
  };
  if (bpf_map_update_elem(&payload_map, &key, &payload, BPF_ANY) != 0) {
    // NOTE: if this is failing, then it probably means the hashmap is full
    // Run 'make stop' to clean out the old entries
    trace_printk("ERR bpf_map_update_elem() failed");
    return TC_ACT_UNSPEC;
  }

  return TC_ACT_UNSPEC;
}

SEC("egress")
int _egress(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  // ensure packet is long enough
  if (data + OFFSET_ICMP_DATA > data_end)
    return TC_ACT_UNSPEC;

  // ergonomic way to access headers later
  struct {
    struct ethhdr *eth;
    struct iphdr *ip;
    struct icmphdr *icmp;
  } pkt = {
      .eth = data,
      .ip = data + OFFSET_IP,
      .icmp = data + OFFSET_ICMP,
  };

  // validate that this is an ICMP_ECHO packet
  if (pkt.eth->h_proto != __constant_htons(ETH_P_IP))
    return TC_ACT_UNSPEC;
  if (pkt.ip->protocol != IPPROTO_ICMP)
    return TC_ACT_UNSPEC;
  if (pkt.icmp->type != ICMP_ECHOREPLY)
    return TC_ACT_UNSPEC;

  // load the payload from the map
  struct map_key key = {
      .ip_saddr = pkt.ip->daddr,
      .icmp_id = pkt.icmp->un.echo.id,
      .icmp_seq = pkt.icmp->un.echo.sequence,
  };
  struct ttl_exceeded_payload *payload =
      bpf_map_lookup_elem(&payload_map, &key);
  if (payload == 0) {
    trace_printk("WARN bpf_map_lookup_elem() failed");
    return TC_ACT_UNSPEC;
  }
  trace_printk("Found ttl=%d in payload_map", payload->ip.ttl);
  if (bpf_map_delete_elem(&payload_map, &key) != 0)
    trace_printk("WARN bpf_map_delete_elem() failed");

  // decide whether or not to edit the response
  __u32 new_saddr = payload->ip.saddr;
  switch (payload->ip.ttl) {
  case 1:
    return TC_ACT_SHOT; // mtr will print ???
  case 2:
    new_saddr &= 0x00FFFFFF;
    new_saddr |= (pkt.ip->daddr & 0x000000FF) << 24;
    break;
  case 3:
    new_saddr &= 0x00FFFFFF;
    new_saddr |= (pkt.ip->daddr & 0x0000FF00) << 16;
    break;
  case 4:
    new_saddr &= 0x00FFFFFF;
    new_saddr |= (pkt.ip->daddr & 0x00FF0000) << 8;
    break;
  case 5:
    new_saddr &= 0x00FFFFFF;
    new_saddr |= pkt.ip->daddr & 0xFF000000;
    break;
  case 6:
    return TC_ACT_SHOT; // mtr will print ???
  default:
    return TC_ACT_UNSPEC; // send the kernel's normal response
  }

  // special case - in case nothing changed, flip the 9th bit
  if (new_saddr == payload->ip.saddr)
    new_saddr ^= 0x00010000;

  trace_printk("DBG Replacing saddr 0x%08x with 0x%08x", payload->ip.saddr,
               new_saddr);

  // store these headers on the stack so that it's easy to use bpf_csum_diff()
  struct {
    struct iphdr ip;
    struct icmphdr icmp;
    struct ttl_exceeded_payload data;
  } new_pkt = {
      .ip = *pkt.ip,
      .icmp = *pkt.icmp,
      .data = *payload,
  };

  /****************************************************************************
   * Get ready to start modifying the packet, but only use readonly operations
   * for now so that we can continue to use pointers derived from skb->data
   ***************************************************************************/

  __s64 ip_csum_diff = 0, icmp_csum_diff = 0;

  // ip.tot_len
  new_pkt.ip.tot_len = __constant_htons(sizeof(new_pkt));
  ip_csum_diff = bpf_csum_diff((__u32 *)&pkt.ip->tot_len, 4,
                               (__u32 *)&new_pkt.ip.tot_len, 4, ip_csum_diff);
  if (ip_csum_diff < 0) {
    trace_printk("ERR bpf_csum_diff() failed");
    return TC_ACT_SHOT;
  }

  // ip.saddr
  new_pkt.ip.saddr = new_saddr;
  ip_csum_diff = bpf_csum_diff((__u32 *)&pkt.ip->saddr, 4,
                               (__u32 *)&new_pkt.ip.saddr, 4, ip_csum_diff);
  if (ip_csum_diff < 0) {
    trace_printk("ERR bpf_csum_diff() failed");
    return TC_ACT_SHOT;
  }

  // icmp.type and icmp.code
  new_pkt.icmp.type = ICMP_TIME_EXCEEDED;
  new_pkt.icmp.code = ICMP_EXC_TTL;
  icmp_csum_diff =
      bpf_csum_diff((__u32 *)&pkt.icmp->type, 4, (__u32 *)&new_pkt.icmp.type, 4,
                    icmp_csum_diff);
  if (icmp_csum_diff < 0) {
    trace_printk("ERR bpf_csum_diff() failed");
    return TC_ACT_SHOT;
  }

  // shrink the packet
  __u32 new_pkt_len = sizeof(struct ethhdr) + sizeof(new_pkt);
  __u32 old_payload_len = (data_end - data - OFFSET_ICMP_DATA);
  // without these safety checks, tc refuses to add the filter
  old_payload_len &= 0xFF;
  if (old_payload_len < 4)
    return TC_ACT_SHOT;
  // copy the old ICMP payload data onto the stack so we can update the checksum
  __u8 old_payload[0xFF];
  if (bpf_skb_load_bytes(skb, OFFSET_ICMP_DATA, &old_payload,
                         old_payload_len) != 0) {
    trace_printk("ERR bpf_skb_load_bytes() failed");
    return TC_ACT_SHOT;
  }
  __u32 payload_remainder = (-old_payload_len % 4);
  for (int i = old_payload_len; i < old_payload_len + payload_remainder; ++i) {
    if (i <= 0xFF) // without this check, bpf complains about calling memcpy
      old_payload[i] = 0;
  }
  old_payload_len += payload_remainder;
  // NOTE: the verifier rejects this on Jammy with:
  // invalid indirect read from stack R3 off -320+39 size 255
  // Same with Fedora 38 (linux 6.2.9)
  icmp_csum_diff = bpf_csum_diff((__u32 *)&old_payload, old_payload_len,
                                 (__u32 *)&new_pkt.data, sizeof(new_pkt.data),
                                 icmp_csum_diff);
  if (icmp_csum_diff < 0) {
    trace_printk("ERR bpf_csum_diff() failed");
    return TC_ACT_SHOT;
  }

  /****************************************************************************
   * Now we start to actually modify the packet, so pointers derived from
   * skb->data will be invalidated and unusable.
   ***************************************************************************/

  // ip.tot_len
  if (bpf_skb_store_bytes(skb, OFFSET_IP + offsetof(struct iphdr, tot_len),
                          &new_pkt.ip.tot_len, sizeof(new_pkt.ip.tot_len),
                          0) != 0) {
    trace_printk("ERR bpf_skb_store_bytes() failed");
    return TC_ACT_SHOT;
  }

  // ip.saddr
  if (bpf_skb_store_bytes(skb, OFFSET_IP + offsetof(struct iphdr, saddr),
                          &new_pkt.ip.saddr, sizeof(new_pkt.ip.saddr),
                          0) != 0) {
    trace_printk("ERR bpf_skb_store_bytes() failed");
    return TC_ACT_SHOT;
  }

  // icmp.type and icmp.code
  if (bpf_skb_store_bytes(
          skb, OFFSET_ICMP + offsetof(struct icmphdr, type), &new_pkt.icmp.type,
          sizeof(new_pkt.icmp.type) + sizeof(new_pkt.icmp.code), 0) != 0) {
    trace_printk("ERR bpf_skb_store_bytes() failed");
    return TC_ACT_SHOT;
  }

  // shrink the packet
  if (bpf_skb_change_tail(skb, new_pkt_len, 0) != 0) {
    trace_printk("ERR bpf_skb_change_tail() failed");
    return TC_ACT_SHOT;
  }

  // write new ICMP data payload
  if (bpf_skb_store_bytes(skb, OFFSET_ICMP_DATA, &new_pkt.data,
                          sizeof(new_pkt.data), 0) != 0) {
    trace_printk("ERR bpf_skb_store_bytes() failed");
    return TC_ACT_SHOT;
  }

  // ip.check
  if (bpf_l4_csum_replace(skb, OFFSET_IP + offsetof(struct iphdr, check), 0,
                          ip_csum_diff, 0) != 0) {
    trace_printk("ERR bpf_l4_csum_replace() failed");
    return TC_ACT_SHOT;
  }

  // icmp.checksum
  if (bpf_l4_csum_replace(skb, OFFSET_ICMP + offsetof(struct icmphdr, checksum),
                          0, icmp_csum_diff, 0) != 0) {
    trace_printk("ERR bpf_l4_csum_replace() failed");
    return TC_ACT_SHOT;
  }

  return TC_ACT_UNSPEC;
}

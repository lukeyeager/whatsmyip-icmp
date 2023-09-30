#include <arpa/inet.h>
#include <libnetfilter_log/libnetfilter_log.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void print_ping(struct iphdr *ip_hdr, struct icmphdr *icmp_hdr) {
  struct in_addr addr;
  printf("IP ");
  addr.s_addr = ip_hdr->saddr;
  printf("src=%s ", inet_ntoa(addr));
  addr.s_addr = ip_hdr->daddr;
  printf("dst=%s ", inet_ntoa(addr));
  printf("ttl=%d\n", ip_hdr->ttl);
  printf("  ICMP id=0x%04x seq=0x%04x\n", htons(icmp_hdr->un.echo.id),
         htons(icmp_hdr->un.echo.sequence));
}

uint16_t icmp_checksum(void *data, int len) {
  uint16_t *p = (uint16_t *)data;
  uint16_t *end = (uint16_t *)(data + len);
  uint32_t sum = 0;
  while (p < end) {
    sum += *p;
    p += 1;
  }
  if (len % 2)
    sum += *(uint8_t *)p;
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  uint16_t result = ~sum;
  return result;
}

int create_response(struct iphdr *req_ip_hdr, struct icmphdr *req_icmp_hdr,
                    char *req_icmp_msg, size_t req_icmp_msg_len, void **resp,
                    size_t *resp_len) {
  *resp_len = sizeof(struct icmphdr) + req_icmp_msg_len;
  *resp = malloc(*resp_len);
  if (!*resp) {
    perror("malloc");
    return 1;
  }
  struct icmphdr *resp_icmp_hdr = (struct icmphdr *)*resp;
  char *resp_icmp_msg = (char *)(*resp + sizeof(struct icmphdr));

  resp_icmp_hdr->type = ICMP_ECHOREPLY;
  resp_icmp_hdr->code = 0;
  resp_icmp_hdr->checksum = 0;
  resp_icmp_hdr->un.echo.id = req_icmp_hdr->un.echo.id;
  resp_icmp_hdr->un.echo.sequence = req_icmp_hdr->un.echo.sequence;
  memcpy(resp_icmp_msg, req_icmp_msg, req_icmp_msg_len);

  // Modify the timestamp embedded in the payload to include the src IP
  struct timeval *tv = (struct timeval *)resp_icmp_msg;
  uint32_t srcaddr = req_ip_hdr->saddr;
  tv->tv_sec -= 1e10 * (srcaddr & 0xFF);
  tv->tv_sec -= 1e7 * ((srcaddr / 256) & 0xFF);
  tv->tv_sec -= 1e4 * ((srcaddr / (256 * 256)) & 0xFF);
  tv->tv_sec -= 1e1 * ((srcaddr / (256 * 256 * 256)) & 0xFF);

  resp_icmp_hdr->checksum = icmp_checksum(*resp, *resp_len);
  return 0;
}

int send_response(uint32_t addr, void *resp, size_t resp_len) {
  int rc = 0;
  int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (sockfd < 0) {
    perror("socket");
    return 1;
  }

  struct sockaddr_in dest_addr;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_addr.s_addr = addr;

  ssize_t numsent = sendto(sockfd, resp, resp_len, 0,
                           (struct sockaddr *)&dest_addr, sizeof(dest_addr));
  if (numsent == -1) {
    perror("sendto");
    rc = 1;
  }
  if (close(sockfd) == -1)
    perror("close");

  return rc;
}

static int callback(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
                    struct nflog_data *ldata, void *data) {
  char *payload;
  size_t payload_len = nflog_get_payload(ldata, &payload);
  if (payload_len == -1) {
    perror("nflog_get_payload");
    return 1;
  }
  struct iphdr *req_ip_hdr = (struct iphdr *)payload;
  struct icmphdr *req_icmp_hdr =
      (struct icmphdr *)(payload + sizeof(struct iphdr));
  char *req_icmp_msg = payload + sizeof(struct iphdr) + sizeof(struct icmphdr);
  size_t req_icmp_msg_len =
      payload_len - sizeof(struct iphdr) - sizeof(struct icmphdr);

  print_ping(req_ip_hdr, req_icmp_hdr);

  void *resp;
  size_t resp_len;
  if (create_response(req_ip_hdr, req_icmp_hdr, req_icmp_msg, req_icmp_msg_len,
                      &resp, &resp_len))
    return 1;

  int rc = send_response(req_ip_hdr->saddr, resp, resp_len);
  free(resp);
  return rc;
}

int main() {
  struct nflog_handle *h;
  struct nflog_g_handle *gh;
  ssize_t rv;
  char buf[4096];
  int rc = 1, fd;

  h = nflog_open();
  if (!h) {
    perror("nflog_open");
    goto close_handler;
  }
  if (nflog_unbind_pf(h, AF_INET) < 0) {
    perror("nflog_unbind_pf");
    goto close_handler;
  }
  if (nflog_bind_pf(h, AF_INET) < 0) {
    perror("nflog_bind_pf");
    goto close_handler;
  }
  gh = nflog_bind_group(h, 0);
  if (!gh) {
    perror("nflog_bind_group");
    goto close_handler;
  }
  if (nflog_set_mode(gh, NFULNL_COPY_PACKET, 0xffff) < 0) {
    perror("nflog_set_mode");
    goto close_handler;
  }
  nflog_callback_register(gh, &callback, NULL);
  fd = nflog_fd(h);
  while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
    nflog_handle_packet(h, buf, rv);
  }
  if (nflog_unbind_group(gh) == -1)
    perror("nflog_unbind_group");

close_handler:
  if (nflog_close(h) != 0)
    perror("nflog_close");
  return rc;
}

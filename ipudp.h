#ifndef IPUDP_DSCAO__
#define IPUDP_DSCAO__
#include <netinet/ip.h>
#include <netinet/udp.h>

#define MINI_UDPLEN	64

struct udp_packet {
	struct udphdr udph;
	char payload[];
};

unsigned short iphdr_check(const struct iphdr *iph);
unsigned short udp_check(const struct iphdr *iph,
                const struct udphdr *udph);
const struct udp_packet *udp_payload(const char *l2buf, int len);
#endif  /* IPUDP_DSCAO__ */

#ifndef IPUDP_DSCAO__
#define IPUDP_DSCAO__
#include <netinet/ip.h>
#include <netinet/udp.h>

#define MINI_UDPLEN	64

struct ip_packet {
	struct iphdr iph;
	struct udphdr udph;
	unsigned int mark;
	unsigned long seq;
	char payload[];
};

unsigned short iphdr_check(const struct iphdr *iph);
unsigned short udp_check(const struct iphdr *iph,
                const struct udphdr *udph);
const char *udp_payload(const char *l2buf, int len);
#endif  /* IPUDP_DSCAO__ */

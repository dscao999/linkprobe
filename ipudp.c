#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "ipudp.h"

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif
#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif

extern int verbose;

static unsigned long __attribute__((noinline))
uint16_sum(const char *arr, int len)
{
	unsigned long sum;
	const uint16_t *ele, *last;

	assert(((unsigned long)arr & 1) == 0);
	sum = 0;
	ele = (const uint16_t *)arr;
	last = (const uint16_t *)(arr + len - 1);
	while (ele < last)
		sum += *ele++;
	if ((len & 1) != 0)
		sum += (unsigned char)arr[len-1];
	return sum;
}

static inline uint16_t checksum(const char *arr, int len, unsigned long rem)
{
	unsigned long sum;

	sum = rem + uint16_sum(arr, len);
	while (sum >> 16)
		sum = (sum & 0x0ffff) + (sum >> 16);
	return sum;
}

unsigned short iphdr_check(const struct iphdr *iph)
{
	uint16_t sc;

	assert(iph->ihl == 5);
	sc = checksum((const char *)iph, 20, 0);
	return htons(~sc);
}

unsigned short udp_check(const struct iphdr *iph,
		const struct udphdr *udph)
{
	struct pseudo_udphdr {
		uint32_t saddr;
		uint32_t daddr;
		uint8_t zero;
		uint8_t proto;
		uint16_t udplen;
	} pseudo;
	unsigned long sum;
	uint16_t check;

	pseudo.saddr = iph->saddr;
	pseudo.daddr = iph->daddr;
	pseudo.zero = 0;
	pseudo.proto = iph->protocol;
	pseudo.udplen = udph->len;
	sum = uint16_sum((const char *)&pseudo, sizeof(pseudo));
	check = checksum((const char *)udph, ntohs(udph->len), sum);
	return htons(~check);
}

const char * udp_payload(const char *l2buf, int len)
{
	const struct iphdr *iph;
	const struct udphdr *udph;
	const struct ip_packet *pkt;
	unsigned short ck, udplen;
	struct timespec tm;
	char tmstamp[32];
	FILE *fout;

	if (l2buf == NULL || len < 28)
		return NULL;
	pkt = (const struct ip_packet *)l2buf;
	iph = &pkt->iph;
	ck = iphdr_check(iph);
	if (unlikely(ck != 0)) {
		fprintf(stderr, "IP Header checksum error: %04X\n", ck);
		return NULL;
	}
	if (iph->protocol != 17) {
		if (likely(verbose < 2))
			return NULL;
		clock_gettime(CLOCK_MONOTONIC_COARSE, &tm);
		snprintf(tmstamp, sizeof(tmstamp), "%10d.%6d", (int)tm.tv_sec,
				(int)(tm.tv_nsec / 1000));
		fprintf(stderr, "[%s] Ignore Non UDP packet\n", tmstamp);
		return NULL;
	}

	udph = &pkt->udph;
	ck = udp_check(iph, udph);
	if (unlikely(ck != 0)) {
		udplen = ntohs(udph->len);
		fprintf(stderr, "UDP checksum error: %04X, udp packet length: %hu\n", ck, udplen);
		fout = fopen("/tmp/packet.dat", "wb");
		fwrite(l2buf, 1, len, fout);
		fclose(fout);
		return NULL;
	}
	return pkt->payload;
}

void dump_packet(const struct ip_packet *ipkt)
{
	const struct iphdr *iph = &ipkt->iph;
	const struct udphdr *udph = &ipkt->udph;
	char ipaddr[24];

	inet_ntop(AF_INET, &iph->saddr, ipaddr, sizeof(ipaddr));
	printf("ID %hu, Src %s ", iph->id, ipaddr);
	inet_ntop(AF_INET, &iph->daddr, ipaddr, sizeof(ipaddr));
	printf("Dst %s. Src Port: %hd Dst Port: %hd\n", ipaddr,
			ntohs(udph->source), ntohs(udph->dest));
}

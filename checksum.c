#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "ipudp.h"

static char buf[2048];

int main(int argc, char *argv[])
{
	FILE *fin;
	const char *pfname;
	int len, retv;
	struct iphdr *iph;
	struct udphdr *udph;
	unsigned short c1, c2;

	retv = 0;
	if (argc > 1)
		pfname = argv[1];
	else
		pfname = "/tmp/packet.dat";
	fin = fopen(pfname, "rb");
	if (!fin) {
		fprintf(stderr, "Cannot open file '%s': %s\n", pfname, strerror(errno));
		exit(1);
	}
	len = fread(buf, 1, sizeof(buf), fin);
	fclose(fin);

	if (len == -1) {
		fprintf(stderr, "Cannot read file '%s': %s\n", pfname, strerror(errno));
		exit(2);
	}
	iph = (struct iphdr *)buf;
	c1 = iphdr_check(iph);
	udph = (struct udphdr *)(buf + sizeof(struct iphdr));
	c2 = udp_check(iph, udph);
	printf("IP Header Checksum: %04hX, UDP Checksum: %04hX\n", c1, c2);
	printf("IP Header Checksum in packet: %04hX, UDP Checksum in packet: %04hX\n",
			ntohs(iph->check), ntohs(udph->check));

	printf("IP length: %hd, UDP length: %hd\n", ntohs(iph->tot_len), ntohs(udph->len));
	iph->check = 0;
	udph->check = 0;
	c1 = iphdr_check(iph);
	c2 = udp_check(iph, udph);
	printf("Calculated IP Header Checksum: %04hX, Calculated UDP checksum: %04hX\n", c1, c2);
	return retv;
}

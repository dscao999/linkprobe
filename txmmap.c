#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>

#define unlikely(x)	__builtin_expect(!!(x), 0)

struct rx_ring {
	char *ring;
	int size;
	int strip;
	int ifindex;
};

static int create_sock(const char *ifname, struct rx_ring *rxr)
{
	int dlsock, sysret, retv;
	struct sockaddr_ll me;
	struct ifreq ifr;

	retv = 0;
	dlsock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (unlikely(dlsock == -1)) {
		fprintf(stderr, "Unable to open AF_PACKET socket: %s\n",
				strerror(errno));
		return -errno;
	}
	strncpy (ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(dlsock, SIOCGIFINDEX, &ifr) == -1) {
		fprintf(stderr, "ioctl failed: %s\n", strerror(errno));
		retv = -errno;
		goto err_exit_10;
	}
	rxr->ifindex = ifr.ifr_ifindex;

	memset(&me, 0, sizeof(me));
	me.sll_family = AF_PACKET;
	me.sll_protocol = htons(ETH_P_IP);
	me.sll_ifindex = rxr->ifindex;
	sysret = bind(dlsock, (struct sockaddr *)&me, sizeof(me));
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot bind AF_PACKET socket to local nic: %d\n",
				me.sll_ifindex);
		retv = -errno;
		goto err_exit_10;
	}
	return dlsock;

err_exit_10:
	close(dlsock);
	return retv;
}

static int init_sock(const char *ifname, struct rx_ring *rxr)
{
	int dlsock, retv, sysret;
	char *curframe;
	struct tpacket_req req_ring;

	retv = 0;
	dlsock = create_sock(ifname, rxr);
	if (dlsock < 0)
		return dlsock;

	memset(&req_ring, 0, sizeof(req_ring));
	req_ring.tp_frame_size = 2048;
	req_ring.tp_block_size = req_ring.tp_frame_size * 2;
	req_ring.tp_block_nr = 2;
	req_ring.tp_frame_nr = 4;
	rxr->size = req_ring.tp_block_size * 2;
	sysret = setsockopt(dlsock, SOL_PACKET, PACKET_TX_RING, &req_ring,
				sizeof(req_ring));
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot get receive map buffer: %s\n",
				strerror(errno));
		retv = -errno;
		goto err_exit_10;
	}
	rxr->ring = mmap(0, rxr->size, PROT_READ|PROT_WRITE, MAP_SHARED,
			dlsock, 0);
	if (unlikely(rxr->ring == MAP_FAILED)) {
		fprintf(stderr, "Cannot map receiving buffer: %s\n",
				strerror(errno));
		retv = -errno;
		goto err_exit_10;
	}
	rxr->strip = req_ring.tp_frame_size;
	for (curframe = rxr->ring; curframe < rxr->ring + rxr->size;
			curframe += rxr->strip)
		memset(curframe, 0, rxr->strip);

	return dlsock;

err_exit_10:
	close(dlsock);
	return retv;
}

int macstr2bin(const char *macstr, unsigned char *bin, int binlen)
{
	int i, bad;
	unsigned long num;
	const char *mac;
	char *colon, sym;

	bad = 0;
	mac = macstr;
	while ((sym = *mac++) != 0) {
		if (sym == ':' || (sym >= '0' && sym <= '9') ||
				(sym >= 'A' && sym <= 'F') ||
				(sym >= 'a' && sym <= 'f'))
			continue;
		bad = 1;
		break;
	}
	if (sym == 0 && *(mac-2) == ':')
		bad = 1;
	if (bad)
		return 0;
	i = 0;
	mac = macstr;
	do {
		num = strtoul(mac, &colon, 16);
		bin[i++] = num;
		mac = colon + 1;
	} while (i < binlen && *colon == ':');
	return i;
}

int main(int argc, char *argv[])
{
	struct rx_ring txr;
	int sock, retv = 0, *tmpi, sysret;
	const char *ifname = NULL, *dstmac = NULL;
	struct sockaddr_ll peer;
	unsigned int mark;
	struct tpacket_hdr *tpkhdr;

	if (argc > 1)
		ifname = argv[1];
	if (argc > 2)
		dstmac = argv[2];
	if (ifname == NULL || dstmac == NULL) {
		fprintf(stderr, "A NIC port and dest mac address must be specified\n");
		exit(1);
	}
	sock = init_sock(ifname, &txr);
	if (sock < 0) {
		fprintf(stderr, "socket initialization failed\n");
		exit(2);
	}
	memset(&peer, 0, sizeof(peer));
	peer.sll_family = AF_PACKET;
	peer.sll_protocol = htons(ETH_P_IP);
	peer.sll_ifindex = txr.ifindex;
	peer.sll_halen = macstr2bin(dstmac, peer.sll_addr, sizeof(peer.sll_addr));
	if (peer.sll_halen == 0) {
		fprintf(stderr, "Invalid MAC address: %s\n", dstmac);
		retv = 250;
		goto exit_10;
	}

	char *curframe;

	for (curframe = txr.ring; curframe < txr.ring + txr.size; curframe += txr.strip) {
		tpkhdr = (struct tpacket_hdr *)curframe;
		memset(curframe, 0, txr.strip);
		tpkhdr->tp_net = TPACKET_ALIGN(sizeof(struct tpacket_hdr));
		tpkhdr->tp_mac = tpkhdr->tp_net;
		tpkhdr->tp_len = 1500;
		tpkhdr->tp_snaplen = 1500;
		mark = 0;
		tmpi = (int *)(curframe + tpkhdr->tp_net);
		*tmpi++ = htonl(0xceedceed);
		for (; (void *)tmpi < (void *)(curframe + txr.strip -3);
				tmpi++)
			*tmpi = htonl(mark++);
		*(tmpi-1) = 0xffffffff;
		tpkhdr->tp_status = TP_STATUS_SEND_REQUEST;
	}
	sysret = sendto(sock, NULL, 0, 0, (const struct sockaddr *)&peer, sizeof(peer));
	if (sysret == -1) {
		fprintf(stderr, "sendto failed: %s\n", strerror(errno));
		retv = errno;
	}


exit_10:
	munmap(txr.ring, txr.size);
	close(sock);
	return retv;
}

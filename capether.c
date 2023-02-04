#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <signal.h>
#include <arpa/inet.h>
#include <assert.h>
#include "enumnet.h"
#include "ipudp.h"

static volatile int global_exit = 0;
static void sig_handler(int sig)
{
	if (sig == SIGTERM || sig == SIGINT)
		global_exit = 1;
}

static inline void install_handler(void (*handler)(int))
{
	struct sigaction sact;

	memset(&sact, 0, sizeof(sact));
	sact.sa_handler = handler;
	if (sigaction(SIGINT, &sact, NULL) == -1 ||
			sigaction(SIGTERM, &sact, NULL) == -1)
		fprintf(stderr, "Cannot install handler: %s\n", strerror(errno));
}

static struct list_head ifhead = LIST_HEAD_INIT(ifhead);
static char combuf[512];

int main(int argc, char *argv[])
{
	const char *ifname;
	int numcards, retv, sysret;
	struct netcard *nic;
	struct sockaddr_ll me, peer;
	socklen_t socklen;
	int dlsock;
	const struct udp_packet *udppkt;

	retv = 0;
	if (argc < 2) {
		fprintf(stderr, "One NIC port must be specified\n");
		return 1;
	}
	ifname = argv[1];

	numcards = enumerate_cards(&ifhead);
	if (numcards == 0) {
		fprintf(stderr, "No network ports found\n");
		return 2;
	}
	list_for_each_entry(nic, &ifhead, lnk) {
		if (strcmp(nic->ifname, ifname) == 0)
			break;
	}
	if (&nic->lnk == &ifhead) {
		fprintf(stderr, "No such nic: %s\n", ifname);
		return 3;
	}
	install_handler(sig_handler);

	dlsock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (dlsock == -1) {
		fprintf(stderr, "Cannot create AF_PACKET socket: %s\n",
				strerror(errno));
		return errno;
	}
	memset(&me, 0, sizeof(me));
	me.sll_family = AF_PACKET;
	me.sll_protocol = htons(ETH_P_IP);
	me.sll_ifindex = nic->ifindex;
	sysret = bind(dlsock, (struct sockaddr *)&me, sizeof(me));
	if (sysret == -1) {
		fprintf(stderr, "Cannot bind AF_PACKET socket to %s: \n",
				ifname);
		retv = errno;
		goto exit_10;
	}
	do {
		socklen = sizeof(peer);
		sysret = recvfrom(dlsock, combuf, sizeof(combuf), 0,
				(struct sockaddr *)&peer, &socklen);
		if (sysret == -1) {
			if (errno != EINTR)
				fprintf(stderr, "Failed to receive from AF_PACKET: %s\n",
						strerror(errno));
			break;
		} else if (sysret == 0) {
			fprintf(stderr, "Unexpected end of AF_PACKET\n");
			break;
		}
		printf("One packet received from %02x:%02x:%02x:%02x:%02x:%02x, length: %d\n", peer.sll_addr[0],
				peer.sll_addr[1], peer.sll_addr[2], peer.sll_addr[3], peer.sll_addr[4], peer.sll_addr[5],
				sysret);
		udppkt = udp_payload(combuf, sysret);
		if (udppkt)
			printf("A UDP Packet\n");
	} while (global_exit == 0);

exit_10:
	close(dlsock);
	return retv;
}

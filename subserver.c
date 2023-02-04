#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "enumnet.h"
#include "subserver.h"

#ifndef unlikely
#define unlikely(x)	__builtin_expect((x), 0)
#endif

static volatile int global_exit = 0;
static void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		global_exit = 1;
}

static char combuf[512];

static int read_link(int dlsock, const char *srcaddr)
{
	struct pollfd pfd;
	socklen_t socklen;
	struct sockaddr_ll peer;
	int maclen, link, tries, sysret;

	link = 0;
	maclen = strlen(srcaddr);
	pfd.fd = dlsock;
	pfd.events = POLLIN;
	pfd.revents = 0;
	tries = 0;
	do {
		sysret = poll(&pfd, 1, 500);
		if (sysret <= 0) {
			if (unlikely(sysret == -1))
				fprintf(stderr, "poll failed: %s\n",
						strerror(errno));
			break;
		}
		assert((pfd.revents & POLLIN) != 0);
		socklen = sizeof(peer);
		sysret = recvfrom(dlsock, combuf, sizeof(combuf), 0,
				(struct sockaddr *)&peer, &socklen);
		if (unlikely(sysret == -1)) {
			fprintf(stderr, "recvfrom AF_PACKET failed: %s.\n",
					strerror(errno));
			break;
		}
		if (strncmp((char *)peer.sll_addr, srcaddr, maclen) == 0 &&
				strcmp(combuf, "HAND-SHAKE") == 0)
			link = 1;
		else
			tries += 1;

	} while (sysret != 0 && link == 0 && tries < 10);
	return link;
}

static void probe_link(const struct sub_server *sv, const char *srcaddr)
{
	int dlsock, sysret, ifindex, found;
	struct sockaddr_ll me;
	struct netcard *iface;

	ifindex = 0;
	memset(&me, 0, sizeof(me));
	me.sll_family = AF_PACKET;
	me.sll_protocol = htons(ETH_P_IP);
	list_for_each_entry(iface, sv->ifhead, lnk) {
		me.sll_ifindex = iface->ifindex;
		dlsock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
		if (unlikely(dlsock == -1)) {
			fprintf(stderr, "Cannot create AF_PACKET socket: %s\n",
					strerror(errno));
			break;
		}
		sysret = bind(dlsock, (struct sockaddr *)&me, sizeof(me));
		if (unlikely(sysret == -1)) {
			fprintf(stderr, "bind to %s failed: %s\n",
					iface->ifname, strerror(errno));
			break;
		}
		sprintf(combuf, "TRY, %s", iface->macaddr);
		sysret = send(sv->sock, combuf, sizeof(combuf), 0);
		if (unlikely(sysret == -1)) {
			fprintf(stderr, "send failed: %s\n", strerror(errno));
			break;
		}
		found = read_link(dlsock, srcaddr);
		close(dlsock);
		if (found == 1) {
			ifindex = iface->ifindex;
			break;
		}
	}
	sprintf(combuf, "FINISH TRYING, %d", ifindex);
	sysret = send(sv->sock, combuf, sizeof(combuf), 0);
	if (sysret == -1)
		fprintf(stderr, "Unable to send %s\n", combuf);
}

static void receive_on(const struct sub_server *sv, int ifindex)
{
}

int subserver(const struct sub_server *sv)
{
	int retv, sysret, ifindex;
	char srcaddr[20];
	const char *cmd;
	struct sigaction sact;

	memset(&sact, 0, sizeof(sact));
	sact.sa_handler = sig_handler;
	if (sigaction(SIGINT, &sact, NULL) == -1 ||
			sigaction(SIGTERM, &sact, NULL) == -1)
		fprintf(stderr, "Cannot install SIGINT/SIGTERM Handler: %s\n",
				strerror(errno));
	retv = 0;
	cmd = combuf;
	sysret = recv(sv->sock, combuf, sizeof(combuf), 0);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot get commands. " \
				"recv failed: %s\n", strerror(errno));
		retv = errno;
		goto exit_10;
	} else if (sysret == 0) {
		fprintf(stderr, "Unexpected end of connection.\n");
		retv = 1;
		goto exit_10;
	}
	cmd = strtok(combuf, ", ");
	if (strcmp(cmd, "PROBE CONNECTION") == 0) {
		cmd = strtok(NULL, ", ");
		if (!cmd)
			fprintf(stderr, "Unexpected command: %s\n", cmd);
		else {
			strcpy(srcaddr, cmd);
			probe_link(sv, srcaddr);
		}
	} else if (strcmp(cmd, "START TEST") == 0) {
		cmd = strtok(NULL, ", ");
		ifindex = atoi(cmd);
		receive_on(sv, ifindex);
	}

exit_10:
	close(sv->sock);
	return retv;
}

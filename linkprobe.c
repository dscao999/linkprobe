/*
 * A Data Link Layer probe and test tool  - dscao999@hotmail.com
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <signal.h>
#include <arpa/inet.h>
#include <assert.h>
#include <getopt.h>
#include <stdlib.h>
#include <time.h>
#include <poll.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/mman.h>
#include "enumnet.h"
#include "ipudp.h"

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

#define	WRITE_ONCE(x, val)						\
	do {								\
		*(volatile typeof(x) *)&(x) = (val);			\
	} while (0)

#define READ_ONCE(x)	*(volatile typeof(x) *)&(x)

int verbose = 0;

static volatile int global_exit = 0;
static volatile int finish_up = 0;
static void sig_handler(int sig)
{
	if (sig == SIGTERM || sig == SIGINT)
		global_exit = 1;
	else if (sig == SIGALRM)
		finish_up = 1;
}

static inline void install_handler(void (*handler)(int))
{
	struct sigaction sact;

	memset(&sact, 0, sizeof(sact));
	sact.sa_handler = handler;
	if (sigaction(SIGINT, &sact, NULL) == -1 ||
			sigaction(SIGTERM, &sact, NULL) == -1)
		fprintf(stderr, "Cannot install handler: %s\n",
				strerror(errno));
}

struct statistics {
	unsigned long gn, bn;
	unsigned int tl;
	unsigned long gcnt, bcnt;
};

struct rx_ring {
	char *ring;
	int size;
	int strip;
};

struct header_inc {
	unsigned int dport:1;
	unsigned int sport:1;
	unsigned int daddr:1;
	unsigned int saddr:1;
};

struct cmdopts {
	unsigned char target[16];
	unsigned char me[16];
	union {
		struct header_inc hdinc;
		unsigned int hdv;
	};
	int nrblock;
	int nrframe;
	unsigned short duration;
	uint16_t ifindex;
	uint8_t tarlen, melen;
	uint8_t listen:1;
	uint8_t probe_only:1;
	uint8_t perftest:1;
};


static struct list_head ifhead = LIST_HEAD_INIT(ifhead);

struct work_info {
	pthread_t thid;
	pid_t pid;
	int mtu, mark_value;
	volatile double *bandwidth;
	int buflen;
	int sock;
	volatile int running;
	volatile int *stop;
	const struct cmdopts *opt;
	char *buf;
	struct rx_ring rxr;
	struct statistics st;
};

static int getmtu(int ifindex)
{
	struct ifreq mreq;
	int sysret, sock, mtu;

	mtu = 0;
	sock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (unlikely(sock == -1)) {
		fprintf(stderr, "Unable to open AF_PACKET socket: %s\n",
				strerror(errno));
		fprintf(stderr, "Cannot get MTU\n");
		return mtu;
	}
	memset(&mreq, 0, sizeof(mreq));
	mreq.ifr_ifindex = ifindex;
	sysret = ioctl(sock, SIOCGIFNAME, &mreq);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Unable to get ifname of nic %d: %s\n", ifindex,
				strerror(errno));
		goto exit_10;
	}
	sysret = ioctl(sock, SIOCGIFMTU, &mreq, sizeof(mreq));
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot get MTU of %s: %s\n", mreq.ifr_name,
				strerror(errno));
		mreq.ifr_mtu = 0;
	}
	printf("%s MTU: %d\n", mreq.ifr_name, mreq.ifr_mtu);
	mtu = mreq.ifr_mtu;

exit_10:
	close(sock);
	return mtu;
}

static void print_macaddr(const unsigned char *mac, int maclen)
{
	const unsigned char *tchar;
	char *buf;
	int len;

	if (unlikely(maclen) <= 0)
		return;
	buf = malloc(3*maclen);
	len = 0;
	for (tchar = mac; tchar < mac + maclen; tchar++)
		len += sprintf(buf+len, "%02hhX:", *tchar);
	*(buf+len-1) = 0;
	printf("%s", buf);
	free(buf);
}

static int nic_check(const char *iface, const struct list_head *ifhead,
		struct cmdopts *opt)
{
	struct netcard *nic;

	opt->ifindex = 0;
	opt->melen = 0;
	if (iface[0] < '0' || iface[0] > '9') {
		list_for_each_entry(nic, ifhead, lnk) {
			if (strcmp(iface, nic->ifname) == 0)
				break;
		}
		if (&nic->lnk != ifhead)
			opt->ifindex = nic->ifindex;
	} else {
		opt->ifindex = atoi(iface);
		list_for_each_entry(nic, ifhead, lnk) {
			if (nic->ifindex == opt->ifindex)
				break;
		}
		if (&nic->lnk == ifhead)
			opt->ifindex = 0;
	}
	if (opt->ifindex) {
		opt->melen = nic->maclen;
		memcpy(opt->me, nic->macaddr, nic->maclen);
	}
	return opt->ifindex;
}

static int parse_option(int argc, char *argv[], struct cmdopts *exopt)
{
	static const struct option options[] = {
		{
			.name = "listen",
			.has_arg = 0,
			.flag = NULL,
			.val = 'l'
		},
		{
			.name = "vary",
			.has_arg = 1,
			.flag = NULL,
			.val = 'a'
		},
		{
			.name = "novary",
			.has_arg = 1,
			.flag = NULL,
			.val = 'o'
		},
		{
			.name = "interface",
			.has_arg = 1,
			.flag = NULL,
			.val = 'i'
		},
		{
			.name = "perf",
			.has_arg = 0,
			.flag = NULL,
			.val = 'p'
		},
		{
			.name = "probe",
			.has_arg = 0,
			.flag = NULL,
			.val = 'b'
		},
		{
			.name = "duration",
			.has_arg = 1,
			.flag = NULL,
			.val = 'd'
		},
		{
			.name = "nrblock",
			.has_arg = 1,
			.flag = NULL,
			.val = 'n'
		},
		{
			.name = "nrframe",
			.has_arg = 1,
			.flag = NULL,
			.val = 'f'
		},
		{
		}
	};
	static const unsigned short defdur = 20;
	extern char *optarg;
	extern int optind, opterr, optopt;
	int fin, c, ncards, retv;
	char *iface;

	retv = 0;
	ncards = enumerate_cards(&ifhead);
	if (ncards == 0) {
		fprintf(stderr, "No NIC ports found!\n");
		return 251;
	}
	memset(exopt, 0, sizeof(*exopt));
	fin = 0;
	opterr = 0;
	while (fin == 0) {
		c = getopt_long(argc, argv, ":lpbi:d:a:o:n:f:",
				options, NULL);
		switch(c) {
			case -1:
				fin = 1;
				break;
			case '?':
				fprintf(stderr, "Unknown option %c ignored\n",
						(char)optopt);
				break;
			case ':':
				fprintf(stderr, "Missing arguments for %c. " \
						"option ignored\n",
						(char)(optopt));
				break;
			case 'n':
				exopt->nrblock = atoi(optarg);
				break;
			case 'f':
				exopt->nrframe = atoi(optarg);
				break;
			case 'a':
				if (strcmp(optarg, "dport") == 0)
					exopt->hdinc.dport = 1;
				else if (strcmp(optarg, "sport") == 0)
					exopt->hdinc.sport = 1;
				else if (strcmp(optarg, "daddr") == 0)
					exopt->hdinc.daddr = 1;
				else if (strcmp(optarg, "saddr") == 0)
					exopt->hdinc.saddr = 1;
				else
					fprintf(stderr, "Invalid variable: " \
							"%s ignored\n", optarg);
				break;
			case 'o':
				if (strcmp(optarg, "dport") == 0)
					exopt->hdinc.dport = 0;
				else if (strcmp(optarg, "sport") == 0)
					exopt->hdinc.sport = 0;
				else if (strcmp(optarg, "daddr") == 0)
					exopt->hdinc.daddr = 0;
				else if (strcmp(optarg, "saddr") == 0)
					exopt->hdinc.saddr = 0;
				else
					fprintf(stderr, "Invalid variable: " \
							"%s ignored\n", optarg);
				break;
			case 'd':
				exopt->duration = atoi(optarg);
				break;
			case 'l':
				exopt->listen = 1;
				break;
			case 'p':
				exopt->perftest = 1;
				break;
			case 'b':
				exopt->probe_only = 1;
			case 'i':
				iface = optarg;
				nic_check(iface, &ifhead, exopt);
				break;
			default:
				assert(0);
		}
	}
	if (exopt->nrblock == 0)
		exopt->nrblock = 64;
	if (exopt->nrframe == 0)
		exopt->nrframe = 16;
	if (exopt->ifindex == 0) {
		fprintf(stderr, "A local nic port must be specified\n");
		retv = 241;
	}
	if (exopt->listen == 0) {
		if (optind == argc) {
			fprintf(stderr, "A target mac address must be " \
					"specified\n");
			retv = 242;
		}
		iface = argv[optind];
		exopt->tarlen = mac2bin(iface, exopt->target,
				sizeof(exopt->target));
		if (exopt->tarlen == 0) {
			fprintf(stderr, "target '%s' is not a valid address\n",
					iface);
			retv = 243;
		}
		if (exopt->perftest == 0 && exopt->probe_only == 0)
			exopt->probe_only = 1;
		if (exopt->probe_only) {
			if (exopt->perftest) {
				fprintf(stderr, "Probe Only takes precedence " \
						"over perftest\n");
				exopt->perftest = 0;
			}
			if (exopt->duration != 0)
				fprintf(stderr, "Probe Only. Test duration: " \
						"%hd ignored\n", exopt->duration);
		}
		if ( exopt->duration > 3600) {
			fprintf(stderr, "Test Duration too large: %d. Reset "\
					"to %d\n", exopt->duration, defdur);
			exopt->duration = defdur;
		} else if (exopt->duration == 0)
			exopt->duration = defdur;
		if (exopt->hdv == 0)
			exopt->hdinc.dport = 1;
	} else {
		if (exopt->probe_only) {
			exopt->probe_only = 0;
			fprintf(stderr, "Listen mode. Probe only ignored\n");
		}
		if (exopt->duration != 0)
			fprintf(stderr, "Listen mode. Test Length: %d " \
					"ignored\n", exopt->duration);
	}
	return retv;
}

static int prepare_udp(char *buf, int buflen, const char *mesg, int bulk,
		const struct header_inc *hdinc)
{
	struct ip_packet *pkt;
	struct iphdr *iph;
	struct timespec tm;
	int len, headlen;
	static unsigned short dport = 10, sport = 10;
	static unsigned int saddr = (192 << 24) | (168 << 16) | (117 << 8) | 10;
	static unsigned int daddr = (192 << 24) | (168 << 16) | (119 << 8) | 10;
	static unsigned long pkts = 1;
	FILE *fout;

	headlen = sizeof(struct iphdr)+sizeof(struct udphdr);
	memset(buf, 0, headlen);
	pkt = (struct ip_packet *)buf;
	iph = &pkt->iph;
	iph->ihl = 5;
	iph->version = 4;
	iph->ttl = 1;
	iph->protocol = 17;
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm);
	iph->id = tm.tv_nsec & 0x0ffff;
	iph->saddr = htonl(saddr);
	iph->daddr = htonl(daddr);

	if (mesg)
		strcpy(pkt->payload, mesg);
	else
		pkt->payload[0] = 0;
	if (!bulk) {
		len = strlen(pkt->payload) + 1 + sizeof(struct ip_packet) -
				sizeof(struct iphdr) - sizeof(struct udphdr);
		if (len < MINI_UDPLEN)
			len = MINI_UDPLEN;
	} else
		len = buflen - headlen;
	pkt->udph.source = htons(sport);
	pkt->udph.dest = htons(dport);
	len += sizeof(struct udphdr);
	pkt->udph.len = htons(len);
	len += sizeof(*iph);
	iph->tot_len = htons(len);

	iph->check = htons(iphdr_check(iph));
	pkt->udph.check = htons(udp_check(iph, &pkt->udph));
	if (unlikely(udp_check(iph, &pkt->udph) != 0)) {
		fprintf(stderr, "bad udp checksum at packet no. %lu\n", pkts);
		fout = fopen("/tmp/packet.dat", "wb");
		fwrite(iph, 1, len, fout);
		fclose(fout);
	} else {
		pkts += 1;
		if (hdinc) {
			dport += hdinc->dport;
			sport += hdinc->sport;
			daddr += hdinc->daddr;
			saddr += hdinc->saddr;
		}
	}

	assert(iphdr_check(iph) == 0);
	assert(udp_check(iph, &pkt->udph) == 0);
	return len;
}

static const char PROBE[] = "PROBE LINK";
static const char PROBE_ONLY[] = "PROBE LINK ONLY";
static const char PROBE_ACK[] = "LINK PROBED OK";
static const char END_TEST[] = "END_OF_TEST ";
static const char LAST_PACKET[] = "THIS IS THE LAST PACKET";

static inline unsigned int tm_elapsed(const struct timespec *t0, const struct timespec *t1)
{
	unsigned int elapsed;
	long nsec;

	elapsed = t1->tv_sec - t0->tv_sec;
	nsec = t1->tv_nsec - t0->tv_nsec;
	if (nsec < 0) {
		elapsed -= 1;
		nsec += 1000000000l;
	}
	return (elapsed*1000000ul + nsec / 1000);
}

static const char Timeout[] = "Abort receiving bulk data! Timeout\n";
static const char PollFail[] = "Abort receiving bulk data! poll failed: %s\n";
static const char LinkErr[] = "Abort receiving bulk data! link error\n";

static int check_ring(const struct cmdopts *opt, struct statistics *st,
		struct rx_ring *rxr, int mark_value) {
	char *curframe, *pktbuf;
	struct tpacket_hdr *pkthdr;
	int pktlen, stop_flag;
	const char *payload;
	struct ip_packet *ippkt;

	stop_flag = 0;
	for (curframe = rxr->ring; curframe < rxr->ring + rxr->size;
			curframe += rxr->strip) {
		pkthdr = (struct tpacket_hdr *)curframe;
		if ((READ_ONCE(pkthdr->tp_status) & TP_STATUS_USER) == 0)
			continue;
		pktlen = pkthdr->tp_len;
		pktbuf = curframe + pkthdr->tp_net;
		ippkt = (struct ip_packet *)pktbuf;
		payload = udp_payload(pktbuf, pktlen);
		if (unlikely(!payload||ntohl(ippkt->mark) != mark_value)) {
			st->bn += pktlen + 18;
			st->bcnt += 1;
		} else {
			st->gn += pktlen + 18;
			st->gcnt += 1;
			if (strcmp(payload, LAST_PACKET) == 0)
				stop_flag = 1;
		}
		WRITE_ONCE(pkthdr->tp_status, TP_STATUS_KERNEL);
	}
	return stop_flag;
}

static void *receive_drain(void *arg)
{
	struct work_info *wrkinf = (struct work_info *)arg;
	struct pollfd pfd;
	int sysret, buflen, retv;
	const char *payload, *res;
	char *buf;
	unsigned long total_bytes;
	unsigned int usecs;
	struct ip_packet *pkt;

	retv = 0;
	wrkinf->running = 1;
	buflen = wrkinf->buflen;
	buf = malloc(buflen);
	if (!buf) {
		fprintf(stderr, "Out of Memory!");
		return NULL;
	}
	pkt = (struct ip_packet *)buf;
	pfd.fd = wrkinf->sock;
	pfd.events = POLLIN;
	payload = NULL;
	do {
		pfd.revents = 0;
		sysret = poll(&pfd, 1, 200);
		if (sysret == 0)
			continue;
		if (sysret == -1) {
			if (errno != EINTR)
				fprintf(stderr, "socket poll failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		}
		payload = NULL;
		sysret = recv(wrkinf->sock, buf, buflen, 0);
		if (sysret == -1) {
			if (errno != EINTR)
				fprintf(stderr, "recvfrom failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		}
		payload = udp_payload(buf, sysret);
		if (!payload)
			printf("foreign non UDP packet. Length: %d\n", sysret);
		else if (pkt->mark != htonl(wrkinf->mark_value)){
			printf("Foreign UDP packet. Source port: %hu, Dest " \
					"port: %hu\n", ntohs(pkt->udph.source),
					ntohs(pkt->udph.dest));
		}
	} while (*wrkinf->stop == 0 && global_exit == 0);
	if (payload && strncmp(payload, END_TEST, strlen(END_TEST)) == 0) {
		res = strchr(payload, ' ');
		sscanf(res, "%lu %u", &total_bytes, &usecs);
		*wrkinf->bandwidth = ((double)total_bytes) / (((double)usecs) / 1000000);
		printf("End Test received by receive drain\n");
	}
	free(buf);
	wrkinf->running = 0;
	return (void *)((long)retv);
}

static int recv_bulk(struct work_info *winf)
{
	struct timespec tm0, tm1;
	int retv, sysret, stop_flag;
	struct pollfd pfd;
	const struct cmdopts *opt = winf->opt;
	struct statistics *st = &winf->st;
	struct rx_ring *rxr = &winf->rxr;

	pfd.fd = winf->sock;
	pfd.events = POLLIN;
	pfd.revents = 0;
	retv = 0;
	st->gcnt = 0;
	st->bcnt = 0;
	st->gn = 0;
	st->bn = 0;
	st->tl = 0;
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm0);
	do {
		pfd.revents = 0;
		sysret = poll(&pfd, 1, 500);
		if (unlikely(sysret == 0)) {
			fprintf(stderr, Timeout);
			retv = 255;
			break;
		} else if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, PollFail, strerror(errno));
			retv = -errno;
			break;
		} else if (unlikely((pfd.revents & POLLIN) == 0)) {
			fprintf(stderr, LinkErr);
			retv = -254;
			break;
		}
		stop_flag = check_ring(opt, st, rxr, winf->mark_value);
	} while (stop_flag == 0 && global_exit == 0 && *winf->stop == 0);
	*winf->stop = 1;
	pfd.revents = 0;
	sysret = poll(&pfd, 1, 100);
	if (sysret > 0)
		check_ring(opt, st, rxr, winf->mark_value);
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm1);
	st->tl = tm_elapsed(&tm0, &tm1);

	printf("Received %lu packets, %lu bytes, in %u microseconds. %lu " \
			"foreign packets, %lu foreign bytes\n",
			st->gcnt, st->gn, st->tl, st->bcnt, st->bn);
	return retv;
}

static int send_bulk(struct work_info *inf, const struct sockaddr_ll *peer);
static int do_client(struct work_info *inf);

static int init_sock(struct work_info *winf, int rx)
{
	int dlsock, retv, sysret;
	struct sockaddr_ll me;
	struct tpacket_hdr *pkthdr;
	char *curframe;
	const struct cmdopts *opt = winf->opt;
	struct rx_ring *rxr = &winf->rxr;
	struct tpacket_req req_ring;

	retv = 0;
	dlsock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (unlikely(dlsock == -1)) {
		fprintf(stderr, "Unable to open AF_PACKET socket: %s\n",
				strerror(errno));
		return -errno;
	}
	memset(&me, 0, sizeof(me));
	me.sll_family = AF_PACKET;
	me.sll_protocol = htons(ETH_P_IP);
	me.sll_ifindex = opt->ifindex;
	sysret = bind(dlsock, (struct sockaddr *)&me, sizeof(me));
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot bind AF_PACKET socket to local nic: %d\n",
				opt->ifindex);
		retv = -errno;
		goto err_exit_10;
	}
	rxr->ring = NULL;
	if (rx == 0)
		return dlsock;

	memset(&req_ring, 0, sizeof(req_ring));
	req_ring.tp_frame_size = winf->buflen;
	req_ring.tp_block_size = req_ring.tp_frame_size * opt->nrframe;
	req_ring.tp_block_nr = opt->nrblock;
	req_ring.tp_frame_nr = opt->nrblock * opt->nrframe;
	rxr->size = req_ring.tp_block_size * req_ring.tp_block_nr;
	sysret = setsockopt(dlsock, SOL_PACKET, PACKET_RX_RING, &req_ring,
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
			curframe += rxr->strip) {
		pkthdr = (struct tpacket_hdr *)curframe;
		pkthdr->tp_status = TP_STATUS_KERNEL;
	}
	int fanout_arg;

	fanout_arg = (winf->pid & 0x0ffff) | (PACKET_FANOUT_LB << 16);
	sysret = setsockopt(dlsock, SOL_PACKET, PACKET_FANOUT, 
			&fanout_arg, sizeof(fanout_arg));
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "setsockopt for fanout failed: %s\n",
				strerror(errno));
		goto err_exit_20;
	}

	return dlsock;

err_exit_20:
	munmap(rxr->ring, rxr->size);
err_exit_10:
	close(dlsock);
	return retv;
}

static inline void close_sock(struct work_info *winf)
{
	if (winf->rxr.ring)
		munmap(winf->rxr.ring, winf->rxr.size);
	close(winf->sock);
}

static void * recv_horse(void *arg)
{
	struct work_info *winf = arg;
	int retv;

	winf->running = 1;
	retv = recv_bulk(winf);
	*winf->stop = 1;
	return (void *)((long)retv);
}

static int do_server(struct work_info *winf)
{
	int retv, len, sysret, probe_only, probelen;
	const char *payload, *mark;
	char *mesg;
	struct sockaddr_ll peer;
	const struct cmdopts *opt = winf->opt;
	socklen_t socklen;

	printf("Listening on ");
	print_macaddr(opt->me, opt->melen);
	printf("\n");

	mesg = winf->buf + winf->buflen;
	probelen = strlen(PROBE);
	retv = 0;
	winf->mark_value = -1;
	while (global_exit == 0) {
		probe_only = 0;
		socklen = sizeof(peer);
		sysret = recvfrom(winf->sock, winf->buf, winf->buflen, 0,
				(struct sockaddr *)&peer, &socklen);
		if (sysret == -1) {
			if (errno != EINTR)
				fprintf(stderr, "poll failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		}
		payload = udp_payload(winf->buf, sysret);
		if (!payload || strncmp(payload, PROBE, probelen) != 0)
			continue;
		if (strcmp(payload, PROBE_ONLY) == 0)
			probe_only = 1;
		else {
			mark = strrchr(payload, ' ');
			winf->mark_value = atoi(mark);
		}

		sprintf(mesg, "%s %ld", PROBE_ACK, random());
		len = prepare_udp(winf->buf, winf->mtu, mesg, 0, NULL);
		sysret = sendto(winf->sock, winf->buf, len, 0,
				(struct sockaddr *)&peer, sizeof(peer));
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "sendto failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		}
		if (probe_only)
			continue;

		close_sock(winf);

		volatile int stop = 0;
		struct work_info wrk[1];
		void *thres;

		wrk[0] = *winf;
		wrk[0].stop = &stop;
		wrk[0].sock = init_sock(wrk, 1);
		if (wrk[0].sock < 0)
			assert(0);
		sysret = pthread_create(&wrk[0].thid, NULL, recv_horse, wrk+0);
		if (unlikely(sysret != 0)) {
			fprintf(stderr, "Cannot create thread: %s\n", strerror(sysret));
			assert(0);
		}
		pthread_join(wrk[0].thid, &thres);
		retv = (int)(long)thres;
		if (retv > 0) {
			fprintf(stderr, "Abort Receiving Packets: %d. " \
					"Timeout!\n", retv);
			retv = 0;
		}
		mesg = winf->buf + winf->buflen;
		len = sprintf(mesg, "%s", END_TEST);
		sprintf(mesg+len, "%lu %u", wrk[0].st.gn, wrk[0].st.tl);
		((struct ip_packet *)winf->buf)->mark = htonl(winf->mark_value);
		len = prepare_udp(winf->buf, winf->mtu, mesg, 0, NULL);
		sysret = sendto(wrk[0].sock, winf->buf, len, 0,
				(struct sockaddr *)&peer, sizeof(peer));
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "send to failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		}
		close_sock(wrk);
		winf->sock = init_sock(winf, 0);
		if (unlikely(winf->sock < 0))
			break;
	}

	return retv;
}

static const char MUMESG[] = "Another instance of linkprobe is active now.\n";

static int check_instance(const char *lockfile)
{
	static const char self[] = "/proc/self/exe";
	DIR *proc;
	struct dirent *dentry;
	char *exename, *selfname, *procpath;
	int num, duplicate, fd;

	duplicate = 1;
	exename = malloc(PATH_MAX*3);
	if (unlikely(!exename)) {
		fprintf(stderr, "Out of Memory!\n");
		return duplicate;
	}
	selfname = exename + PATH_MAX;
	procpath = selfname + PATH_MAX;
	realpath(self, selfname);
	proc = opendir("/proc");
	if (unlikely(!proc)) {
		fprintf(stderr, "Unable to open directory /proc: %s\n",
				strerror(errno));
		return duplicate;
	}
	num = 0;
	errno = 0;
	while ((dentry = readdir(proc)) != NULL) {
		if (dentry->d_type != DT_DIR || dentry->d_name[0] < '0' ||
				dentry->d_name[0] > '9')
			continue;
		sprintf(procpath, "/proc/%s/exe", dentry->d_name);
		if (realpath(procpath, exename) &&
				strcmp(exename, selfname) == 0)
			num += 1;
		errno = 0;
	}
	if (errno != 0)
		fprintf(stderr, "Directory entry read failed: %s\n",
				strerror(errno));
	closedir(proc);
	free(exename);

	duplicate = num > 1;
	if (duplicate)
		return duplicate;

	fd = open(lockfile, O_CREAT|O_EXCL, 0666);
	if (fd == -1) {
		fprintf(stderr, "Cannot lock file '%s': %s\n", lockfile,
				strerror(errno));
		duplicate = 1;
	} else
		close(fd);
	return duplicate;
}

static inline void remove_instance_lock(const char *lockfile)
{
	unlink(lockfile);
}

int main(int argc, char *argv[])
{
	struct cmdopts cmdopt;
	struct work_info winf;
	int retv, nbits, mtu;
	struct netcard *nic, *nnic;
	static const char lockfile[] = "/run/lock/linkprobe";

	if (geteuid() != 0) {
		fprintf(stderr, "Must be root to run linkprobe\n");
		return 252;
	}
	if (unlikely(check_instance(lockfile))) {
		fprintf(stderr, MUMESG);
		return 253;
	}
	retv = parse_option(argc, argv, &cmdopt);
	if (retv != 0)
		goto exit_10;
	memset(&winf, 0, sizeof(winf));
	winf.opt = &cmdopt;
	winf.mtu = getmtu(cmdopt.ifindex);
	mtu = winf.mtu;
	nbits = 0;
	while (mtu) {
		nbits += 1;
		mtu >>= 1;
	}
	winf.buflen = (1 << nbits);
	winf.pid = getpid();
	winf.buf = malloc(winf.buflen + 128);
	if (unlikely(!winf.buf)) {
		fprintf(stderr, "Out of Memory!\n");
		retv = -ENOMEM;
		goto exit_10;
	}
	winf.sock = init_sock(&winf, 0);
	if (unlikely(winf.sock) < 0) {
		retv = -winf.sock;
		goto exit_10;
	}
	install_handler(sig_handler);
	if (cmdopt.listen) {
		retv = do_server(&winf);
	} else {
		retv = do_client(&winf);
	}

	close_sock(&winf);
exit_10:
	list_for_each_entry_safe(nic, nnic, &ifhead, lnk) {
		list_del(&nic->lnk, &ifhead);
		free(nic);
	}
	remove_instance_lock(lockfile);
	return retv;
}

static int do_client(struct work_info *winf)
{
	struct sockaddr_ll peer;
	const struct cmdopts *opt = winf->opt;
	const char *payload;
	struct pollfd pfd;
	int retv, len, sysret, count;
	char *mesg;
	struct timespec tm;
	struct ip_packet *ipkt;

	retv = 0;
	mesg = winf->buf + winf->buflen;
	pfd.fd = winf->sock;
	pfd.events = POLLIN;
	memset(&peer, 0, sizeof(peer));
	peer.sll_family = AF_PACKET;
	peer.sll_protocol = htons(ETH_P_IP);
	peer.sll_halen = opt->tarlen;
	memcpy(peer.sll_addr, opt->target, opt->tarlen);
	peer.sll_ifindex = opt->ifindex;

	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm);
	winf->mark_value = tm.tv_nsec & 0x0ffffffff;
	ipkt = (struct ip_packet *)winf->buf;
	ipkt->mark = htonl(winf->mark_value);
	retv = 0;
	count = 0;
	if (opt->probe_only)
		sprintf(mesg, "%s", PROBE_ONLY);
	else
		sprintf(mesg, "%s %d", PROBE, winf->mark_value);
	do {
		count += 1;
		len = prepare_udp(winf->buf, winf->mtu, mesg, 0, NULL);
		sysret = sendto(winf->sock, winf->buf, len, 0,
				(struct sockaddr *)&peer, sizeof(peer));
		if (sysret == -1) {
			if (errno != EINTR)
				fprintf(stderr, "sendto failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		}
		retv = 0;
		pfd.revents = 0;
		sysret = poll(&pfd, 1, 500);
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "poll failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		} else if (sysret == 0) {
			retv = 255;
			continue;
		}
		sysret = recv(winf->sock, winf->buf, winf->buflen, 0);
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "recvfrom failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		}
		payload = udp_payload(winf->buf, sysret);
		if (!payload)
			continue;
		if (strncmp(payload, PROBE_ACK, strlen(PROBE_ACK)) == 0)
			break;
	} while (global_exit == 0 && count < 50);
	if (retv == 0 && count < 50)
		printf("Link OK: ");
	else
		printf("Link Bad: ");
	print_macaddr(opt->me, opt->melen);
	printf(" ---> ");
	print_macaddr(opt->target, opt->tarlen);
	printf("\n");
	if (retv != 0 || opt->probe_only)
		return retv;

	tm.tv_sec = 0;
	tm.tv_nsec = 5000000000l;
	nanosleep(&tm, NULL);
	retv = send_bulk(winf, &peer);

	return retv;
}

static int send_bulk(struct work_info *winf, const struct sockaddr_ll *peer)
{
	int retv, buflen, off, len, sysret, count;
	FILE *fin;
	struct sigaction sact, oact;
	long rinc, *tmpl;
	timer_t tmid;
	struct sigevent sevent;
	struct itimerspec itm;
	const char *payload;
	const char *res;
	struct timespec tm0, tm1;
	struct pollfd pfd;
	struct ip_packet *pkt;
	struct work_info subwrk;
	volatile double speed;
	const struct cmdopts *opt = winf->opt;

	speed = -1.0;
	retv = 0;
	fin = fopen("/dev/urandom", "rb");
	if (unlikely(!fin)) {
		fprintf(stderr, "Cannot open /dev/urandom for reading: %s\n",
				strerror(errno));
		return errno;
	}
	off = 0;
	buflen = winf->buflen;
	do {
		len = fread(winf->buf+off, 1, buflen, fin);
		if (unlikely(len == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "Cannot read random bytes: %s\n",
						strerror(errno));
			fclose(fin);
			return errno;
		}
		off = len;
		buflen -= len;
	} while (buflen > 0);
	fclose(fin);

	memset(&sact, 0, sizeof(sact));
	sact.sa_handler = sig_handler;
	if (sigaction(SIGALRM, &sact, &oact) == -1) {
		fprintf(stderr, "Cannot install handler for SIGALRM: %s\n",
				strerror(errno));
		return errno;
	}
	memset(&sevent, 0, sizeof(sevent));
	sevent.sigev_notify = SIGEV_SIGNAL;
	sevent.sigev_signo = SIGALRM;
	sysret = timer_create(CLOCK_MONOTONIC, &sevent, &tmid);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot create timer: %s\n", strerror(errno));
		retv = errno;
		goto exit_10;
	}
	finish_up = 0;
	memset(&subwrk, 0, sizeof(subwrk));
	subwrk.mark_value = winf->mark_value;
	subwrk.opt = winf->opt;
	subwrk.sock = winf->sock;
	subwrk.buflen = winf->buflen;
	subwrk.stop = &finish_up;
	subwrk.mtu = winf->mtu;
	subwrk.running = -1;
	subwrk.bandwidth = &speed;
	sysret = pthread_create(&subwrk.thid, NULL, receive_drain, &subwrk);
	if (unlikely(sysret != 0))
		fprintf(stderr, "Warning! Cannot create drain thread: %s\n",
			strerror(sysret));
	count = 0;
	pkt = (struct ip_packet *)winf->buf;
	pkt->mark = htonl(winf->mark_value);
	memset(&itm, 0, sizeof(itm));
	itm.it_value.tv_sec = opt->duration;
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm0);
	sysret = timer_settime(tmid, 0, &itm, NULL);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot arm timer: %s\n", strerror(errno));
		retv = errno;
		goto exit_20;
	}
	do {
		rinc = random();
		tmpl = (long *)(pkt->payload);
		while (tmpl < (long *)(winf->buf+winf->buflen)) {
			*tmpl += rinc;
			tmpl += 1;
		}
		pkt->seq = count;
		len = prepare_udp(winf->buf, winf->mtu, NULL, 1, &opt->hdinc);
		sysret = sendto(winf->sock, winf->buf, len, 0,
				(struct sockaddr *)peer, sizeof(*peer));
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "Send failed: %s\n",
						strerror(errno));
			retv = -errno;
			goto exit_20;
		}
		count += 1;
	} while (finish_up == 0 && global_exit == 0);
	len = prepare_udp(winf->buf, winf->mtu, LAST_PACKET, 1, &opt->hdinc);
	sysret = sendto(winf->sock, winf->buf, len, 0, 
			(struct sockaddr *)peer, sizeof(*peer));
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm1);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Send failed: %s\n", strerror(errno));
		retv = -errno;
		goto exit_20;
	}
	count += 1;
	rinc = tm_elapsed(&tm0, &tm1) / 1000;
	printf("Total %d packets sent in %ld milliseconds\n", count, rinc);
	pfd.fd = winf->sock;
	pfd.events = POLLIN;
	count = 0;
	global_exit = 0;
	payload = NULL;
	if (subwrk.running != -1)
		pthread_join(subwrk.thid, NULL);
	if (speed != -1.0)
		goto exit_30;
	do {
		retv = 0;
		pfd.revents = 0;
		sysret = poll(&pfd, 1, 500);
		if (unlikely(sysret == 0)) {
			fprintf(stderr, Timeout);
			retv = 255;
			continue;
		} else if (unlikely(sysret == -1)) {
			fprintf(stderr, PollFail, strerror(errno));
			retv = -errno;
			break;
		}
		if ((pfd.revents & POLLIN) == 0) {
			fprintf(stderr, LinkErr);
			retv = -255;
			break;
		}
		payload = NULL;
		sysret = recv(winf->sock, winf->buf, len, 0);
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "recvfrom failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		}
		payload = udp_payload(winf->buf, sysret);
		if (payload) {
			pkt = (struct ip_packet *)winf->buf;
			if (strncmp(payload, END_TEST, strlen(END_TEST)) == 0)
				break;
			printf("Foreign UDP packet. Source port: %hu, Dest " \
					"port: %hu\n", ntohs(pkt->udph.source),
					ntohs(pkt->udph.dest));
		}
		count += 1;
	} while (count < 50 && global_exit == 0);
	if (retv != 0 || count == 50 || payload == NULL)
		goto exit_20;

	unsigned long total_bytes;
	unsigned int usecs;

	res = payload;
	res = strchr(res, ' ');
	sscanf(res, "%lu %u", &total_bytes, &usecs);
	speed = ((double)total_bytes) / (((double)usecs) / 1000000);

exit_30:
	printf("Speed: %18.2f bytes/s\n", speed);

exit_20:
	timer_delete(tmid);
exit_10:
	if (sigaction(SIGALRM, &oact, NULL) == -1)
		fprintf(stderr, "Cannot restore handler for SIGALRM: %s\n",
				strerror(errno));
	return retv;
}

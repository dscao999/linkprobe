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

#define POLL_TIME	250
#define POLL_CNT	4

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

struct packet_record {
	unsigned long pkts;
	unsigned short dport, sport;
	unsigned int saddr;
	unsigned int daddr;
};

struct header_inc {
	unsigned int inc_dport:1;
	unsigned int inc_sport:1;
	unsigned int inc_daddr:1;
	unsigned int inc_saddr:1;
};

struct cmdopts {
	unsigned char target[16];
	unsigned char me[16];
	struct header_inc hdinc;
	int nrblock;
	int nrframe;
	unsigned short duration;
	unsigned short numths;
	uint16_t ifindex;
	uint8_t tarlen, melen;
	uint8_t listen:1;
	uint8_t probe_only:1;
	uint8_t perftest:1;
};


static struct list_head ifhead = LIST_HEAD_INIT(ifhead);

struct proc_info {
	pid_t pid;
	int mtu;
	int buflen;
	const struct cmdopts *opt;
};

struct drain_thread {
	const struct proc_info *pinf;
	volatile double *bandwidth;
	pthread_t thid;
	volatile int *stop;
	volatile int running;
	int sock;
	int mark_value;
};

struct worker_params {
	const struct proc_info *pinf;
	int sock;
	int mark_value;
	char *buf;
	struct rx_ring rxr;
};

struct recv_thread {
	pthread_t thid;
	volatile int *stop;
	struct worker_params wparam;
	struct statistics st;
	const struct sockaddr_ll *peer;
	volatile int running;
	int numths;
};

struct send_thread {
	pthread_t thid;
	volatile double *bandwidth;
	volatile int *stop;
	struct packet_record prec;
	struct worker_params wparam;
	const struct sockaddr_ll *peer;
	volatile int running;
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
			.name = "threads",
			.has_arg = 1,
			.flag = NULL,
			.val = 't'
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
		c = getopt_long(argc, argv, ":lpbi:d:a:o:n:f:t:",
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
			case 't':
				exopt->numths = atoi(optarg);
				break;
			case 'n':
				exopt->nrblock = atoi(optarg);
				break;
			case 'f':
				exopt->nrframe = atoi(optarg);
				break;
			case 'a':
				if (strcmp(optarg, "dport") == 0)
					exopt->hdinc.inc_dport = 1;
				else if (strcmp(optarg, "sport") == 0)
					exopt->hdinc.inc_sport = 1;
				else if (strcmp(optarg, "daddr") == 0)
					exopt->hdinc.inc_daddr = 1;
				else if (strcmp(optarg, "saddr") == 0)
					exopt->hdinc.inc_saddr = 1;
				else
					fprintf(stderr, "Invalid variable: " \
							"%s ignored\n", optarg);
				break;
			case 'o':
				if (strcmp(optarg, "dport") == 0)
					exopt->hdinc.inc_dport = 0;
				else if (strcmp(optarg, "sport") == 0)
					exopt->hdinc.inc_sport = 0;
				else if (strcmp(optarg, "daddr") == 0)
					exopt->hdinc.inc_daddr = 0;
				else if (strcmp(optarg, "saddr") == 0)
					exopt->hdinc.inc_saddr = 0;
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
	if (exopt->numths == 0)
		exopt->numths = 2;
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
		if (exopt->hdinc.inc_dport == 0 &&
				exopt->hdinc.inc_sport == 0 &&
				exopt->hdinc.inc_daddr == 0 &&
				exopt->hdinc.inc_saddr == 0)
			exopt->hdinc.inc_dport = 1;
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

static const unsigned short c_dport = 10, c_sport = 10;
static const unsigned int c_saddr = (192 << 24) | (168 << 16) | (117 << 8) | 10;
static const unsigned int c_daddr = (192 << 24) | (168 << 16) | (119 << 8) | 10;

static int prepare_udp(char *buf, int buflen, const char *mesg, int bulk,
		struct packet_record *prec, const struct header_inc *hdinc)
{
	struct ip_packet *pkt;
	struct iphdr *iph;
	struct timespec tm;
	int len, headlen;
	unsigned short dport, sport;
	unsigned int saddr, daddr;
	FILE *fout;

	if (prec) {
		dport = prec->dport;
		sport = prec->sport;
		saddr = prec->saddr;
		daddr = prec->daddr;
	} else {
		dport = c_dport;
		sport = c_sport;
		saddr = c_saddr;
		daddr = c_daddr;
	}
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
		fprintf(stderr, "bad udp checksum at packet no. %lu\n", pkt->seq);
		fout = fopen("/tmp/packet.dat", "wb");
		fwrite(iph, 1, len, fout);
		fclose(fout);
	}
	if (prec && hdinc) {
		prec->dport += hdinc->inc_dport;
		prec->sport += hdinc->inc_sport;
		prec->daddr += hdinc->inc_daddr;
		prec->saddr += hdinc->inc_saddr;
	}

	assert(iphdr_check(iph) == 0);
	assert(udp_check(iph, &pkt->udph) == 0);
	return len;
}

enum MSGTYPE {V_PROBE = 1, V_PROBE_ONLY = 2, V_PROBE_ACK = 4, V_END_TEST = 8,
	V_LAST_PACKET = 16, V_RECV_READY = 32, V_BULK = 64};

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
		if (unlikely(!payload||ntohl(ippkt->mark) != mark_value||
					(ippkt->msgtyp != htonl(V_BULK) &&
					 ippkt->msgtyp != htonl(V_LAST_PACKET)))) {
			st->bn += pktlen + 18;
			st->bcnt += 1;
		} else {
			st->gn += pktlen + 18;
			st->gcnt += 1;
			if (ippkt->msgtyp == htonl(V_LAST_PACKET))
				stop_flag = 1;
		}
		WRITE_ONCE(pkthdr->tp_status, TP_STATUS_KERNEL);
	}
	return stop_flag;
}

static void *receive_drain(void *arg)
{
	struct drain_thread *drain = (struct drain_thread *)arg;
	struct pollfd pfd;
	int sysret, buflen, retv;
	const char *payload, *res;
	char *buf;
	unsigned long total_bytes;
	unsigned int usecs;
	struct ip_packet *pkt;
	const struct proc_info *pinf = drain->pinf;

	retv = 0;
	drain->running = 1;
	buflen = pinf->buflen;
	buf = malloc(buflen);
	if (!buf) {
		fprintf(stderr, "Out of Memory!");
		return NULL;
	}
	pkt = (struct ip_packet *)buf;
	pfd.fd = drain->sock;
	pfd.events = POLLIN;
	payload = NULL;
	do {
		pfd.revents = 0;
		sysret = poll(&pfd, 1, POLL_TIME);
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
		sysret = recv(drain->sock, buf, buflen, 0);
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
		else if (pkt->mark != htonl(drain->mark_value)){
			printf("Foreign UDP packet. Source port: %hu, Dest " \
					"port: %hu\n", ntohs(pkt->udph.source),
					ntohs(pkt->udph.dest));
		} else if (pkt->msgtyp == htonl(V_END_TEST)) {
			res = strchr(payload, ' ');
			sscanf(res, "%lu %u", &total_bytes, &usecs);
			*drain->bandwidth = ((double)total_bytes) / (((double)usecs) / 1000000);
			printf("End Test received by receive drain\n");
		}
	} while (*drain->stop == 0 && global_exit == 0);
	free(buf);
	drain->running = 0;
	return (void *)((long)retv);
}

static int recv_bulk(struct recv_thread *thinf)
{
	struct timespec tm0, tm1;
	int retv, sysret, stop_flag, tmcnt;
	struct pollfd pfd;
	struct worker_params *wparam = &thinf->wparam;
	const struct proc_info *pinf = wparam->pinf;
	const struct cmdopts *opt = pinf->opt;
	struct statistics *st = &thinf->st;
	struct rx_ring *rxr = &wparam->rxr;

	pfd.fd = wparam->sock;
	pfd.events = POLLIN;
	st->gcnt = 0;
	st->bcnt = 0;
	st->gn = 0;
	st->bn = 0;
	st->tl = 0;

	tmcnt = 0;
	retv = 0;
	do {
		pfd.revents = 0;
		sysret = poll(&pfd, 1, 5000);
		clock_gettime(CLOCK_MONOTONIC_COARSE, &tm0);
		if (unlikely(sysret == 0)) {
			fprintf(stderr, "Timeout waiting for client!\n");
			return 255;
		} else if (unlikely(sysret == -1)) {
			fprintf(stderr, "poll error when waiting for client: %s\n",
					strerror(errno));
			return -errno;
		} else if ((pfd.revents & POLLIN) == 0) {
			fprintf(stderr, "Link error when waiting for client!\n");
			return -254;
		}
		stop_flag = check_ring(opt, st, rxr, wparam->mark_value);
	} while (st->gcnt == 0);
	do {
		pfd.revents = 0;
		sysret = poll(&pfd, 1, POLL_TIME);
		if (unlikely(sysret == 0)) {
			if (*thinf->stop || stop_flag)
				break;
			tmcnt += 1;
			continue;
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
		stop_flag = check_ring(opt, st, rxr, wparam->mark_value);
	} while (stop_flag == 0 && global_exit == 0 && *thinf->stop == 0 &&
			tmcnt < POLL_CNT);
	if (stop_flag)
		*thinf->stop = 1;
	if (tmcnt == POLL_CNT)
		retv = 255;
	pfd.revents = 0;
	sysret = poll(&pfd, 1, 0);
	if (sysret > 0)
		check_ring(opt, st, rxr, wparam->mark_value);
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm1);
	st->tl = tm_elapsed(&tm0, &tm1);

	printf("Received %lu packets, %lu bytes, in %u microseconds. %lu " \
			"foreign packets, %lu foreign bytes\n",
			st->gcnt, st->gn, st->tl, st->bcnt, st->bn);
	return retv;
}

static int send_bulk(struct send_thread *thinf);
static int do_client(struct worker_params *wparam);

static int create_sock(const struct cmdopts *opt)
{
	int dlsock, sysret, retv;
	struct sockaddr_ll me;

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
	return dlsock;

err_exit_10:
	close(dlsock);
	return retv;
}

static int init_sock(struct worker_params *wparam, int rx, int fanout)
{
	int dlsock, retv, sysret, fanout_arg;
	struct tpacket_hdr *pkthdr;
	char *curframe;
	const struct proc_info *pinf = wparam->pinf;
	const struct cmdopts *opt = pinf->opt;
	struct tpacket_req req_ring;
	struct rx_ring *rxr = &wparam->rxr;

	retv = 0;
	dlsock = create_sock(opt);
	if (dlsock < 0)
		return dlsock;

	if (rx == 0) {
		rxr->ring = NULL;
		wparam->buf = malloc(pinf->buflen+128);
		if (unlikely(!wparam->buf)) {
			fprintf(stderr, "Out of Memory!\n");
			retv = -ENOMEM;
			goto err_exit_10;
		}
	} else {
		wparam->buf = NULL;
		memset(&req_ring, 0, sizeof(req_ring));
		req_ring.tp_frame_size = pinf->buflen;
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
	}

	if (fanout) {
		fanout_arg = (pinf->pid & 0x0ffff) | (PACKET_FANOUT_LB << 16);
		sysret = setsockopt(dlsock, SOL_PACKET, PACKET_FANOUT, 
				&fanout_arg, sizeof(fanout_arg));
		if (unlikely(sysret == -1)) {
			fprintf(stderr, "setsockopt for fanout failed: %s\n",
					strerror(errno));
			goto err_exit_20;
		}
	}

	return dlsock;

err_exit_20:
	munmap(rxr->ring, rxr->size);
err_exit_10:
	close(dlsock);
	return retv;
}

static inline void close_sock(struct worker_params *wparam)
{
	if (wparam->rxr.ring) {
		munmap(wparam->rxr.ring, wparam->rxr.size);
		wparam->rxr.ring = NULL;
	}
	if (wparam->buf) {
		free(wparam->buf);
		wparam->buf = NULL;
	}
	if (wparam->sock != -1) {
		close(wparam->sock);
		wparam->sock = -1;
	}
}

const char RECV_READY[] = "Receive ready";

static void * recv_horse(void *arg)
{
	struct recv_thread *thinf = arg;
	struct worker_params *wparam = &thinf->wparam;
	const struct proc_info *pinf = wparam->pinf;
	int retv, len, sysret;
	char *buf, *mesg;
	struct ip_packet *ipkt;
	const struct sockaddr_ll *peer;

	buf = malloc(pinf->buflen+128);
	if (unlikely(buf == NULL)) {
		fprintf(stderr, "Out of Memory");
		retv = -ENOMEM;
		goto exit_10;
	}
	mesg = buf + pinf->buflen;
	thinf->running = 1;
	ipkt = (struct ip_packet *)buf;
	ipkt->mark = htonl(wparam->mark_value);
	ipkt->msgtyp = htonl(V_RECV_READY);
	peer = thinf->peer;
	sprintf(mesg, "%d %s", thinf->numths, RECV_READY);
	len = prepare_udp(buf, pinf->mtu, mesg, 0, NULL, NULL);
	sysret = sendto(wparam->sock, buf, len, 0,
			(const struct sockaddr *)peer, sizeof(*peer));
	free(buf);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "sendto failed: %s\n", strerror(errno));
		retv = -errno;
		goto exit_10;
	}
	retv = recv_bulk(thinf);
	thinf->running = 0;

exit_10:
	return (void *)((long)retv);
}

static int do_server(struct worker_params *wparam)
{
	int retv, len, sysret, probe_only;
	const char *payload, *mark;
	char *mesg, *buf;
	struct sockaddr_ll peer;
	const struct proc_info *pinf = wparam->pinf;
	const struct cmdopts *opt = pinf->opt;
	socklen_t socklen;
	struct ip_packet *ipkt = (struct ip_packet *)wparam->buf;
	volatile int stop;
	int numths, i;
	struct recv_thread *thinfs, *thinf;
	void *thres;
	struct statistics st;

	printf("Listening on ");
	print_macaddr(opt->me, opt->melen);
	printf("\n");

	mesg = wparam->buf + pinf->buflen;
	retv = 0;
	wparam->mark_value = -1;
	while (global_exit == 0) {
		probe_only = 0;
		socklen = sizeof(peer);
		sysret = recvfrom(wparam->sock, wparam->buf, pinf->buflen, 0,
				(struct sockaddr *)&peer, &socklen);
		if (sysret == -1) {
			if (errno != EINTR)
				fprintf(stderr, "poll failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		}
		payload = udp_payload(wparam->buf, sysret);
		if (!payload || (ipkt->msgtyp != htonl(V_PROBE) &&
					ipkt->msgtyp != htonl(V_PROBE_ONLY)))
			continue;
		if (ipkt->msgtyp == htonl(V_PROBE_ONLY))
			probe_only = 1;
		else {
			mark = strrchr(payload, ' ');
			wparam->mark_value = atoi(mark);
		}

		sprintf(mesg, "%s %ld", PROBE_ACK, random());
		ipkt->msgtyp = htonl(V_PROBE_ACK);
		len = prepare_udp(wparam->buf, pinf->mtu, mesg, 0, NULL, NULL);
		sysret = sendto(wparam->sock, wparam->buf, len, 0,
				(const struct sockaddr *)&peer, sizeof(peer));
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "sendto failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		}
		if (probe_only)
			continue;

		close(wparam->sock);

		numths = opt->numths;
		thinfs = malloc(sizeof(struct recv_thread)*numths);
		if (unlikely(thinfs == NULL)) {
			fprintf(stderr, "Out of Memory!\n");
			retv = -ENOMEM;
			break;
		}
		for (i = 0, thinf = thinfs; i < numths; i++, thinf++) {
			thinf->running = -1;
			thinf->wparam.sock = -1;
			thinf->numths = numths;
		}
		stop = 0;
		for (i = 0, thinf = thinfs; i < numths; i++, thinf++) {
			thinf->wparam.pinf = wparam->pinf;
			thinf->wparam.mark_value = wparam->mark_value;
			thinf->stop = &stop;
			thinf->peer = &peer;
			thinf->wparam.sock = init_sock(&thinf->wparam, 1, 1);
			if (unlikely(thinf->wparam.sock < 0)) {
				retv = thinf->wparam.sock;
				goto err_exit_50;
			}
			sysret = pthread_create(&thinf->thid, NULL, recv_horse, thinf);
			if (unlikely(sysret != 0)) {
				fprintf(stderr, "Cannot create thread: %s\n", strerror(sysret));
				retv = -sysret;
				goto err_exit_50;
			}
		}

		st.gn = 0;
		st.bn = 0;
		st.tl = 0;
		st.gcnt = 0;
		st.bcnt = 0;
		for (i = 0, thinf = thinfs; i < numths; i++, thinf++) {
			pthread_join(thinf->thid, &thres);
			retv = (int)(long)thres;
			if (retv > 0) {
				fprintf(stderr, "Abort Receiving Packets: %d. " \
						"Timeout!\n", retv);
				retv = 0;
			}
			close_sock(&thinf->wparam);
			st.gn += thinf->st.gn;
			st.bn += thinf->st.bn;
			st.gcnt += thinf->st.gcnt;
			st.bcnt += thinf->st.bcnt;
			if (st.tl < thinf->st.tl)
				st.tl = thinf->st.tl;
		}
		free(thinfs);

		wparam->sock = create_sock(opt);
		assert(wparam->sock >= 0);
		buf = wparam->buf;
		mesg = buf + pinf->buflen;
		len = sprintf(mesg, "%s", END_TEST);
		sprintf(mesg+len, "%lu %u", st.gn, st.tl);
		ipkt->mark = htonl(wparam->mark_value);
		ipkt->msgtyp = htonl(V_END_TEST);
		len = prepare_udp(buf, pinf->mtu, mesg, 0, NULL, NULL);
		sysret = sendto(wparam->sock, wparam->buf, len, 0,
				(struct sockaddr *)&peer, sizeof(peer));
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "send to failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		}
	}

	return retv;

err_exit_50:
	sleep(1);
	for (i = 0, thinf = thinfs; i < numths; i++, thinf++) {
		if (thinf->running != -1) {
			pthread_cancel(thinf->thid);
			pthread_join(thinf->thid, NULL);
		}
		if (thinf->wparam.sock >= 0)
			close_sock(&thinf->wparam);
	}
	free(thinfs);
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
	struct proc_info pinf;
	struct worker_params wparam;
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
	memset(&pinf, 0, sizeof(pinf));
	pinf.opt = &cmdopt;
	pinf.mtu = getmtu(cmdopt.ifindex);
	mtu = pinf.mtu;
	nbits = 0;
	while (mtu) {
		nbits += 1;
		mtu >>= 1;
	}
	pinf.buflen = (1 << nbits);
	pinf.pid = getpid();
	wparam.buf = malloc(pinf.buflen + 128);
	if (unlikely(!wparam.buf)) {
		fprintf(stderr, "Out of Memory!\n");
		retv = -ENOMEM;
		goto exit_10;
	}
	wparam.pinf = &pinf;
	wparam.sock = init_sock(&wparam, 0, 0);
	if (unlikely(wparam.sock) < 0) {
		retv = -wparam.sock;
		goto exit_10;
	}
	install_handler(sig_handler);
	if (cmdopt.listen) {
		retv = do_server(&wparam);
	} else {
		retv = do_client(&wparam);
	}

	close_sock(&wparam);
exit_10:
	list_for_each_entry_safe(nic, nnic, &ifhead, lnk) {
		list_del(&nic->lnk, &ifhead);
		free(nic);
	}
	remove_instance_lock(lockfile);
	return retv;
}

static int do_client(struct worker_params *wparam)
{
	struct sockaddr_ll peer;
	const struct proc_info *pinf = wparam->pinf;
	const struct cmdopts *opt = pinf->opt;
	const char *payload;
	struct pollfd pfd;
	int retv, len, sysret, count, ready, numths;
	char *mesg;
	struct timespec tm;
	struct ip_packet *ipkt;
	unsigned int msgtyp;

	retv = 0;
	mesg = wparam->buf + pinf->buflen;
	pfd.fd = wparam->sock;
	pfd.events = POLLIN;
	memset(&peer, 0, sizeof(peer));
	peer.sll_family = AF_PACKET;
	peer.sll_protocol = htons(ETH_P_IP);
	peer.sll_halen = opt->tarlen;
	memcpy(peer.sll_addr, opt->target, opt->tarlen);
	peer.sll_ifindex = opt->ifindex;

	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm);
	wparam->mark_value = tm.tv_nsec & 0x0ffffffff;
	ipkt = (struct ip_packet *)wparam->buf;
	ipkt->mark = htonl(wparam->mark_value);
	retv = 0;
	count = 0;
	if (opt->probe_only) {
		sprintf(mesg, "%s", PROBE_ONLY);
		msgtyp = htonl(V_PROBE_ONLY);
	} else {
		sprintf(mesg, "%s %d", PROBE, wparam->mark_value);
		msgtyp = htonl(V_PROBE);
	}
	do {
		ipkt->msgtyp = msgtyp;
		len = prepare_udp(wparam->buf, pinf->mtu, mesg, 0, NULL, NULL);
		sysret = sendto(wparam->sock, wparam->buf, len, 0,
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
		sysret = poll(&pfd, 1, POLL_TIME);
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "poll failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		} else if (sysret == 0) {
			count += 1;
			continue;
		}
		sysret = recv(wparam->sock, wparam->buf, pinf->buflen, 0);
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "recvfrom failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		}
		payload = udp_payload(wparam->buf, sysret);
		if (payload && ipkt->msgtyp == htonl(V_PROBE_ACK) &&
				ipkt->mark == htonl(wparam->mark_value))
			break;
	} while (global_exit == 0 && count < POLL_CNT);
	if (count == POLL_CNT)
		retv = 255;
	if (retv == 0)
		printf("Link OK: ");
	else
		printf("Link Bad: ");
	print_macaddr(opt->me, opt->melen);
	printf(" ---> ");
	print_macaddr(opt->target, opt->tarlen);
	printf("\n");
	if (retv != 0 || opt->probe_only)
		return retv;

	numths = -1;
	count = 0;
	ready = 0;
	do {
		pfd.revents = 0;
		sysret = poll(&pfd, 1, POLL_TIME);
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "poll failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		} else if (sysret == 0) {
			count += 1;
			continue;
		}
		sysret = recv(wparam->sock, wparam->buf, pinf->buflen, 0);
		payload = udp_payload(wparam->buf, sysret);
		if (payload && ipkt->mark == htonl(wparam->mark_value) && 
				ipkt->msgtyp == htonl(V_RECV_READY)) {
			ready += 1;
			if (numths == -1)
				numths = atoi(payload);
		}
	} while (count < POLL_CNT && (numths == -1 || ready < numths));
	if (unlikely(count == POLL_CNT)) {
		fprintf(stderr, "Timeout when waiting for ready signal\n");
		return 255;
	}
	printf("Number of receiving threads: %d\n", ready);
	close_sock(wparam);

	struct sigaction sact, oact;
	timer_t tmid;
	struct sigevent sevent;
	struct itimerspec itm;

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

	struct send_thread thinf;
	double speed;

	speed = -1.0;
	finish_up = 0;

	thinf.bandwidth = &speed;
	thinf.stop = &finish_up;
	thinf.prec.sport = c_sport + (random() & 0x0ff);
	thinf.prec.dport = c_dport;
	thinf.prec.saddr = c_saddr;
	thinf.prec.daddr = c_daddr;
	thinf.wparam.pinf = pinf;
	thinf.wparam.mark_value = wparam->mark_value;
	thinf.wparam.sock = init_sock(&thinf.wparam, 0, 1);
	assert(thinf.wparam.sock != -1);
	thinf.peer = &peer;
	thinf.running = -1;

	memset(&itm, 0, sizeof(itm));
	itm.it_value.tv_sec = opt->duration;
	sysret = timer_settime(tmid, 0, &itm, NULL);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot arm timer: %s\n", strerror(errno));
		retv = errno;
		goto exit_20;
	}

	retv = send_bulk(&thinf);

	close_sock(&thinf.wparam);

exit_20:
	timer_delete(tmid);
exit_10:
	sigaction(SIGALRM, &oact, NULL);
	return retv;
}

static int send_bulk(struct send_thread *thinf)
{
	struct worker_params *wparam = &thinf->wparam;
	struct packet_record *prec = &thinf->prec;
	const struct sockaddr_ll *peer = thinf->peer;
	int retv, buflen, off, len, sysret, last, count;
	long telapsed;
	FILE *fin;
	const char *payload;
	const char *res;
	struct timespec tm0, tm1;
	struct pollfd pfd;
	struct ip_packet *pkt;
	const struct proc_info *pinf = wparam->pinf;
	const struct cmdopts *opt = pinf->opt;
	struct drain_thread drain;

	retv = 0;
	fin = fopen("/dev/urandom", "rb");
	if (unlikely(!fin)) {
		fprintf(stderr, "Cannot open /dev/urandom for reading: %s\n",
				strerror(errno));
		return errno;
	}
	off = 0;
	buflen = pinf->buflen;
	do {
		len = fread(wparam->buf+off, 1, buflen, fin);
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

	drain.sock = wparam->sock;
	drain.pinf = wparam->pinf;
	drain.running = -1;
	drain.bandwidth = thinf->bandwidth;
	drain.stop = thinf->stop;
	drain.mark_value = wparam->mark_value;
	sysret = pthread_create(&drain.thid, NULL, receive_drain, &drain);
	if (unlikely(sysret != 0)) {
		fprintf(stderr, "Warning! Cannot create drain thread: %s\n",
			strerror(sysret));
		return -sysret;
	}
	prec->pkts = 0;
	pkt = (struct ip_packet *)wparam->buf;
	pkt->mark = htonl(wparam->mark_value);
	pkt->msgtyp = htonl(V_BULK);
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm0);
	do {
		*(long *)(pkt->payload) = random();
		pkt->seq = prec->pkts;
		len = prepare_udp(wparam->buf, pinf->mtu, NULL, 1, prec, &opt->hdinc);
		sysret = sendto(wparam->sock, wparam->buf, len, 0,
				(struct sockaddr *)peer, sizeof(*peer));
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "Send failed: %s\n",
						strerror(errno));
			retv = -errno;
			goto exit_10;
		}
		prec->pkts += 1;
	} while (finish_up == 0 && global_exit == 0);
	pkt->msgtyp = htonl(V_LAST_PACKET);
	len = prepare_udp(wparam->buf, pinf->mtu, LAST_PACKET, 1, prec, &opt->hdinc);
	sysret = sendto(wparam->sock, wparam->buf, len, 0, 
			(struct sockaddr *)peer, sizeof(*peer));
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm1);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Send failed: %s\n", strerror(errno));
		retv = -errno;
		goto exit_10;
	}
	prec->pkts += 1;
	telapsed = tm_elapsed(&tm0, &tm1) / 1000;
	printf("Total %ld packets sent in %ld milliseconds\n", prec->pkts, telapsed);

	int tmout_cnt = 0;

	pfd.fd = wparam->sock;
	pfd.events = POLLIN;
	count = 0;
	payload = NULL;
	last = 0;
	pkt = (struct ip_packet *)wparam->buf;
	do {
		pfd.revents = 0;
		sysret = poll(&pfd, 1, POLL_TIME);
		if (unlikely(sysret == 0)) {
			count += 1;
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
		sysret = recv(wparam->sock, wparam->buf, len, 0);
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "recvfrom failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		}
		payload = udp_payload(wparam->buf, sysret);
		if (payload) {
			if (pkt->mark == htonl(wparam->mark_value) &&
					pkt->msgtyp == htonl(V_END_TEST)) {
				last = 1;
				break;
			}
			printf("Foreign UDP packet. Source port: %hu, Dest " \
					"port: %hu\n", ntohs(pkt->udph.source),
					ntohs(pkt->udph.dest));
		} else
			printf("Foreign non UDP packet.\n");
		tmout_cnt += 1;
	} while (*thinf->bandwidth == -1.0 && count < POLL_CNT &&
			global_exit == 0 && tmout_cnt < 100);
	if (last) {
		unsigned long total_bytes;
		unsigned int usecs;

		res = payload;
		res = strchr(res, ' ');
		sscanf(res, "%lu %u", &total_bytes, &usecs);
		*thinf->bandwidth = ((double)total_bytes) / (((double)usecs) / 1000000);
		printf("Speed: %18.2f bytes/s\n", *thinf->bandwidth);
	} else if (*thinf->bandwidth == -1.0) {
		retv = 255;
		fprintf(stderr, "Waiting for V_END_TEST. ");
		fprintf(stderr, Timeout);
	}


exit_10:
	*thinf->stop = 1;
	pthread_join(drain.thid, NULL);
	return retv;
}

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
#include "enumnet.h"
#include "ipudp.h"

#ifndef unlikely
#define unlikely(x)	__builtin_expect((x), 0)
#endif

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

static struct list_head ifhead = LIST_HEAD_INIT(ifhead);
static char combuf[1024];

struct header_inc {
	unsigned char dport:1;
	unsigned char sport:1;
	unsigned char daddr:1;
	unsigned char saddr:1;
};

struct cmdopts {
	struct sockaddr_ll *peer;
	char *buf;
	char target[16];
	char me[16];
	union {
		struct header_inc hdinc;
		unsigned char hdv;
	};
	int buflen;
	int sock;
	unsigned short duration;
	uint16_t ifindex;
	uint8_t tarlen, melen;
	uint8_t listen:1;
	uint8_t probe_only:1;
	uint8_t perftest:1;
};

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

static void parse_option(int argc, char *argv[], struct cmdopts *exopt)
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
		}
	};
	static const unsigned short defdur = 20;
	extern char *optarg;
	extern int optind, opterr, optopt;
	int fin, c, ncards;
	char *iface;

	ncards = enumerate_cards(&ifhead);
	if (ncards == 0) {
		fprintf(stderr, "No NIC ports found!\n");
		exit(0);
	}
	memset(exopt, 0, sizeof(*exopt));
	fin = 0;
	opterr = 0;
	while (fin == 0) {
		c = getopt_long(argc, argv, ":lpbi:d:a:",
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
				if (exopt->ifindex == 0) {
					fprintf(stderr, "A local nic port must"\
						       " be specified. '%s' is"\
							" not valid\n", iface);
					exit(1);
				}
				break;
			default:
				assert(0);
		}
	}
	if (exopt->ifindex == 0) {
		fprintf(stderr, "A local nic port must be specified\n");
		exit(1);
	}
	if (exopt->listen == 0) {
		if (optind == argc) {
			fprintf(stderr, "A target mac address must be " \
					"specified\n");
			exit(2);
		}
		iface = argv[optind];
		exopt->tarlen = mac2bin(iface, exopt->target,
				sizeof(exopt->target));
		if (exopt->tarlen == 0) {
			fprintf(stderr, "target '%s' is not a valid address\n",
					iface);
			exit(3);
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
}

static int prepare_udp(char *buf, int buflen, const char *mesg, int bulk,
		const struct header_inc *hdinc)
{
	struct udp_packet *udpbuf;
	struct iphdr *iph;
	struct timespec tm;
	int len, headlen;
	static unsigned short dport = 0, sport = 0;
	static unsigned int saddr = (192 << 24) | (168 << 16) | (117 << 8) | 10;
	static unsigned int daddr = (192 << 24) | (168 << 16) | (119 << 8) | 10;
	static unsigned long pkts = 1;
	FILE *fout;

	headlen = sizeof(struct iphdr)+sizeof(struct udphdr);
	memset(buf, 0, headlen);
	iph = (struct iphdr *)buf;
	iph->ihl = 5;
	iph->version = 4;
	iph->ttl = 1;
	iph->protocol = 17;
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm);
	iph->id = tm.tv_nsec & 0x0ffff;
	iph->saddr = saddr;
	iph->daddr = daddr;
	udpbuf = (struct udp_packet *)(buf + iph->ihl*4);

	if (!bulk) {
		if (mesg)
			strcpy(udpbuf->payload, mesg);
		else
			udpbuf->payload[0] = 0;
		len = strlen(udpbuf->payload) + 1;
		if (len < MINI_UDPLEN)
			len = MINI_UDPLEN;
	} else
		len = buflen - headlen;
	udpbuf->udph.uh_sport = sport;
	udpbuf->udph.uh_dport = dport;
	len += sizeof(struct udphdr);
	udpbuf->udph.uh_ulen = htons(len);
	len += sizeof(*iph);
	iph->tot_len = htons(len);

	iph->check = htons(iphdr_check(iph));
	udpbuf->udph.uh_sum = htons(udp_check(iph, &udpbuf->udph));
	if (unlikely(udp_check(iph, &udpbuf->udph) != 0)) {
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
	assert(udp_check(iph, &udpbuf->udph) == 0);
	return len;
}

static const char PROBE[] = "PROBE LINK";
static const char PROBE_ONLY[] = "PROBE LINK ONLY";
static const char PROBE_ACK[] = "LINK PROBED OK";
static const char END_TEST[] = "END_OF_TEST ";
static const char LAST_PACKET[] = "THIS IS THE LAST PACKET";

struct statistics {
	unsigned long n;
	unsigned int tl;
};

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
	return (elapsed*1000000 + nsec / 1000); 
}

static const char Timeout[] = "Abort receiving bulk data! Timeout\n";
static const char PollFail[] = "Abort receiving bulk data! poll failed: %s\n";
static const char LinkErr[] = "Abort receiving bulk data! link error\n";
static int recv_bulk(struct cmdopts *opt, struct statistics *st)
{
	socklen_t socklen;
	struct timespec tm0, tm1;
	int retv, sysret;
	struct pollfd pfd;
	unsigned long count;
	const struct udp_packet *udppkt;

	pfd.fd = opt->sock;
	pfd.events = POLLIN;
	pfd.revents = 0;
	retv = 0;
	sysret = poll(&pfd, 1, 500);
	if (unlikely(sysret == 0)) {
		fprintf(stderr, Timeout);
		return 255;
	} else if (unlikely(sysret == -1)) {
		fprintf(stderr, PollFail, strerror(errno));
		return -errno;
	} else if ((pfd.revents & POLLIN) == 0) {
		fprintf(stderr, LinkErr);
		return -254;
	}
	socklen = sizeof(*opt->peer);
	sysret = recvfrom(opt->sock, opt->buf, opt->buflen, 0,
			(struct sockaddr *)opt->peer, &socklen);
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm0);
	if (unlikely(sysret == -1)) {
		if (errno != EINTR)
			fprintf(stderr, "recvfrom failed: %s\n",
					strerror(errno));
		return -errno;
	}
	count = 0;
	st->n = 0;
	do {
		pfd.revents = 0;
		sysret = poll(&pfd, 1, 500);
		if (unlikely(sysret == 0)) {
			fprintf(stderr, Timeout);
			retv = 255;
			break;
		} else if (unlikely(sysret == -1)) {
			fprintf(stderr, PollFail, strerror(errno));
			retv = -errno;
			break;
		} else if (unlikely((pfd.revents & POLLIN) == 0)) {
			fprintf(stderr, LinkErr);
			retv = -254;
			break;
		}
		socklen = sizeof(*opt->peer);
		sysret = recvfrom(opt->sock, opt->buf, opt->buflen, 0,
				(struct sockaddr *)opt->peer, &socklen);
		clock_gettime(CLOCK_MONOTONIC_COARSE, &tm1);
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "recvfrom failed: %s\n",
						strerror(errno));
			retv = -errno;
			break;
		}
		st->n += sysret + 18;
		count += 1;
		udppkt = udp_payload(opt->buf, sysret);
		if (udppkt && strcmp(udppkt->payload, LAST_PACKET) == 0)
			break;
	} while (1);
	st->tl = tm_elapsed(&tm0, &tm1);
	fprintf(stderr, "Received %lu packets, %lu bytes, in %u microseconds\n", count, st->n, st->tl);
	return retv;
}

static int send_bulk(struct cmdopts *opt);
static int do_client(struct cmdopts *opt);

static int do_server(struct cmdopts *opt)
{
	socklen_t socklen;
	int retv, len, sysret, probe_only, i;
	const struct udp_packet *udppkt;
	struct statistics st;
	char *mesg, *adr;
	struct sockaddr_ll *peer;
	struct timespec tmnow;

	adr = opt->me;
	printf("Listening on ");
	for (i = 0; i < opt->melen - 1; i++, adr++) {
		printf("%02hhx:", *adr);
	}
	printf("%02hhx\n", *adr);
	peer = opt->peer;
	retv = 0;
	while (retv == 0 && global_exit == 0) {
		probe_only = 0;
		socklen = sizeof(*opt->peer);
		sysret = recvfrom(opt->sock, opt->buf, opt->buflen, 0,
				(struct sockaddr *)peer, &socklen);
		if (sysret == -1) {
			if (errno != EINTR)
				fprintf(stderr, "recvfrom failed: %s\n",
						strerror(errno));
			retv = errno;
			break;
		}
		udppkt = udp_payload(opt->buf, sysret);
		if (!udppkt)
			continue;
		if (strncmp(udppkt->payload, PROBE, strlen(PROBE)) == 0) {
			if (strcmp(udppkt->payload, PROBE_ONLY) == 0)
				probe_only = 1;
			st.n = 0;
			st.tl = 0;
			mesg = opt->buf + opt->buflen - 64;
			clock_gettime(CLOCK_MONOTONIC_COARSE, &tmnow);
			sprintf(mesg, "%s %ld", PROBE_ACK, tmnow.tv_nsec);
			len = prepare_udp(opt->buf, opt->buflen - 64, mesg, 0,
					NULL);
			peer->sll_ifindex = opt->ifindex;
			sysret = sendto(opt->sock, opt->buf, len, 0,
					(struct sockaddr *)peer, sizeof(*peer));
			if (unlikely(sysret == -1)) {
				if (errno != EINTR)
					fprintf(stderr, "sendto failed: %s\n",
							strerror(errno));
				retv = errno;
				break;
			}
			if (probe_only)
				continue;
			retv = recv_bulk(opt, &st);
			if (retv > 0)
				continue;
			else if (retv < 0) {
				retv = -retv;
				break;
			}
			mesg = opt->buf + opt->buflen - 128;
			len = sprintf(mesg, "%s", END_TEST);
			sprintf(mesg+len, "%lu %u", st.n, st.tl);
			len = prepare_udp(opt->buf, opt->buflen - 128, mesg, 0,
					NULL);
			peer->sll_ifindex = opt->ifindex;
			sysret = sendto(opt->sock, opt->buf, len, 0,
					(struct sockaddr *)peer, sizeof(*peer));
			if (unlikely(sysret == -1)) {
				if (errno != EINTR)
					fprintf(stderr, "sendto failed: %s\n",
							strerror(errno));
				retv = errno;
			}
		}
	}
	return retv;
}

static const char MUMESG[] = "Another instance of linkprobe is active now.\n";

static int check_instance(void)
{
	static const char self[] = "/proc/self/exe";
	DIR *proc;
	struct dirent *dentry;
	char *exename, *selfname, *procpath;
	int num;

	exename = malloc(PATH_MAX*3);
	if (unlikely(!exename)) {
		fprintf(stderr, "Out of Memory!\n");
		exit(ENOMEM);
	}
	selfname = exename + PATH_MAX;
	procpath = selfname + PATH_MAX;
	realpath(self, selfname);
	proc = opendir("/proc");
	if (unlikely(!proc)) {
		fprintf(stderr, "Unable to open directory /proc: %s\n",
				strerror(errno));
		exit(250);
	}
	num = 0;
	errno = 0;
	while ((dentry = readdir(proc)) != NULL) {
		if (dentry->d_type != DT_DIR || dentry->d_name[0] < '0' ||
				dentry->d_name[0] > '9')
			continue;
		sprintf(procpath, "/proc/%s/exe", dentry->d_name);
		realpath(procpath, exename);
		if (strcmp(exename, selfname) == 0)
			num += 1;
		errno = 0;
	}
	if (errno != 0)
		fprintf(stderr, "Directory entry read failed: %s\n",
				strerror(errno));
	closedir(proc);
	free(exename);
	return num;
}

int main(int argc, char *argv[])
{
	struct cmdopts cmdopt;
	int dlsock, sysret, retv;
	struct sockaddr_ll me, peer;
	struct netcard *nic, *nnic;

	if (unlikely(check_instance() != 1)) {
		fprintf(stderr, MUMESG);
		return 253;
	}
	if (geteuid() != 0) {
		fprintf(stderr, "Must be root to run linkprobe\n");
		return 252;
	}
	retv = 0;
	parse_option(argc, argv, &cmdopt);
	dlsock = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (unlikely(dlsock == -1)) {
		fprintf(stderr, "Unable to open AF_PACKET socket: %s\n",
				strerror(errno));
		exit(5);
	}
	memset(&me, 0, sizeof(me));
	me.sll_family = AF_PACKET;
	me.sll_protocol = htons(ETH_P_IP);
	me.sll_ifindex = cmdopt.ifindex;
	sysret = bind(dlsock, (struct sockaddr *)&me, sizeof(me));
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot bind AF_PACKET socket to local nic: %d\n",
				cmdopt.ifindex);
		exit(6);
	}
	install_handler(sig_handler);
	cmdopt.buf = combuf;
	cmdopt.buflen = sizeof(combuf);
	cmdopt.sock = dlsock;
	cmdopt.peer = &peer;
	if (cmdopt.listen) {
		retv = do_server(&cmdopt);
	} else {
		retv = do_client(&cmdopt);
	}

	close(dlsock);

	list_for_each_entry_safe(nic, nnic, &ifhead, lnk) {
		list_del(&nic->lnk, &ifhead);
		free(nic);
	}
	return retv;
}

static int do_client(struct cmdopts *opt)
{
	struct sockaddr_ll *peer;
	const struct udp_packet *udp;
	socklen_t socklen;
	struct pollfd pfd;
	int retv, len, sysret, count;

	retv = 0;
	pfd.fd = opt->sock;
	pfd.events = POLLIN;
	peer = opt->peer;
	memset(peer, 0, sizeof(*peer));
	peer->sll_family = AF_PACKET;
	peer->sll_protocol = htons(ETH_P_IP);

	count = 0;
	if (opt->probe_only)
		len = prepare_udp(opt->buf, opt->buflen, PROBE_ONLY, 0, NULL);
	else
		len = prepare_udp(opt->buf, opt->buflen, PROBE, 0, NULL);
	do {
		peer->sll_halen = opt->tarlen;
		memcpy(peer->sll_addr, opt->target, opt->tarlen);
		peer->sll_ifindex = opt->ifindex;
		sysret = sendto(opt->sock, opt->buf, len, 0,
				(struct sockaddr *)peer, sizeof(*peer));
		if (sysret == -1) {
			if (errno != EINTR)
				fprintf(stderr, "sendto failed: %s\n",
						strerror(errno));
			retv = errno;
			break;
		}

		pfd.revents = 0;
		sysret = poll(&pfd, 1, 1000);
		if (sysret == 0) {
			retv = 255;
			break;
		} else if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "poll failed: %s\n",
						strerror(errno));
			retv = errno;
			break;
		}
		if ((pfd.revents & POLLIN) == 0) {
			fprintf(stderr, "Error on link\n");
			retv = 254;
			break;
		}
		socklen = sizeof(*peer);
		sysret = recvfrom(opt->sock, opt->buf, opt->buflen, 0,
				(struct sockaddr *)peer, &socklen);
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "recvfrom failed: %s\n",
						strerror(errno));
			retv = errno;
			break;
		}
		udp = udp_payload(opt->buf, sysret);
		if (udp && strncmp(udp->payload, PROBE_ACK, strlen(PROBE_ACK))
				== 0)
			break;
		if (opt->probe_only)
			len = prepare_udp(opt->buf, opt->buflen, PROBE_ONLY, 0,
					NULL);
		else
			len = prepare_udp(opt->buf, opt->buflen, PROBE, 0,
					NULL);
		count += 1;
	} while (global_exit == 0 && retv == 0 && count < 50);
	if (retv == 0 && count < 50)
		printf("Link OK: ");
	else
		printf("Link Bad: ");
	printf("%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX ---> ", opt->me[0],
			opt->me[1], opt->me[2], opt->me[3], opt->me[4],
			opt->me[5]);
	printf("%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\n", opt->target[0],
			opt->target[1], opt->target[2], opt->target[3],
			opt->target[4], opt->target[5]);
	if (retv != 0 || opt->probe_only)
		return retv;

	retv = send_bulk(opt);

	return retv;
}

static int send_bulk(struct cmdopts *opt)
{
	int retv, buflen, off, len, sysret, count;
	FILE *fin;
	struct sigaction sact, oact;
	long rinc, *tmpl;
	timer_t tmid;
	struct sigevent sevent;
	struct itimerspec itm;
	struct sockaddr_ll *peer;
	socklen_t socklen;
	const struct udp_packet *udp;
	const char *res;
	struct timespec tm0, tm1;
	struct pollfd pfd;

	retv = 0;
	fin = fopen("/dev/urandom", "rb");
	if (unlikely(!fin)) {
		fprintf(stderr, "Cannot open /dev/urandom for reading: %s\n",
				strerror(errno));
		return errno;
	}
	off = 0;
	buflen = opt->buflen;
	do {
		len = fread(opt->buf+off, 1, buflen, fin);
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

	peer = opt->peer;
	memset(peer, 0, sizeof(*peer));
	peer->sll_family = AF_PACKET;
	peer->sll_protocol = htons(ETH_P_IP);
	peer->sll_ifindex = opt->ifindex;
	peer->sll_halen = opt->tarlen;
	memcpy(peer->sll_addr, opt->target, opt->tarlen);

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
	memset(&itm, 0, sizeof(itm));
	itm.it_value.tv_sec = opt->duration;
	sysret = timer_settime(tmid, 0, &itm, NULL);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Cannot set timer: %s\n", strerror(errno));
		retv = errno;
		goto exit_20;
	}
	count = 0;
	finish_up = 0;
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm0);
	do {
		rinc = random();
		tmpl = (long *)opt->buf;
		while (tmpl < (long *)(opt->buf+opt->buflen)) {
			*tmpl += rinc;
			tmpl += 1;
		}
		len = prepare_udp(opt->buf, opt->buflen, NULL, 1, &opt->hdinc);
		sysret = sendto(opt->sock, opt->buf, len, 0,
				(struct sockaddr *)peer, sizeof(*peer));
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "Send failed: %s\n",
						strerror(errno));
			if (finish_up == 0)
				retv = errno;
			continue;
		}
		count += 1;
	} while (finish_up == 0 && global_exit == 0 && retv == 0);
	strcpy(opt->buf+sizeof(struct iphdr)+sizeof(struct udphdr), LAST_PACKET);
	len = prepare_udp(opt->buf, opt->buflen, NULL, 1, &opt->hdinc);
	sysret = sendto(opt->sock, opt->buf, len, 0, 
			(struct sockaddr *)peer, sizeof(*peer));
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm1);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "Send failed: %s\n", strerror(errno));
		retv = errno;
		goto exit_20;
	}
	opt->duration = tm_elapsed(&tm0, &tm1) / 1000;
	printf("Total %d packets sent in %d milliseconds\n", count,
			opt->duration);
	pfd.fd = opt->sock;
	pfd.events = POLLIN;
	pfd.revents = 0;
	count = 0;
	global_exit = 0;
	udp = NULL;
	do {
		sysret = poll(&pfd, 1, 500);
		if (unlikely(sysret == 0)) {
			fprintf(stderr, Timeout);
			retv = 255;
			break;
		} else if (unlikely(sysret == -1)) {
			fprintf(stderr, PollFail, strerror(errno));
			retv = errno;
			break;
		}
		if ((pfd.revents & POLLIN) == 0) {
			fprintf(stderr, LinkErr);
			retv = 255;
			break;
		}
		socklen = sizeof(peer);
		udp = NULL;
		sysret = recvfrom(opt->sock, opt->buf, len, 0,
				(struct sockaddr *)peer, &socklen);
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "recvfrom failed: %s\n",
						strerror(errno));
			retv = errno;
			break;
		}
		udp = udp_payload(opt->buf, sysret);
		if (udp && strncmp(udp->payload, END_TEST, strlen(END_TEST)) == 0)
			break;
		printf("W: %s\n", opt->buf+28);
		count += 1;
	} while (count < 50 && global_exit == 0);
	if (retv != 0 || count == 50 || udp == NULL)
		goto exit_20;

	unsigned long total_bytes;
	unsigned int msecs;
	double speed;

	res = udp->payload;
	res = strchr(res, ' ');
	sscanf(res, "%lu %u", &total_bytes, &msecs);
	speed = ((double)total_bytes) / (((double)msecs) / 1000000);
	printf("Speed: %18.2f bytes/s\n", speed);

exit_20:
	timer_delete(tmid);
exit_10:
	if (sigaction(SIGALRM, &oact, NULL) == -1)
		fprintf(stderr, "Cannot restore handler for SIGALRM: %s\n",
				strerror(errno));
	return retv;
}

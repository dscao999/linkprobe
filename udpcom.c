#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

static volatile int global_exit = 0;
static void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		global_exit = 1;
}

static const char end_mark[] = "STOP TEST";

struct cmdopt {
	int sndrcv;
	const char * port;
	const char *server;
	const char *ifname;
};

static void parse_option(int argc, char *argv[], struct cmdopt *opt)
{
	const static char default_port[] = "12395";
	static struct option options[] = {
		{
			.name = "server",
			.has_arg = 1,
			.flag = NULL,
			.val = 's'
		},
		{
			.name = "port",
			.has_arg = 1,
			.flag = NULL,
			.val = 'p'
		},
		{
			.name = "interface",
			.has_arg = 1,
			.flag = NULL,
			.val = 'i'
		},
		{
			.name = NULL,
			.has_arg = 0,
			.flag = NULL,
			.val = 0
		}
	};
	int c, fin;
	extern char *optarg;
	extern int opterr, optopt;

	memset(opt, 0, sizeof(*opt));
	opterr = 0;
	fin = 0;
	while (fin == 0) {
		c = getopt_long(argc, argv, ":s:p:i:", options, NULL);
		switch(c) {
			case -1:
				fin = 1;
				break;
			case 's':
				opt->server = optarg;
				break;
			case 'p':
				opt->port = optarg;
				break;
			case 'i':
				opt->ifname = optarg;
				break;
			case '?':
				fprintf(stderr, "unknown option: %c\n", optopt);
				break;
			case ':':
				fprintf(stderr, "missing argument for %c\n",
						optopt);
				break;
			default:
				assert(0);
		}
	}
	if (opt->server == NULL)
		opt->sndrcv = 1;
	if (opt->port == NULL)
		opt->port = default_port;
}

static char xbuf[512];

static int do_server(int sock, struct cmdopt *opt)
{
	struct addrinfo *addrs, *adr, hints;
	int sysret, retv;
	struct sockaddr_in peer;
	socklen_t solen;

	retv = 0;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	sysret = getaddrinfo(NULL, opt->port, &hints, &addrs);
	if (unlikely(sysret != 0)) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(sysret));
		return sysret;
	}
	for (adr = addrs; adr != NULL; adr = adr->ai_next) {
		sysret = bind(sock, adr->ai_addr, adr->ai_addrlen);
		if (sysret != -1)
			break;
	}
	freeaddrinfo(addrs);
	if (adr == NULL) {
		fprintf(stderr, "all binds failed: %s\n", strerror(errno));
		return errno;
	}

	do {
		solen = sizeof(peer);
		sysret = recvfrom(sock, xbuf, sizeof(xbuf), 0,
				(struct sockaddr *)&peer, &solen);
		if (unlikely(sysret == -1)) {
			if (errno != EINTR)
				fprintf(stderr, "recvfrom failed: %s\n",
						strerror(errno));
			retv = errno;
			break;
		} else if (unlikely(sysret == 0)) {
			fprintf(stderr, "connection unexpected closed.\n");
			break;
		}
		printf("%s", xbuf);
		if (strcmp(xbuf, end_mark) == 0)
			break;
	} while (global_exit == 0);
	return retv;
}

static int readline(char *buf, int len)
{
	int c, pos;

	pos = 0;
	do {
		c = getchar();
		buf[pos++] = c;
	} while (c != '\n' && pos < len-1);
	buf[pos] = 0;
	return pos + 1;
}
static int do_client(int sock, struct cmdopt *opt)
{
	int retv, sysret, clen;
	struct addrinfo *addrs, *adr, hints;

	retv = 0;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	sysret = getaddrinfo(opt->server, opt->port, &hints, &addrs);
	if (unlikely(sysret != 0)) {
		fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(sysret));
		return sysret;
	}
	for (adr = addrs; adr != NULL; adr = adr->ai_next) {
		sysret = connect(sock, adr->ai_addr, adr->ai_addrlen);
		if (sysret != -1)
			break;
	}
	freeaddrinfo(addrs);
	if (adr == NULL) {
		fprintf(stderr, "all binds failed: %s\n", strerror(errno));
		return errno;
	}
	do {
		sysret = readline(xbuf, sizeof(xbuf));
		if (sysret == 2 && xbuf[0] == '\n') {
			strcpy(xbuf, end_mark);
			sysret = strlen(end_mark) + 1;
		}
		clen = sysret < 64? 64 : sysret;
		clen = clen > 256? 256 : clen;
		clen = clen + 4 - (clen & 3);
		sysret = send(sock, xbuf, clen, 0);
		if (unlikely(sysret == -1)) {
			fprintf(stderr, "send failed: %s\n", strerror(errno));
			break;
		}
		if (strcmp(xbuf, end_mark) == 0)
			break;
	} while (global_exit == 0);

	return retv;
}

int main(int argc, char *argv[])
{
	int retv, sock, sysret;
	struct cmdopt opt;
	socklen_t solen;
	struct sigaction sact;

	retv = 0;
	parse_option(argc, argv, &opt);

	memset(&sact, 0, sizeof(sact));
	sact.sa_handler = sig_handler;
	if (sigaction(SIGINT, &sact, NULL) == -1 ||
			sigaction(SIGTERM, &sact, NULL) == -1)
		fprintf(stderr, "Unable to install signal handler: %s\n",
				strerror(errno));

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (unlikely(sock == -1)) {
		fprintf(stderr, "Cannot create socket: %s\n", strerror(errno));
		return errno;
	}
	if (opt.ifname) {
		solen = strlen(opt.ifname) + 1;
		sysret = setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
				opt.ifname, solen);
		if (unlikely(sysret == -1)) {
			fprintf(stderr, "Cannot bind to device %s: %s\n",
					opt.ifname, strerror(errno));
			retv = errno;
			goto exit_10;
		} else
			printf("Successfully bind to %s\n", opt.ifname);
	}
	if (opt.server)
		retv = do_client(sock, &opt);
	else
		retv = do_server(sock, &opt);

exit_10:
	close(sock);
	return retv;
}

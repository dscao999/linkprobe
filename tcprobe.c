#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <stdlib.h>
#include <poll.h>
#include <time.h>
#include <assert.h>
#include "list_head.h"

#define unlikely(x)	__builtin_expect(!!(x), 0)

const char port[] = "34231";

static volatile int global_exit;
static volatile int finish_up = 0;

static void sig_handler(int sig)
{
	if (sig == SIGINT || sig == SIGTERM)
		global_exit = 1;
	if (sig == SIGALRM)
		finish_up = 1;
}

static struct list_head ths = LIST_HEAD_INIT(ths);

struct thread_arg {
	pthread_t thid;
	struct list_head lnk;
	volatile int running;
	volatile int *stop;
	int sock;
};
static const int buflen = 65536;

static inline unsigned long tm_elapsed(const struct timespec *t0, const struct timespec *t1)
{
	unsigned long elapsed;
	long nsec;

	elapsed = t1->tv_sec - t0->tv_sec;
	nsec = t1->tv_nsec - t0->tv_nsec;
	if (nsec < 0) {
		elapsed -= 1;
		nsec += 1000000000l;
	}
	return (elapsed*1000000ul + nsec / 1000);
}

static void *recv_horse(void *arg)
{
	struct thread_arg *tharg = arg;
	struct pollfd pfd;
	int sysret, retv = 0;
	char *buf;
	unsigned long sumbytes = 0;
	int sock = tharg->sock, len;
	struct timespec tm0, tm1;
	long pkts;

	tharg->running = 1;
	printf("Begin receiving...\n");
	buf = malloc(buflen);
	if (unlikely(!buf)) {
		fprintf(stderr, "Out of Memory!\n");
		tharg->running = 0;
		return NULL;
	}
	pfd.fd = sock;
	pfd.revents = 0;
	pfd.events = POLLIN;
	pkts = 0;
	sysret = poll(&pfd, 1, 5000);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "poll failed: %s\n", strerror(errno));
		retv = errno;
		goto exit_10;
	} else if (unlikely(sysret == 0)) {
		fprintf(stderr, "timeout waiting for client packets\n");
		retv = 255;
		goto exit_10;
	}
	if (unlikely((pfd.revents & POLLIN) == 0)) {
		fprintf(stderr, "Link error!\n");
		retv = 250;
		goto exit_10;
	}
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm0);
	sysret = recv(sock, buf, buflen, 0);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "recv failed: %s\n", strerror(errno));
		retv = errno;
		goto exit_10;
	}
	pkts += 1;
	sumbytes += sysret;
	do {
		pfd.revents = 0;
		sysret = poll(&pfd, 1, 250);
		if (unlikely(sysret == -1)) {
			fprintf(stderr, "poll failed: %s\n", strerror(errno));
			retv = errno;
			goto exit_10;
		} else if (unlikely(sysret == 0)) {
			fprintf(stderr, "Timeout! Test Ends\n");
			break;
		}
		if ((pfd.revents & POLLIN) == 0) {
			fprintf(stderr, "TCP link error.\n");
			retv = 254;
			goto exit_10;
		}
		sysret = recv(sock, buf, buflen, 0);
		if (unlikely(sysret == -1)) {
			fprintf(stderr, "recv failed: %s\n", strerror(errno));
			retv = errno;
			goto exit_10;
		}
		pkts += 1;
		sumbytes += sysret;
	} while (*tharg->stop == 0);
	clock_gettime(CLOCK_MONOTONIC_COARSE, &tm1);
	if (retv)
		goto exit_10;
	len = sprintf(buf, "%lu %lu", sumbytes, tm_elapsed(&tm0, &tm1));
	sysret = send(sock, buf, len+1, 0);
	if (unlikely(sysret == -1))
		fprintf(stderr, "send failed: %s\n", strerror(errno));
	printf("Total %lu packets received\n", pkts);

exit_10:
	tharg->running = 0;
	return NULL;
}

static int do_server(int sock);
static int do_client(int sock, int interval);

static int do_client(int sock, int interval)
{
	char *buf;
	int retv = 0, sysret;
	timer_t timerid;
	struct sigevent sevent;
	struct itimerspec itm;
	unsigned long seq, numbytes, etm;

	buf = malloc(buflen);
	if (unlikely(!buf)) {
		fprintf(stderr, "Out of memory!\n");
		return ENOMEM;
	}
	memset(&sevent, 0, sizeof(sevent));
	sevent.sigev_notify = SIGEV_SIGNAL;
	sevent.sigev_signo = SIGALRM;
	sysret = timer_create(CLOCK_MONOTONIC, &sevent, &timerid);
	if (unlikely(sysret == -1)) {
		retv = errno;
		fprintf(stderr, "timer_create failed: %s\n", strerror(errno));
		goto exit_10;
	}

	finish_up = 0;
	seq = 0;
	memset(&itm, 0, sizeof(itm));
	itm.it_value.tv_sec = interval;
	sysret = timer_settime(timerid, 0, &itm, NULL);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "timer_settime failed: %sn\n", strerror(errno));
		retv = errno;
		goto exit_20;
	}
	do {
		*((unsigned long *)buf) = seq++;
		sysret = send(sock, buf, buflen, 0);
		if (unlikely(sysret == -1)) {
			fprintf(stderr, "send failed: %s\n", strerror(errno));
			retv = errno;
			goto exit_20;
		}
	} while (global_exit == 0 && finish_up == 0);
	double ratio;
	sysret = recv(sock, buf, buflen, 0);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "recv failed: %s\n", strerror(errno));
	} else {
		printf("Total %lu packets sent\n", seq+1);
		sscanf(buf, "%lu %lu", &numbytes, &etm);
		ratio = ((double)numbytes)/(((double)etm)/1000000);
		printf("Bytes: %lu, Time: %lu\n", numbytes, etm/1000000);
		printf("Bandwidth: %18.2f bytes/s\n", ratio);
	}

exit_20:
	timer_delete(timerid);
exit_10:
	free(buf);
	return retv;
}

static int do_server(int sock)
{
	int retv = 0, csock, sysret;
	struct sockaddr_in peer;
	socklen_t peerlen;
	struct thread_arg *tharg, *tmpn;

	sysret = listen(sock, 10);
	if (unlikely(sysret == -1)) {
		fprintf(stderr, "listen failed: %s\n", strerror(errno));
		return errno;
	}
	do {
		list_for_each_entry_safe(tharg, tmpn, &ths, lnk) {
			if (tharg->running == 0) {
				pthread_join(tharg->thid, NULL);
				list_del(&tharg->lnk, &ths);
				close(tharg->sock);
				free(tharg);
			}
		}
		peerlen = sizeof(peer);
		csock = accept(sock, (struct sockaddr *)&peer, &peerlen);
		if (unlikely(csock == -1)) {
			if (errno != EINTR) {
				fprintf(stderr, "accept failed: %s\n", strerror(errno));
				retv = errno;
				break;
			}
			continue;
		}
		tharg = malloc(sizeof(struct thread_arg));
		if (unlikely(!tharg)) {
			close(csock);
			fprintf(stderr, "Out of Memory");
			retv = ENOMEM;
			break;
		}
		tharg->running = -1;
		tharg->stop = &global_exit;
		tharg->sock = csock;
		sysret = pthread_create(&tharg->thid, NULL, recv_horse, tharg);
		if (unlikely(sysret != 0)) {
			fprintf(stderr, "pthread_create failed: %s\n", strerror(sysret));
			free(tharg);
			close(csock);
			break;
		}
		list_add(&tharg->lnk, &ths);
	} while (global_exit == 0);
	list_for_each_entry_safe(tharg, tmpn, &ths, lnk) {
		if (tharg->running == 0) {
			pthread_join(tharg->thid, NULL);
			close(tharg->sock);
			list_del(&tharg->lnk, &ths);
			free(tharg);
		}
	}
	return retv;
}

int main(int argc, char *argv[])
{
	const char *svrip;
	int sock, sysret, retv = 0;
	int server = 0;
	struct addrinfo hints, *res;
	struct sigaction act;
	int c, fin, interval;
	extern int optind, opterr, optopt;

	interval = 0;
	fin = 0;
	do {
		c = getopt(argc, argv, ":t:");
		switch(c) {
			case ':':
				fprintf(stderr, "Missing argument for '%c'\n", (char)optopt);
				break;
			case '?':
				fprintf(stderr, "Unknown option '%c'\n", (char)optopt);
				break;
			case -1:
				fin = 1;
				break;
			case 't':
				interval = atoi(optarg);
				break;
			default:
				assert(0);
		}
	} while (fin == 0);
	if (interval == 0)
		interval = 60;

	if (optind == argc) {
		server = 1;
		printf("Listening for connections...\n");
	} else {
		server = 0;
		svrip = argv[optind];
	}

	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_handler;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGALRM, &act, NULL);

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (unlikely(sock == -1)) {
		fprintf(stderr, "socket creation failed: %s\n", strerror(errno));
		return 5;
	}
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (server) {
		hints.ai_flags = AI_PASSIVE|AI_NUMERICSERV;
		sysret = getaddrinfo(NULL, port, &hints, &res);
		if (unlikely(sysret)) {
			fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(sysret));
			retv = sysret;
			goto exit_10;
		}
		sysret = bind(sock, res->ai_addr, res->ai_addrlen);
		if (unlikely(sysret == -1)) {
			fprintf(stderr, "bind failed: %s\n", strerror(errno));
			retv = errno;
			goto exit_20;
		}
		retv = do_server(sock);
	} else {
		sysret = getaddrinfo(svrip, port, &hints, &res);
		if (unlikely(sysret)) {
			fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(sysret));
			retv = sysret;
			goto exit_10;
		}
		sysret = connect(sock, res->ai_addr, res->ai_addrlen);
		if (unlikely(sysret == -1)) {
			fprintf(stderr, "connect failed: %s\n", strerror(errno));
			retv = errno;
			goto exit_20;
		}
		retv = do_client(sock, interval);
	}

exit_20:
	freeaddrinfo(res);
exit_10:
	close(sock);
	return retv;
}

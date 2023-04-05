#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "pktgen.h"

#define unlikely(x)	__builtin_expect(!!(x), 0)
#define syscall_log(syscall)	\
	fprintf(stderr, "%s failed: %s. At line %d file %s, in function: %s\n",\
			#syscall, strerror(errno),	\
			__LINE__, __FILE__, __func__);

static const char PKTGEN_BASEDIR[] = "/proc/net/pktgen";
static const char PKTGEN_THREAD[] = "/proc/net/pktgen/kpktgen_";
static const char PKTGEN_CTRL[] = "/proc/net/pktgen/pgctrl";
static const char CPUINFO[] = "/proc/cpuinfo";

static const char *ctrl_cmd[] = {
	"start", "stop", "reset", NULL
};

static int sendcmd(const char *fname, const char *cmd, const char *arg)
{
	FILE *fout;
	int retv, len, numbytes;
	char *buf;

	len = strlen(cmd) + 1;
	if (arg)
		len += strlen(arg) + 1;
	len = (len + 7) & 0xffff8;
	buf = malloc(len);
	if (unlikely(buf == NULL)) {
		fprintf(stderr, "Out of Memory\n");
		return -ENOMEM;
	}
	fout = fopen(fname, "w");
	if (unlikely(fout == NULL)) {
		syscall_log(fopen);
		return -errno;
	}
	if (arg)
		len = sprintf(buf, "%s %s\n", cmd, arg);
	else
		len = sprintf(buf, "%s\n", cmd);
	numbytes = fwrite(buf, 1, len, fout);
	retv = fclose(fout);
	if (unlikely(numbytes < len || retv != 0)) {
		buf[len-1] = 0;
		fprintf(stderr, "Command %s failed\n", buf);
		retv = -255;
	}
	free(buf);
	return retv;
}

int pktgen_control(const char *cmd)
{
	const char **cmdary;
	int retv;

	for (cmdary = ctrl_cmd; *cmdary; cmdary++) {
		if (strcmp(*cmdary, cmd) == 0)
			break;
	}
	if (*cmdary == NULL) {
		fprintf(stderr, "Invalid command: %s\n", cmd);
		return -255;
	}
	retv = sendcmd(PKTGEN_CTRL, cmd, NULL);
	return retv;
}

static const char *nic_cmds[] = {
	"count", "src_min", "src_max", "dst_min", "dst_max",
	"src_mac", "dst_mac", "clear_counters",
	"udp_src_min", "udp_src_max", "udp_dst_min", "udp_dst_max",
	"pkt_size", NULL
};

enum NICMD {COUNT = 0, SRCMIN = 1, SRCMAX = 2, DSTMIN = 3, DSTMAX = 4,
	SRCMAC = 5, DSTMAC = 6, CLEAR_COUNTERS = 7,
	UDP_SRCMIN = 8, UDP_SRCMAX = 9, UDP_DSTMIN = 10, UDP_DSTMAX = 11,
	PKTSIZE = 12, INVCMD = 13
};

int nic_control(const char *nic, const char *cmd, const char *arg)
{
	const char **cmdary;
	int retv;
	char ctrl_file[128];

	for (cmdary = nic_cmds; *cmdary; cmdary++) {
		if (strcmp(cmd, *cmdary) == 0) {
			break;
		}
	}
	if (*cmdary == NULL) {
		fprintf(stderr, "No such command: %s\n", cmd);
		return -255;
	}
	sprintf(ctrl_file, "%s/%s", PKTGEN_BASEDIR, nic);
	retv = sendcmd(ctrl_file, cmd, arg);
	return retv;
}

static const char *thread_cmd[] = {
	"add_device", "remove_device_all", NULL
};

int pktgen_thread(const char *cmd, const char *device, int thnum)
{
	const char **cmdary;
	char cmdfile[128];
	int retv;

	for (cmdary = thread_cmd; *cmdary; cmdary++) {
		if (strcmp(*cmdary, cmd) == 0)
			break;
	}
	if (*cmdary == NULL) {
		fprintf(stderr, "Invalid command: %s\n", cmd);
		return -255;
	}
	sprintf(cmdfile, "%s%d", PKTGEN_THREAD, thnum);
	retv = sendcmd(cmdfile, cmd, device);
	return retv;
}

int num_cpus(void)
{
	FILE *fin;
	int numbytes, numcpus;
	char *line;
	size_t len;

	fin = fopen(CPUINFO, "rb");
	if (unlikely(!fin)) {
		syscall_log(fopen);
		return -errno;
	}
	line = NULL;
	len = 0;
	numcpus = 0;
	while (!feof(fin)) {
		numbytes = getline(&line, &len, fin);
		if (unlikely(numbytes == -1)) {
			syscall_log(getline);
			break;
		}
		if (strstr(line, "processor") == line)
			numcpus += 1;
	}
	free(line);
	fclose(fin);
	return numcpus;
}

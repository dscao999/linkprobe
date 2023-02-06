#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "enumnet.h"

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

static int get_netindex(const char *ifname)
{
	FILE *fin;
	int num, idx;
	char ifbuf[8];

	fin = fopen(ifname, "rb");
	if (unlikely(!fin)) {
		fprintf(stderr, "Cannot open '%s': %s\n", ifname,
				strerror(errno));
		return -1;
	}
	idx = 0;
	num = fread(ifbuf, 1, sizeof(ifbuf), fin);
	if (num > 0)
		idx = atoi(ifbuf);
	fclose(fin);
	return idx;
}

int mac2bin(const char *mac, unsigned char *buf, int len)
{
	int pos, maclen;
	char *macbuf, *rc;

	pos = 0;
	if (mac == NULL || strlen(mac) == 0 || strchr(mac, ':') == NULL ||
			strlen(mac) > len*3 - 1)
		return pos;
	maclen = strlen(mac) + 1;
	macbuf = malloc(maclen);
	if (unlikely(macbuf == NULL)) {
		fprintf(stderr, "Out of Memory\n");
		return pos;
	}
	strcpy(macbuf, mac);
	rc = strtok(macbuf, ":");
	while (rc != NULL && pos < len) {
		buf[pos++] = strtol(rc, NULL, 16);
		rc = strtok(NULL, ":");
	}
	free(macbuf);
	return pos;
}

static int get_macaddr(const char *ifname, unsigned char *macbuf, int maclen)
{
	FILE *fin;
	char buf[32];
	int num, pos;

	fin = fopen(ifname, "rb");
	if (unlikely(!fin)) {
		fprintf(stderr, "Cannot open '%s': %s\n", ifname,
				strerror(errno));
		return -1;
	}
	num = fread(buf, 1, sizeof(buf), fin);
	fclose(fin);
	if (num == 0)
		return num;
	pos = mac2bin(buf, macbuf, maclen);
	return pos;
}

int enumerate_cards(struct list_head *ifhead)
{
	static const char netdir[] = "/sys/class/net";
	char netface[256];
	DIR *odir;
	struct dirent *dentry;
	int numc = 0, len, sysret;
	struct netcard *ncard;

	odir = opendir(netdir);
	if (unlikely(odir == NULL)) {
		fprintf(stderr, "Cannot open dir '%s': %s\n", netdir,
				strerror(errno));
		return numc;
	}
	errno = 0;
	dentry = readdir(odir);
	while (dentry != NULL) {
		if (unlikely(strlen(dentry->d_name) + 1 > MAX_IFACE_NAME)) {
			fprintf(stderr, "ifname '%s' too long. Ignored!\n",
					dentry->d_name);
			goto next_entry;
		}
		if (dentry->d_type != DT_LNK)
			goto next_entry;
		ncard = malloc(sizeof(struct netcard));
		if (unlikely(ncard == 0)) {
			fprintf(stderr, "Fatal Error. Out of Memory!");
			exit(ENOMEM);
		}
		strcpy(ncard->ifname, dentry->d_name);
		strcpy(netface, netdir);
		len = strlen(netface);
		netface[len] = '/';
		strcpy(netface+len+1, ncard->ifname);
		strcat(netface, "/ifindex");
		ncard->ifindex = get_netindex(netface);
		if (ncard->ifindex <= 0) {
			free(ncard);
			goto next_entry;
		}
		strcpy(netface, netdir);
		len = strlen(netface);
		netface[len] = '/';
		strcpy(netface+len+1, ncard->ifname);
		strcat(netface, "/address");
		sysret = get_macaddr(netface, ncard->macaddr,
				sizeof(ncard->macaddr));
		if (sysret <= 0)
			free(ncard);
		else {
			numc += 1;
			ncard->maclen = sysret;
			list_add(&ncard->lnk, ifhead);
		}
next_entry:
		errno = 0;
		dentry = readdir(odir);
	}
	if (unlikely(errno != 0))
		fprintf(stderr, "Read dir '%s' failed: %s\n", netdir,
				strerror(errno));
	closedir(odir);
	return numc;
}

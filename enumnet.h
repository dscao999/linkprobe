#ifndef ENUMNET_DSCAO__
#define ENUMNET_DSCAO__
#include "list_head.h"

#define MAX_IFACE_NAME	24

struct netcard {
	struct list_head lnk;
	int ifindex;
	char ifname[MAX_IFACE_NAME];
	unsigned char maclen;
	char macaddr[16];
};

int mac2bin(const char *mac, char *buf, int len);
int enumerate_cards(struct list_head *ifhead);

static const char default_port[] = "12765";
#endif  /* ENUMNET_DSCAO__ */

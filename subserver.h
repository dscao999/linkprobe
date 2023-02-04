#ifndef SUBSERVER_DSCAO__
#define SUBSERVER_DSCAO__

#include <sys/types.h>
#include "list_head.h"
struct sub_server {
	pid_t pid;
	struct sockaddr addr;
	socklen_t solen;
	int sock;
	struct list_head lnk;
	struct list_head *ifhead;
};

int subserver(const struct sub_server *sv);

#endif  /* SUBSERVER_DSCAO__ */

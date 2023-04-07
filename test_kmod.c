#include <stdio.h>
#include "pktgen.h"

int main(int argc, char *argv[])
{
	int retv;
	char aws;

	retv = check_pktgen();
	if (retv) {
		fprintf(stderr, "Missing kernel module pktgen!\n");
		return 1;
	}
	retv = pktgen_control("reset");
	if (retv < 0)
		return -retv;
	printf("Please check the pktgen module. Press return when finished: ");
	fflush(stdout);
	scanf("%c", &aws);
	exit_pktgen();
	return retv;
}

#ifndef PKTGEN_H_DSCAO__
#define PKTGEN_H_DSCAO__

int check_pktgen(void);
void exit_pktgen(void);
int pktgen_control(const char *cmd);
int num_cpus(void);
#endif  /* PKTGEN_H_DSCAO__ */

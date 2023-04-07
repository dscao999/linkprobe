#ifndef KMOD_DSCAO__
#define KMOD_DSCAO__
int search_token(int fd, const char *token, int FS);
int lsmod(const char *mod_name);
int rmmod(const char *mod_name);
int insmod(const char *mod_name);
#endif  /* KMOD_DSCAO__ */

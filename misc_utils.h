#ifndef MISC_UTILS_DSCAO__
#define MISC_UTILS_DSCAO__

#define unlikely(x)	__builtin_expect(!!(x), 0)
#define likely(x)	__builtin_expect(!!(x), 1)

#define syscall_log(syscall)	\
	fprintf(stderr, "Line: %d File: %s in function '%s', %s failed: %s\n", \
			__LINE__, __FILE__, __func__, #syscall, strerror(errno))

#define nomem_log	\
	fprintf(stderr, "Out of Memory! Line: %d File: %s Function: '%s'\n", \
			__LINE__, __FILE__, __func__)

#endif  /* MISC_UTILS_DSCAO__ */

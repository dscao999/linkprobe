#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <sys/wait.h>
#include <assert.h>
#include <stdlib.h>

#define unlikely(x)	__builtin_expect(!!(x), 0)

static inline void __attribute__((always_inline))
elog(int line, const char *file, const char *func, const char *syscall)
{
	fprintf(stderr, "Line %d File %s in function %s, %s failed: %s\n",
			line, file, func, syscall, strerror(errno));
}

int search_token(int fd, const char *token, int FS)
{
	int sysret, retv, buflen, bitpos, offset;
	int fin;
	char *buf, *ln, *nxtbuf;

	fin = 0;
	retv = 0;
	bitpos = 4;
	buflen = (1 << bitpos);
	buf = malloc(buflen+1);
	if (unlikely(buf == NULL)) {
		fprintf(stderr, "Out of Memory!\n");
		return -ENOMEM;
	}
	offset = 0;
	do {
		do {
			sysret = read(fd, buf+offset, buflen - offset);
			if (unlikely(sysret == -1)) {
				retv = -errno;
				elog(__LINE__, __FILE__, __func__, "read");
				goto exit_10;
			} else if (unlikely(sysret == 0))
				break;
			offset += sysret;
			buf[offset] = 0;
			ln = strrchr(buf, FS);
		} while (ln == NULL && offset < buflen && sysret > 0);
		if (strstr(buf, token)) {
			retv = 1;
			break;
		}
		if (sysret <= 0)
			break;
		if (ln == NULL) {
			bitpos += 1;
			buflen = (1 << bitpos);
			nxtbuf = malloc(buflen+1);
			if (unlikely(nxtbuf == NULL)) {
				fprintf(stderr, "Out of Memory!\n");
				retv = -ENOMEM;
				goto exit_10;
			}
			memcpy(nxtbuf, buf, offset);
			free(buf);
			buf = nxtbuf;
		} else {
			offset -= (ln - buf + 1);
			if (offset > 0)
				memcpy(buf, ln+1, offset);
		}
	} while(1);

exit_10:
	free(buf);
	return retv;
}

int lsmod(const char *mod_name)
{
	int sysret, retv, offset;
	int pipd[2], rd, wrt;
	char *ln;

	retv = 0;
	sysret = pipe(pipd);
	if (unlikely(sysret == -1)) {
		elog(__LINE__, __FILE__, __func__, "pipe");
		return -errno;
	}
	rd = pipd[0];
	wrt = pipd[1];
	sysret = fork();
	if (unlikely(sysret == -1)) {
		elog(__LINE__, __FILE__, __func__, "fork");
		retv = -errno;
		goto exit_10;
	}
	if (sysret == 0) {
		fflush(NULL);
		close(rd);
		fclose(stdout);
		stdout = fdopen(dup(wrt), "w");
		fclose(stderr);
		stderr = fdopen(dup(wrt), "w");
		close(wrt);
		fclose(stdin);
		sysret = execlp("lsmod", "lsmod", NULL);
		if (unlikely(sysret == -1)) {
			fprintf(stderr, "execlp failed: %s\n", strerror(errno));
			return -errno;
		}
	} else {
		int cid, status;

		close(wrt);
		cid = sysret;
		close(wrt);
		retv = search_token(rd, mod_name, '\n');
		close(rd);
		sysret = waitpid(cid, &status, 0);
	}

exit_10:
	close(pipd[0]);
	close(pipd[1]);
	return retv;
}

int main(int argc, char *argv[])
{
	int retv;

	retv = lsmod("pktgen");
	if (retv == 1)
		printf("pktgen installed\n");
	else if (retv == 0)
		printf("pktgen not installed\n");
	return 0;
}

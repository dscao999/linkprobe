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

#define syscall_log(syscall)	\
	fprintf(stderr, "Line: %d File: %s in function '%s', %s failed: %s\n", \
			__LINE__, __FILE__, __func__, #syscall, strerror(errno))

#define nomem_log	\
	fprintf(stderr, "Out of Memory! Line: %d File: %s Function: '%s'\n", \
			__LINE__, __FILE__, __func__)

int search_token(int fd, const char *token, int FS)
{
	int sysret, retv, buflen, bitpos, offset;
	char *buf, *ln, *nxtbuf;

	retv = 0;
	bitpos = 6;
	buflen = (1 << bitpos);
	buf = malloc(buflen+1);
	if (unlikely(buf == NULL)) {
		nomem_log;
		return -ENOMEM;
	}
	offset = 0;
	do {
		do {
			sysret = read(fd, buf+offset, buflen - offset);
			if (unlikely(sysret == -1)) {
				retv = -errno;
				syscall_log(read);
				goto exit_10;
			} else if (unlikely(sysret == 0))
				break;
			offset += sysret;
			buf[offset] = 0;
			ln = strrchr(buf, FS);
		} while (ln == NULL && offset < buflen);
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
				nomem_log;
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
	int sysret, retv, cid, status;
	int pipd[2], rd, wrt;

	retv = 0;
	sysret = pipe(pipd);
	if (unlikely(sysret == -1)) {
		syscall_log(pipe);
		return -errno;
	}
	rd = pipd[0];
	wrt = pipd[1];
	sysret = fork();
	if (unlikely(sysret == -1)) {
		syscall_log(fork);
		retv = -errno;
		goto exit_10;
	}
	if (sysret == 0) {
		close(rd);
		fclose(stdout);
		stdout = fdopen(dup(wrt), "w");
		fclose(stderr);
		stderr = fdopen(dup(wrt), "w");
		fclose(stdin);
		sysret = execlp("lsmod", "lsmod", NULL);
		if (unlikely(sysret == -1)) {
			syscall_log(execlp);
			return errno;
		}
	}

	close(wrt);
	cid = sysret;
	close(wrt);
	retv = search_token(rd, mod_name, '\n');
	close(rd);
	sysret = waitpid(cid, &status, 0);
	if (unlikely(sysret == -1))
		syscall_log(waitpid);

exit_10:
	close(pipd[0]);
	close(pipd[1]);
	return retv;
}

int insmod(const char *mod_name)
{
	int retv, sysret, status;

	retv = 0;
	sysret = fork();
	if (unlikely(sysret == -1)) {
		syscall_log(fork);
		return -errno;
	} else if (sysret == 0) {
		fclose(stdin);
		sysret = execlp("modprobe", "modprobe", mod_name, NULL);
		if (unlikely(sysret == -1)) {
			syscall_log(execlp);
			exit(errno);
		}
	}
	status = 0;
	sysret = waitpid(sysret, &status, 0);
	if (unlikely(sysret == -1)) {
		syscall_log(waitpid);
		return -errno;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		retv = -1;
	return retv;
}

int check_pktgen(void)
{
	int retv;

	retv = lsmod("pktgen");
	if (retv == 1)
		return 0;
	else if (retv == 0)
		retv = insmod("pktgen");
	if (retv)
		fprintf(stderr, "No pktgen module\n");
	return retv;
}

int main(int argc, char *argv[])
{
	int retv;

	retv = check_pktgen();
	if (retv) {
		fprintf(stderr, "Missing kernel module pktgen!\n");
		return 1;
	}
	return 0;
}

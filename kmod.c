#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "misc_utils.h"
#include "kmod.h"

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
		fflush(NULL);
		close(fileno(stdout));
		dup(wrt);
		close(fileno(stderr));
		dup(wrt);
		close(wrt);
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

int rmmod(const char *mod_name)
{
	int retv, sysret, status;

	retv = 0;
	sysret = fork();
	if (unlikely(sysret == -1)) {
		syscall_log(fork);
		return -errno;
	} else if (sysret == 0) {
		fclose(stdin);
		sysret = execlp("rmmod", "rmmod", mod_name, NULL);
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

/*	$OpenBSD$	*/

/*
 * Copyright (c) 2024 Gilles Chehade <gilles@poolp.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/tree.h>
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <imsg.h>
#include <event.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "cron.h"
#include "dict.h"
#include "ioev.h"
#include "mproc.h"
#include "log.h"

#define	CRON_MAXARG	32

static int	imsg_wait(struct imsgbuf *ibuf, struct imsg *imsg, int timeout);

struct mproc *
start_child(int save_argc, char **save_argv, char *rexec)
{
	struct mproc *p;
	char *argv[CRON_MAXARG];
	int sp[2], argc = 0;
	pid_t pid;

	if (save_argc >= CRON_MAXARG - 2)
		fatalx("too many arguments");

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, sp) == -1)
		fatal("socketpair");

	io_set_nonblocking(sp[0]);
	io_set_nonblocking(sp[1]);

	switch (pid = fork()) {
	case -1:
		fatal("%s: fork", save_argv[0]);
	case 0:
		break;
	default:
		close(sp[0]);
		p = calloc(1, sizeof(*p));
		if (p == NULL)
			fatal("calloc");
		if((p->name = strdup(rexec)) == NULL)
			fatal("strdup");
		mproc_init(p, sp[1]);
		p->pid = pid;
		p->handler = parent_imsg;
		return p;
	}

	if (sp[0] != 3) {
		if (dup2(sp[0], 3) == -1)
			fatal("%s: dup2", rexec);
	} else if (fcntl(sp[0], F_SETFD, 0) == -1)
		fatal("%s: fcntl", rexec);

	if (closefrom(4) == -1)
		fatal("%s: closefrom", rexec);

	for (argc = 0; argc < save_argc; argc++)
		argv[argc] = save_argv[argc];
	argv[argc++] = "-x";
	argv[argc++] = rexec;
	argv[argc++] = NULL;

	execvp(argv[0], argv);
	fatal("%s: execvp", rexec);
}

void
setup_peers(struct mproc *a, struct mproc *b)
{
	int sp[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, sp) == -1)
		fatal("socketpair");

	io_set_nonblocking(sp[0]);
	io_set_nonblocking(sp[1]);

	if (imsg_compose(&a->imsgbuf, IMSG_SETUP_PEER, b->proc, b->pid, sp[0],
	    NULL, 0) == -1)
		fatal("imsg_compose");
	if (imsg_flush(&a->imsgbuf) == -1)
		fatal("imsg_flush");

	if (imsg_compose(&b->imsgbuf, IMSG_SETUP_PEER, a->proc, a->pid, sp[1],
	    NULL, 0) == -1)
		fatal("imsg_compose");
	if (imsg_flush(&b->imsgbuf) == -1)
		fatal("imsg_flush");
}

void
setup_done(struct mproc *p)
{
	struct imsg imsg;

	if (imsg_compose(&p->imsgbuf, IMSG_SETUP_DONE, 0, 0, -1, NULL, 0) == -1)
		fatal("imsg_compose");
	if (imsg_flush(&p->imsgbuf) == -1)
		fatal("imsg_flush");

	if (imsg_wait(&p->imsgbuf, &imsg, 10000) == -1)
		fatal("imsg_wait");

	if (imsg.hdr.type != IMSG_SETUP_DONE)
		fatalx("expect IMSG_SETUP_DONE");

	log_debug("setup_done: %s[%d] done", p->name, p->pid);

	imsg_free(&imsg);
}


void
setup_proc(void)
{
	struct imsgbuf *ibuf;
	struct imsg imsg;
        int setup = 1;

	log_procinit(proc_title(cron_process));

	p_parent = calloc(1, sizeof(*p_parent));
	if (p_parent == NULL)
		fatal("calloc");
	if((p_parent->name = strdup("parent")) == NULL)
		fatal("strdup");
	p_parent->proc = PROC_PARENT;
	p_parent->handler = imsg_dispatch;
	mproc_init(p_parent, 3);

	ibuf = &p_parent->imsgbuf;

	while (setup) {
		if (imsg_wait(ibuf, &imsg, 10000) == -1)
			fatal("imsg_wait");

		switch (imsg.hdr.type) {
		case IMSG_SETUP_PEER:
			setup_peer(imsg.hdr.peerid, imsg.hdr.pid,
			    imsg_get_fd(&imsg));
			break;
		case IMSG_SETUP_DONE:
			setup = 0;
			break;
		default:
			fatal("bad imsg %d", imsg.hdr.type);
		}
		imsg_free(&imsg);
	}

	if (imsg_compose(ibuf, IMSG_SETUP_DONE, 0, 0, -1, NULL, 0) == -1)
		fatal("imsg_compose");

	if (imsg_flush(ibuf) == -1)
		fatal("imsg_flush");

	log_debug("setup_proc: %s done", proc_title(cron_process));
}

struct mproc *
setup_peer(enum cron_proc_type proc, pid_t pid, int sock)
{
	struct mproc *p, **pp;

	log_debug("setup_peer: %s -> %s[%u] fd=%d", proc_title(cron_process),
	    proc_title(proc), pid, sock);

	if (sock == -1)
		fatalx("peer socket not received");

	switch (proc) {
	case PROC_CONTROL:
		pp = &p_control;
		break;
	case PROC_SCHEDULER:
		pp = &p_scheduler;
		break;
	case PROC_PLANNER:
		pp = &p_planner;
		break;
	default:
		fatalx("unknown peer");
	}

	if (*pp)
		fatalx("peer already set");

	p = calloc(1, sizeof(*p));
	if (p == NULL)
		fatal("calloc");
	if((p->name = strdup(proc_title(proc))) == NULL)
		fatal("strdup");
	mproc_init(p, sock);
	p->pid = pid;
	p->proc = proc;
	p->handler = imsg_dispatch;

	*pp = p;

	return p;
}

static int
imsg_wait(struct imsgbuf *ibuf, struct imsg *imsg, int timeout)
{
	struct pollfd pfd[1];
	ssize_t n;

	pfd[0].fd = ibuf->fd;
	pfd[0].events = POLLIN;

	while (1) {
		if ((n = imsg_get(ibuf, imsg)) == -1)
			return -1;
		if (n)
			return 1;

		n = poll(pfd, 1, timeout);
		if (n == -1)
			return -1;
		if (n == 0) {
			errno = ETIMEDOUT;
			return -1;
		}

		if (((n = imsg_read(ibuf)) == -1 && errno != EAGAIN) || n == 0)
			return -1;
	}
}

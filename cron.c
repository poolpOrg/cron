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
#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "cron.h"
#include "mproc.h"
#include "log.h"

extern char *__progname;
enum cron_proc_type cron_process;

int	tracing = 0;

struct mproc	*p_parent = NULL;
struct mproc	*p_control = NULL;
struct mproc	*p_scheduler = NULL;
struct mproc	*p_planner = NULL;

void		(*imsg_callback)(struct mproc *, struct imsg *);

static void	usage(void);
static int	opt_foreground;
static int	opt_foreground_log;

int	parent(void);
int	parser(void);
int	scheduler(void);

static void
usage(void)
{

	fprintf(stderr, "usage: %s [-dnv] [-l load_avg]\n", __progname);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	int	c;
	int	save_argc = argc;
	char	**save_argv = argv;
	char	*rexec = NULL;
	
	log_init(1, LOG_CRON);

	while ((c = getopt(argc, argv, "dnvx:FT:")) != -1) {
		switch (c) {
		case 'd':
		case 'n':
			opt_foreground = 1;
			opt_foreground_log = 1;
			break;
			
		case 'v':
			tracing |= TRACE_DEBUG;
			break;

		case 'x':
			rexec = optarg;
			break;

		case 'F':
			opt_foreground = 1;
			break;

		case 'T':
			if (!strcmp(optarg, "scheduler"))
				tracing |= TRACE_SCHEDULER;
			break;

		default:
			usage();
		}
	}

	argv += optind;
	argc -= optind;

	if (geteuid())
		fatalx("need root privileges");

	log_init(opt_foreground_log, LOG_CRON);

	if (rexec == NULL) {
		cron_process = PROC_PARENT;

		log_info("info: cron starting");

		if (!opt_foreground)
			if (daemon(0, 0) == -1)
				fatal("failed to daemonize");

		/* setup all processes */
		p_scheduler = start_child(save_argc, save_argv, "scheduler");
		p_scheduler->proc = PROC_SCHEDULER;

		p_planner = start_child(save_argc, save_argv, "planner");
		p_planner->proc = PROC_PLANNER;

		setup_peers(p_scheduler, p_planner);

		setup_done(p_scheduler);
		setup_done(p_planner);

		return parent();
	}

	if (!strcmp(rexec, "scheduler")) {
		cron_process = PROC_SCHEDULER;
		setup_proc();

		return scheduler();
	}

	if (!strcmp(rexec, "planner")) {
		cron_process = PROC_PLANNER;
		setup_proc();

		return planner();
	}

	return (0);
	    
}
const char *
proc_title(enum cron_proc_type proc)
{
	switch (proc) {
	case PROC_PARENT:
		return "[priv]";
	case PROC_CONTROL:
		return "control";
	case PROC_SCHEDULER:
		return "scheduler";
	case PROC_PLANNER:
		return "planner";
	case PROC_CLIENT:
		return "client";
	}
	return "unknown";
}

const char *
proc_name(enum cron_proc_type proc)
{
	switch (proc) {
	case PROC_PARENT:
		return "parent";
	case PROC_CONTROL:
		return "control";
	case PROC_SCHEDULER:
		return "scheduler";
	case PROC_PLANNER:
		return "planner";
 	case PROC_CLIENT:
		return "client";
	default:
		return "unknown";
	}
}

#define CASE(x) case x : return #x

const char *
imsg_to_str(int type)
{
	static char	 buf[32];

	switch (type) {
	default:
		(void)snprintf(buf, sizeof(buf), "IMSG_??? (%d)", type);

		return buf;
	}
}

void
log_trace0(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vlog(LOG_DEBUG, emsg, ap);
	va_end(ap);
}

void
log_trace_verbose(int v)
{
	tracing = v;

	/* Set debug logging in log.c */
	log_setverbose(v & TRACE_DEBUG ? 2 : opt_foreground_log);
}

void
log_imsg(int to, int from, struct imsg *imsg)
{

	if (to == PROC_CONTROL )
		return;

	log_trace(TRACE_IMSG, "imsg: %s <- %s: %s (len=%zu)",
	    proc_name(to),
	    proc_name(from),
	    imsg_to_str(imsg->hdr.type),
	    imsg->hdr.len - IMSG_HEADER_SIZE);
}

void
imsg_dispatch(struct mproc *p, struct imsg *imsg)
{
	struct timespec	t0, t1, dt;
	int		msg;

	if (imsg == NULL) {
		imsg_callback(p, imsg);
		return;
	}

	log_imsg(cron_process, p->proc, imsg);

	msg = imsg->hdr.type;
	imsg_callback(p, imsg);
}


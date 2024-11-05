/*	$OpenBSD: config.c,v 1.58 2024/01/04 09:30:09 op Exp $	*/

/*
 * Copyright (c) 2008 Pierre-Yves Ritschard <pyr@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/resource.h>
#include <sys/tree.h>

#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cron.h"
#include "dict.h"
#include "mproc.h"
#include "log.h"

void
config_process(enum cron_proc_type proc)
{
	struct rlimit rl;

	cron_process = proc;
	setproctitle("%s", proc_title(proc));

	if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
		fatal("fdlimit: getrlimit");
	rl.rlim_cur = rl.rlim_max;
	if (setrlimit(RLIMIT_NOFILE, &rl) == -1)
		fatal("fdlimit: setrlimit");
}

void
config_peer(enum cron_proc_type proc)
{
	struct mproc	*p;

	if (proc == cron_process)
		fatal("config_peers: cannot peer with oneself");

	if (proc == PROC_CONTROL)
		p = p_control;
	else if (proc == PROC_PARENT)
		p = p_parent;
	else if (proc == PROC_PLANNER)
		p = p_planner;
	else
		fatalx("bad peer");

	mproc_enable(p);
}

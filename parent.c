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
#include <sys/tree.h>
#include <sys/queue.h>

#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "cron.h"
#include "dict.h"
#include "mproc.h"
#include "log.h"


void
parent_imsg(struct mproc *p, struct imsg *imsg)
{
	struct msg		 m;
	const void		*data;
	const char		*username, *password, *cause, *procname;
	uint64_t		 reqid;
	size_t			 sz;
	void			*i;
	int			 fd, n, v, ret;

	if (imsg == NULL)
		fatalx("process %s socket closed", p->name);

	switch (imsg->hdr.type) {
	}

	fatalx("parent_imsg: unexpected %s imsg from %s",
	    imsg_to_str(imsg->hdr.type), proc_title(p->proc));
}

int
parent()
{
	imsg_callback = parent_imsg;

	event_init();

	config_peer(PROC_SCHEDULER);
	config_peer(PROC_PLANNER);
	
	if (pledge("stdio", NULL) == -1)
		fatal("pledge");

	event_dispatch();
	fatalx("exited event loop");
	return (1);
}

	    

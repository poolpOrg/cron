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
#include <sys/stat.h>
#include <sys/tree.h>
#include <sys/queue.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <fts.h>
#include <imsg.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <util.h>

#include "cron.h"
#include "mproc.h"
#include "log.h"


void
task_init(struct task *taskp)
{
	memset(taskp, 0, sizeof *taskp);
	SLIST_INIT(&taskp->minutes);
	SLIST_INIT(&taskp->hours);
	SLIST_INIT(&taskp->days_of_month);
	SLIST_INIT(&taskp->months);
	SLIST_INIT(&taskp->days_of_week);
}

void
task_cleanup(struct task *taskp)
{
	struct time_field_atom	*tfap;

	while (!SLIST_EMPTY(&taskp->minutes)) {
		tfap = SLIST_FIRST(&taskp->minutes);
		SLIST_REMOVE_HEAD(&taskp->minutes, entries);
		free(tfap);
	}

	while (!SLIST_EMPTY(&taskp->hours)) {
		tfap = SLIST_FIRST(&taskp->hours);
		SLIST_REMOVE_HEAD(&taskp->hours, entries);
		free(tfap);
	}

	while (!SLIST_EMPTY(&taskp->days_of_month)) {
		tfap = SLIST_FIRST(&taskp->days_of_month);
		SLIST_REMOVE_HEAD(&taskp->days_of_month, entries);
		free(tfap);
	}

	while (!SLIST_EMPTY(&taskp->months)) {
		tfap = SLIST_FIRST(&taskp->months);
		SLIST_REMOVE_HEAD(&taskp->months, entries);
		free(tfap);
	}

	while (!SLIST_EMPTY(&taskp->days_of_week)) {
		tfap = SLIST_FIRST(&taskp->days_of_week);
		SLIST_REMOVE_HEAD(&taskp->days_of_week, entries);
		free(tfap);
	}

	free(taskp->username);
	free(taskp->command);
}
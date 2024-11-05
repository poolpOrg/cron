/*	$OpenBSD: tree.h,v 1.1 2018/12/23 16:06:24 gilles Exp $	*/

/*
 * Copyright (c) 2013 Eric Faurot <eric@openbsd.org>
 * Copyright (c) 2011 Gilles Chehade <gilles@poolp.org>
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

#ifndef	_RUNQ_H_
#define	_RUNQ_H_

struct job {
	TAILQ_ENTRY(job)	 entry;
	time_t			 when;
	void			*arg;
};

struct runq {
	TAILQ_HEAD(, job)	 jobs;
	void			(*cb)(struct runq *, void *);
	struct event		 ev;
};


/* runq.c */
int runq_init(struct runq **, void (*)(struct runq *, void *));
int runq_schedule(struct runq *, time_t, void *);
int runq_schedule_at(struct runq *, time_t, void *);
int runq_cancel(struct runq *, void *);
int runq_pending(struct runq *, void *, time_t *);

#endif


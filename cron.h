/*
 * Copyright (c) 2024 Gilles Chehade <gilles@poolp.org>
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

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

#define	CRON_USER	"_cron"
#define	PATH_CHROOT	"/var/empty"
#define	PATH_SPOOLER	"/var/cron"

#include "tree.h"
#include "dict.h"
#include "runq.h"

struct cron {
};

enum cron_proc_type {
	PROC_PARENT,
	PROC_CONTROL,
	PROC_PLANNER,
	PROC_CLIENT,	// control session
};


enum imsg_type {
	IMSG_SETUP_PEER,
	IMSG_SETUP_DONE,
};

struct tab {
	uint32_t	id;
	struct dict	env;
	struct tree	tasks;
};

struct tab_cache {
	size_t	size;
	time_t	mtime;
};


enum time_field_type {
	TFA_MINUTE,
	TFA_HOUR,
	TFA_DAY_OF_MONTH,
	TFA_MONTH,
	TFA_DAY_OF_WEEK,
};

SLIST_HEAD(time_field_head, time_field_atom);
struct time_field_atom {
	SLIST_ENTRY(time_field_atom)	entries;

	int8_t	step;
	int8_t	rndval;
	int8_t	minval;
	int8_t	maxval;
};


struct task {
	uint8_t	run_once;

	struct time_field_head minutes;
	struct time_field_head hours;
	struct time_field_head days_of_month;
	struct time_field_head months;
	struct time_field_head days_of_week;

	char	*username;

	uint8_t	n_flag;
	uint8_t	q_flag;
	uint8_t	s_flag;

	char	*command;
};


extern enum cron_proc_type	cron_process;

extern struct mproc *p_control;
extern struct mproc *p_parent;
extern struct mproc *p_planner;

extern int tracing;

extern struct cron	*env;
extern void (*imsg_callback)(struct mproc *, struct imsg *);

#define	TRACE_DEBUG	0x0001
#define	TRACE_MPROC	0x0002
#define	TRACE_IMSG	0x0004
#define	TRACE_SCHEDULER	0x0008

int	parent(void);
int	control(void);
int	planner(void);


void	imsg_dispatch(struct mproc *, struct imsg *);
void	parent_imsg(struct mproc *, struct imsg *);

struct mproc *	start_child(int, char **, char *);
void	setup_proc(void);
struct mproc *	setup_peer(enum cron_proc_type, pid_t, int);
void	setup_done(struct mproc *);

const char *	proc_title(enum cron_proc_type);
const char *	proc_name(enum cron_proc_type);
const char *	imsg_to_str(int);

void	config_process(enum cron_proc_type);
void	config_peer(enum cron_proc_type);

void log_trace_verbose(int);
void log_trace0(const char *, ...);
#define log_trace(m, ...)  do { if (tracing & (m)) log_trace0(__VA_ARGS__); } while (0)


/* setup.c */
void	setup_peers(struct mproc *, struct mproc *);

/* tab.c */
void	tab_init(struct tab *);
void	tab_cleanup(struct tab *);


/* task.c */
void	task_init(struct task *);
void	task_cleanup(struct task *);


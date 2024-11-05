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
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "cron.h"
#include "mproc.h"
#include "log.h"

static struct event	ev;

static void	scheduler_reset_events(void);
static void	scheduler_timeout(int, short, void *);
static void	scheduler_shutdown(void);

static struct tree tabs;

void
scheduler_imsg(struct mproc *p, struct imsg *imsg)
{
	struct msg	m;
	struct tab	*tabp;
	struct task	*taskp;
	uint32_t	tab_id;
	uint32_t	task_id;
	char		*key;
	char		*value;

	if (imsg == NULL)
		scheduler_shutdown();

	switch (imsg->hdr.type) {
	case IMSG_TAB_BEGIN:
		m_msg(&m, imsg);
		m_get_u32(&m, &tab_id);
		m_end(&m);

		if ((tabp = calloc(1, sizeof *tabp)) == NULL)
			fatal("calloc");

		tab_init(tabp);

		tree_xset(&tabs, (uint64_t)tab_id, tabp);
		break;

	case IMSG_TAB_ENV:
		m_msg(&m, imsg);
		m_get_u32(&m, &tab_id);
		m_get_string(&m, (const char **)&key);
		m_get_string(&m, (const char **)&value);
		m_end(&m);

		if ((value = strdup(value)) == NULL)
			fatal("calloc");
		
		tabp = tree_xget(&tabs, (uint64_t)tab_id);
		dict_set(&tabp->env, key, value);
		break;

	case IMSG_TAB_COMMIT:
		m_msg(&m, imsg);
		m_get_u32(&m, &tab_id);
		m_end(&m);

		tabp = tree_xget(&tabs, (uint64_t)tab_id);
		log_info("tab %08x committed, will compute schedule table", tab_id);

		break;

	case IMSG_TAB_REMOVE:
		m_msg(&m, imsg);
		m_get_u32(&m, &tab_id);
		m_end(&m);

		tabp = tree_xpop(&tabs, (uint64_t)tab_id);
		tab_cleanup(tabp);
		free(tabp);
		log_info("tab %08x removed", tab_id);

		break;

	case IMSG_TAB_TASK_BEGIN: {
		uint8_t	run_once;
		const char	*username;
		uint8_t	n_flag;
		uint8_t	q_flag;
		uint8_t	s_flag;
		const char	*command;

		m_msg(&m, imsg);
		m_get_u32(&m, &tab_id);
		m_get_u32(&m, &task_id);
		m_get_u8(&m, &run_once);
		m_get_string(&m, &username);
		m_get_u8(&m, &n_flag);
		m_get_u8(&m, &q_flag);
		m_get_u8(&m, &s_flag);
		m_get_string(&m, &command);
		m_end(&m);

		if ((taskp = calloc(1, sizeof *taskp)) == NULL)
			fatal("calloc");
		task_init(taskp);

		if (username != NULL) {
			if ((taskp->username = strdup(username)) == NULL)
				fatal("strdup");
		}
		if ((taskp->command = strdup(command)) == NULL)
			fatal("strdup");

		taskp->run_once = run_once;
		taskp->n_flag = n_flag;
		taskp->q_flag = q_flag;
		taskp->s_flag = s_flag;

		tabp = tree_xget(&tabs, (uint64_t)tab_id);
		tree_xset(&tabp->tasks, (uint64_t)task_id, taskp);
		break;
	}

	case IMSG_TAB_TASK_COMMIT:
		m_msg(&m, imsg);
		m_get_u32(&m, &tab_id);
		m_get_u32(&m, &task_id);
		m_end(&m);


		/* XXX - for now do nothing */
		tabp = tree_xget(&tabs, (uint64_t)tab_id);
		taskp = tree_xget(&tabp->tasks, (uint64_t)task_id);

		break;

	case IMSG_TAB_TASK_ADD_TIMEFIELD: {
		uint8_t type;
		uint8_t	step;
		uint8_t	rndval;
		uint8_t	minval;
		uint8_t	maxval;
		struct time_field_atom *np;

		m_msg(&m, imsg);
		m_get_u32(&m, &tab_id);
		m_get_u32(&m, &task_id);
		m_get_u8(&m, &type);
		m_get_u8(&m, &step);
		m_get_u8(&m, &rndval);
		m_get_u8(&m, &minval);
		m_get_u8(&m, &maxval);
		m_end(&m);

		if ((np = calloc(1, sizeof *np)) == NULL)
			fatal("calloc");

		np->step = step;
		np->rndval = rndval;
		np->minval = minval;
		np->maxval = maxval;
		
		tabp = tree_xget(&tabs, (uint64_t)tab_id);
		taskp = tree_xget(&tabp->tasks, (uint64_t)task_id);

		switch (type) {
		case TFA_MINUTE:
			SLIST_INSERT_HEAD(&taskp->minutes, np, entries);
			break;
		case TFA_HOUR:
			SLIST_INSERT_HEAD(&taskp->hours, np, entries);
			break;
		case TFA_DAY_OF_MONTH:
			SLIST_INSERT_HEAD(&taskp->days_of_month, np, entries);
			break;
		case TFA_MONTH:
			SLIST_INSERT_HEAD(&taskp->months, np, entries);
			break;
		case TFA_DAY_OF_WEEK:
			SLIST_INSERT_HEAD(&taskp->days_of_week, np, entries);
			break;
		default:
			fatalx("unrecognized time field type");
		}

		
		break;
	}

	default:
		fatalx("scheduler_imsg: unexpected %s imsg",
		    imsg_to_str(imsg->hdr.type));
	}
}

static void
scheduler_shutdown(void)
{
	log_debug("debug: scheduler agent exiting");
	_exit(0);
}

int
scheduler(void)
{
	struct passwd	*pw;

	if ((pw = getpwnam(CRON_USER)) == NULL)
		fatalx("unknown user " CRON_USER);

	config_process(PROC_SCHEDULER);

	if (chroot(PATH_CHROOT) == -1)
		fatal("scheduler: chroot");
	if (chdir("/") == -1)
		fatal("scheduler: chdir(\"/\")");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("scheduler: cannot drop privileges");

	tree_init(&tabs);
	
	imsg_callback = scheduler_imsg;
	event_init();

	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	config_peer(PROC_PARENT);
	config_peer(PROC_PLANNER);
	
	if (pledge("stdio", NULL) == -1)
		fatal("pledge");

	//evtimer_set(&ev, scheduler_timeout, NULL);
	//scheduler_reset_events();

	event_dispatch();
	fatalx("exited event loop");
	return (1);
}

static void
scheduler_reset_events(void)
{
	struct timeval	 tv;

	evtimer_del(&ev);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	evtimer_add(&ev, &tv);
}

static void
scheduler_timeout(int fd, short event, void *p)
{
	struct timeval		tv;

	log_info("scheduler tick");

	tv.tv_sec = 60;
	tv.tv_usec = 0;
	evtimer_add(&ev, &tv);
}

static void
analyze_task()
{
}

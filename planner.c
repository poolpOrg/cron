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
#include <inttypes.h>
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


static struct dict	tabs;

static struct event	ev;

static struct runq	*runq;

static struct tab *planning_parse_user_tab(char *, char *, uid_t);
static void	planner_process_user_tab(char *, char *, uid_t);
static void	planner_walk(void);
static void	planner_shutdown(void);

static time_t	next_schedule(time_t, struct task *);
static void	task_execute_callback(struct runq *, void *);

static int	handle_notify_user_tab(int, const char *, uid_t, char **);
static struct tab *parse_user_tab(FILE *, const char *, uid_t);

void
planner_imsg(struct mproc *p, struct imsg *imsg)
{
	struct msg	m;

	if (imsg == NULL)
		planner_shutdown();

	switch (imsg->hdr.type) {
	case IMSG_NOTIFY_USER_TAB: {
		int		fd;
		FILE		*fp;
		const char	*username;
		uid_t		uid;
		char		*errormsg;

		m_msg(&m, imsg);
		m_get_string(&m, &username);
		m_get_uid(&m, &uid);
		m_end(&m);

		if (handle_notify_user_tab(imsg_get_fd(imsg), username, uid, &errormsg))
			return;

		m_create(p_parent, IMSG_NOTIFY_USER_TAB_FAILURE, 0, 0, -1);
		m_add_string(p_parent, username);
		m_add_string(p_parent, errormsg);
		m_close(p_parent);
		break;
	}
	default:
		fatalx("planner_imsg: unexpected %s imsg",
		    imsg_to_str(imsg->hdr.type));
	}
}

static void
planner_shutdown(void)
{
	log_debug("debug: planner agent exiting");
	_exit(0);
}

int
planner(void)
{
	struct passwd	*pw;

	if ((pw = getpwnam(CRON_USER)) == NULL)
		fatalx("unknown user " CRON_USER);

	config_process(PROC_PLANNER);

	if (chroot(PATH_SPOOLER) == -1)
		fatal("planner: chroot");
	if (chdir("/") == -1)
		fatal("planner: chdir(\"/\")");

	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("planner: cannot drop privileges");

	imsg_callback = planner_imsg;

	event_init();

	if (!runq_init(&runq, task_execute_callback))
		fatal("planner: runq_init");

	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	config_peer(PROC_PARENT);
	
	if (pledge("stdio rpath recvfd", NULL) == -1)
		fatal("pledge");

	dict_init(&tabs);
 
	event_dispatch();
	fatalx("exited event loop");
	return (1);
}


static void
task_execute_callback(struct runq *rq, void *arg)
{
	struct task	*taskp = (struct task *)arg;
	time_t		now, next;

	struct tm	*now_ti;
	char		now_buffer[80];

	struct tm	*ti;
	char		buffer[80];

	void		*iter;
	const char	*key;
	const char	*value;

	uint32_t	*tab_id;
	struct tab	*tabp;
	
	now = time(NULL);
	now_ti = localtime(&now);
	strftime(now_buffer, sizeof(now_buffer), "%Y-%m-%d-%H:%M", now_ti);
	
	next = task_next_schedule(taskp, now);
	ti = localtime(&next);
	strftime(buffer, sizeof(buffer), "%Y-%m-%d-%H:%M", ti);


	m_create(p_parent, IMSG_TASK_CREATE, 0, 0, -1);
	m_add_id(p_parent, taskp->id);
	m_add_string(p_parent, taskp->username);
	m_add_uid(p_parent, taskp->uid);
	m_add_u8(p_parent, taskp->n_flag);
	m_add_u8(p_parent, taskp->q_flag);
	m_add_u8(p_parent, taskp->s_flag);
	m_add_string(p_parent, taskp->command);
	m_close(p_parent);

	tabp = taskp->tabp;

	iter = NULL;
	while (dict_iter(&tabp->env, &iter, &key, (void **)&value)) {
		m_create(p_parent, IMSG_TASK_SETENV, 0, 0, -1);
		m_add_id(p_parent, taskp->id);
		m_add_string(p_parent, key);
		m_add_string(p_parent, value);
		m_close(p_parent);
	}

	m_create(p_parent, IMSG_TASK_RUN, 0, 0, -1);
	m_add_id(p_parent, taskp->id);
	m_close(p_parent);

	log_info("[%016" PRIx64 "] %s: running command [%s] as user %s (uid=%d)",
	    taskp->id, now_buffer, taskp->command, taskp->username, taskp->uid);
	
	if (!runq_schedule_at(runq, next, (void *)taskp)) {
		log_warn("Failed to schedule task %s", taskp->command);
	}
	log_info("[%016" PRIx64 "] \trescheduling at %s",
	    taskp->id, buffer);
}

static int
handle_notify_user_tab(int fd, const char *username, uid_t uid, char **errormsg)
{
	FILE		*fp = NULL;
	struct tab	*tabp = NULL, *old = NULL;

	/* fd exhaustion prevented fd passing */
	if (fd == -1) {
		*errormsg = "could not obtain file descriptor";
		goto err;
	}

	if ((fp = fdopen(fd, "r")) == NULL) {
		*errormsg = strerror(errno);
		goto err;
	}

	if ((tabp = tab_parse_user(fp, username, uid)) == NULL)
		goto err;

	old = dict_get(&tabs, username);
	dict_set(&tabs, username, tabp);
	if (old != NULL) {
		tab_unplan(runq, tabp);
		tab_cleanup(old);
		free(old);
		old = NULL;
	}

	if (!tab_plan(runq, tabp)) {
		tab_unplan(runq, tabp);
		dict_pop(&tabs, username);
		tab_cleanup(tabp);
		free(tabp);
		tabp = NULL;
		goto err;
	}

	fclose(fp);
	return 1;

err:
	if (fd != -1)
		close(fd);
	if (fp != NULL)
		fclose(fp);
	if (*errormsg == NULL) {
		*errormsg = "unknown error";
	}
	return 0;
}

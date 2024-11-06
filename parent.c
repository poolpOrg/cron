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

#include <err.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <fts.h>
#include <imsg.h>
#include <inttypes.h>
#include <paths.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "cron.h"
#include "dict.h"
#include "mproc.h"
#include "log.h"

static struct dict	tabs_cache;
static struct tree	tasks;

static struct event	ev;

static int	run_task(struct task *);
static int	run_command(const char *);

static void	reset_events(void);
static void	watcher_timeout(int, short, void *);
static void	watcher_tabs(void);
static void	watcher_handle_user_tab(const char *, const char *, struct stat *);

void
parent_imsg(struct mproc *p, struct imsg *imsg)
{
	struct msg		 m;
	struct task		*taskp;

	if (imsg == NULL)
		fatalx("process %s socket closed", p->name);

	switch (imsg->hdr.type) {
	case IMSG_NOTIFY_USER_TAB_FAILURE: {
		const char		*username;
		const char		*errormsg;
		struct tab_cache	*tc;

		m_msg(&m, imsg);
		m_get_string(&m, &username);
		m_get_string(&m, &errormsg);
		m_end(&m);

		log_warnx("error installing crontab for %s: %s",
		    username, errormsg);

		/* invalidate cache to give it another chance at next tick */
		if ((tc = dict_pop(&tabs_cache, username)) != NULL)
			free(tc);		
		break;
	}
		
	case IMSG_TASK_CREATE: {
		uint64_t	taskid;
		const char     	*username;
		uid_t		uid;
		uint8_t		n_flag;
		uint8_t		q_flag;
		uint8_t		s_flag;
		const char     	*command;

		m_msg(&m, imsg);
		m_get_id(&m, &taskid);
		m_get_string(&m, &username);
		m_get_uid(&m, &uid);
		m_get_u8(&m, &n_flag);
		m_get_u8(&m, &q_flag);
		m_get_u8(&m, &s_flag);
		m_get_string(&m, &command);
		m_end(&m);

		if ((taskp = calloc(1, sizeof(*taskp))) == NULL)
			fatal("calloc");

		task_init(taskp);

		if ((taskp->username = strdup(username)) == NULL)
			fatal("strdup");
		if ((taskp->command = strdup(command)) == NULL)
			fatal("strdup");

		taskp->id = taskid;
		taskp->uid = uid;
		taskp->n_flag = n_flag;
		taskp->q_flag = q_flag;
		taskp->s_flag = s_flag;

		tree_xset(&tasks, taskid, taskp);
		break;
	}

	case IMSG_TASK_SETENV: {
		uint64_t	taskid;
		const char	*key;
		const char	*value, *valuecp;
		
		m_msg(&m, imsg);
		m_get_id(&m, &taskid);
		m_get_string(&m, &key);
		m_get_string(&m, &value);
		m_end(&m);

		taskp = tree_xget(&tasks, taskid);

		if ((valuecp = strdup(value)) == NULL)
			fatal("strdup");

		dict_set(&taskp->env, key, (void *)valuecp);
		break;
	}

	case IMSG_TASK_RUN: {
		uint64_t	taskid;

		m_msg(&m, imsg);
		m_get_id(&m, &taskid);
		m_end(&m);

		taskp = tree_xpop(&tasks, taskid);

		run_task(taskp);

		task_cleanup(taskp);
		free(taskp);

		break;
	}

	default:
		fatalx("parent_imsg: unexpected %s imsg from %s",
		    imsg_to_str(imsg->hdr.type), proc_title(p->proc));
	}
}

int
parent()
{
	imsg_callback = parent_imsg;

	event_init();

	config_peer(PROC_PLANNER);
	
	if (pledge("stdio proc getpw rpath id exec sendfd", NULL) == -1)
		fatal("pledge");


	evtimer_set(&ev, watcher_timeout, NULL);
	reset_events();

	dict_init(&tabs_cache);
	tree_init(&tasks);

	event_dispatch();
	fatalx("exited event loop");
	return (1);
}

static int
run_command(const char *command)
{
	char	*shell = getenv("SHELL");

	execle(shell, shell, "-c", command, (char *)NULL, NULL);
	log_warn("could not execute command");
	return 0;
}
	    
static int
run_task(struct task *taskp)
{
	pid_t	pid;
	struct passwd	*pw;
	void	*iter;
	const char	*key;
	const char	*value;
	char		**envp;
	extern char **environ;
	
	log_info("RUNNING TASK FOR %s (uid=%d) REQUEST FOR %016"PRIx64, taskp->username, taskp->uid, taskp->id);	

	if ((pw = getpwnam(taskp->username)) == NULL) {
		log_info("getpnam failed");
		return 0;
	}
	if (pw->pw_uid != taskp->uid) {
		log_info("uid mismatch: %d <> %d", pw->pw_uid, taskp->uid);
		return 0;
	}
	log_info("uid: %d, gid: %d", pw->pw_uid, pw->pw_gid);
	
	pid = fork();
	if (pid == -1)
		return 0;

	if (pid > 0) {

		
		// parent process
		return 1;
	}

	if (chdir(pw->pw_dir) == -1 && chdir("/") == -1)
		fatal("chdir");
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid))
		fatal("run_task: cannot drop privileges");

	/* set environment */
	environ = NULL;
	setenv("LOGNAME", pw->pw_name, 1);
	setenv("HOME", pw->pw_dir, 1);
	setenv("PWD", pw->pw_dir, 1);
	setenv("PATH", _PATH_DEFPATH, 1);
	setenv("SHELL", "/bin/sh", 1);
	setenv("USER", pw->pw_name, 1);

	iter = NULL;
	while (dict_iter(&taskp->env, &iter, &key, (void **)&value)) {
		if (!strcmp("LOGNAME", key))
			continue;
		if (!strcmp("USER", key))
			continue;
		setenv(key, value, 1);
	}

	_exit(run_command(taskp->command));
}

static void
reset_events(void)
{
	struct timeval	tv;

	evtimer_del(&ev);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	evtimer_add(&ev, &tv);
}

static void
watcher_timeout(int fd, short event, void *p)
{
	struct timeval	tv;

	tv.tv_sec = 10;
	tv.tv_usec = 0;

	watcher_tabs();

	evtimer_add(&ev, &tv);
}

static void
watcher_tabs(void)
{
	FTS		*fts;
	FTSENT		*ftse;
	int		depth = 0;
	char * const	path_argv[] = { "/var/cron/tabs", NULL };

	fts = fts_open(path_argv,
	    FTS_PHYSICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL) {
		log_warn("watcher_tabs: fts_open: %s", PATH_SPOOLER);
		return;
	}

	while ((ftse = fts_read(fts)) != NULL) {
		switch (ftse->fts_info) {
		case FTS_D:
			depth +=1;
			if (depth != 1) {
				/* skip subdirectories */
				continue;
			}
			break;
		case FTS_DP:
		case FTS_DNR:
			depth -= 1;
			break;
		case FTS_F:
			if (depth != 1) {
				/* skip file */
				continue;
			}
			watcher_handle_user_tab(fts->fts_path, ftse->fts_name, ftse->fts_statp);
			break;
		default:
			break;
		}
	}
	fts_close(fts);
}

static void
watcher_handle_user_tab(const char *pathname, const char *username, struct stat *st)
{
	struct tab_cache *cc;
	int fd;

	/* check if tab is already in cache with identical size and mtime */
	cc = dict_get(&tabs_cache, username);
	if (cc != NULL && cc->size == st->st_size && cc->mtime == st->st_mtime)
		return;

	if ((fd = open(pathname, O_RDONLY)) == -1) {
		log_warn("cannot open crontab %s", pathname);
		return;
	}

	
	/* hand over tab to planner for parsing and scheduling */
	m_create(p_planner, IMSG_NOTIFY_USER_TAB, 0, 0, fd);
	m_add_string(p_planner, username);
	m_add_uid(p_planner, st->st_uid);
	m_close(p_planner);


	/* update cache, will be invalidated if IMSG_NOTIFY_USER_TAB fails */
	if (cc == NULL)
		if ((cc = calloc(1, sizeof *cc)) == NULL) {
			log_warn("cannot allocate tab cache entry");
			return;
		}
	cc->size = st->st_size;
	cc->mtime = st->st_mtime;
	dict_set(&tabs_cache, username, cc);
}

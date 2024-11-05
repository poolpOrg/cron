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
#include <inttypes.h>
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

static struct tree	tasks;

static int	run_task(struct task *);

void
parent_imsg(struct mproc *p, struct imsg *imsg)
{
	struct msg		 m;
	struct task		*taskp;

	if (imsg == NULL)
		fatalx("process %s socket closed", p->name);

	switch (imsg->hdr.type) {
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

	case IMSG_TASK_RUN: {
		uint64_t	taskid;

		m_msg(&m, imsg);
		m_get_id(&m, &taskid);
		m_end(&m);

		run_task(tree_xpop(&tasks, taskid));
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
	
	if (pledge("stdio proc getpw rpath id exec", NULL) == -1)
		fatal("pledge");

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
	char	*shell;
	struct passwd	*pw;

	log_info("RUNNING TASK FOR %s (uid=%d) REQUEST FOR %016"PRIx64, taskp->username, taskp->uid, taskp->id);	

	if ((pw = getpwnam(taskp->username)) == NULL) {
		return 0;
	}
	if (pw->pw_uid != taskp->uid) {
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

	/* XXX - SET ENV */

	_exit(run_command(taskp->command));
}

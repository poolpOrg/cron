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

static struct dict	tabs_cache;
static struct dict	tabs;


static struct event	ev;

static struct tab *planning_parse_user_tab(FILE *, char *);
static void	planner_process_tab(char *);
static void	planner_walk(void);
static void	planner_reset_events(void);
static void	planner_timeout(int, short, void *);
static void	planner_shutdown(void);

void
planner_imsg(struct mproc *p, struct imsg *imsg)
{
	struct msg		 m;

	if (imsg == NULL)
		planner_shutdown();

	switch (imsg->hdr.type) {
	default:
		break;
	}
	fatalx("planner_imsg: unexpected %s imsg",
	    imsg_to_str(imsg->hdr.type));
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

	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);

	config_peer(PROC_PARENT);
	
	if (pledge("stdio rpath", NULL) == -1)
		fatal("pledge");

	evtimer_set(&ev, planner_timeout, NULL);
	planner_reset_events();

	dict_init(&tabs_cache);
	dict_init(&tabs);
 
	event_dispatch();
	fatalx("exited event loop");
	return (1);
}

static void
planner_reset_events(void)
{
	struct timeval	 tv;

	evtimer_del(&ev);
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	evtimer_add(&ev, &tv);
}

static void
planner_timeout(int fd, short event, void *p)
{
	struct timeval		tv;

	planner_walk();

	tv.tv_sec = 10;
	tv.tv_usec = 0;
	evtimer_add(&ev, &tv);
}

static void
planner_walk()
{
	FTS		*fts;
	FTSENT		*ftse;
	int		depth = 0;
	char * const	path_argv[] = { "/tabs", NULL };

	fts = fts_open(path_argv,
	    FTS_PHYSICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL)
		fatal("planner_walk: fts_open: %s", PATH_SPOOLER);

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
				/* skip tab */
				continue;
			}
			planner_process_tab(fts->fts_path);
			break;
		default:
			break;
		}
	}

		
	fts_close(fts);
}

static void
planner_process_tab(char *pathname)
{
	FILE *fp;
	struct stat	sb;
	struct tab_cache *cc;
	struct tab	*c, *old;
	
	if (stat(pathname, &sb) == -1) {
		log_warn("stat");
		return;
	}

	cc = dict_get(&tabs_cache, pathname);
	if (cc != NULL && cc->size == sb.st_size && cc->mtime == sb.st_mtime) {
		return;
	}
	
	fp = fopen(pathname, "r");
	if (fp == NULL)
		goto err;


	c = planning_parse_user_tab(fp, pathname);
	if (c == NULL) {
		log_warn("could not parse %s", pathname);
	} else {
		old = dict_get(&tabs, pathname);
		dict_set(&tabs, pathname, c);
		if (old != NULL) {
			tab_cleanup(old);
			free(old);
		}
	}
	fclose(fp);

	if (cc == NULL) {
		if ((cc = calloc(1, sizeof *cc)) == NULL) {
			log_warn("calloc");
			goto err;
		}
	}
	cc->size = sb.st_size;
	cc->mtime = sb.st_mtime;
	dict_set(&tabs_cache, pathname, cc);

	return;

err:
	if (fp != NULL)
		fclose(fp);
	return;
}

static int
parse_env_entry(struct tab *c, char *line) {
	char *key;
	char *value;
	char *p;


	key = line;
	for (p = key; *p != '\0' && isalnum(*p); p++)
		;
	for (; *p != '\0' && isspace(*p); p++)
		*p = '\0';
	if (*p != '=')
		return 0;
	*p = '\0';
	value = p+1;

	/* TODO: handle quoting */


	/* USER may not be overriden by settings in the tab */
	if (!strcmp(key, "USER"))
		return 0;

	if ((value = strdup(value)) == NULL)
		return 0;
	dict_set(&c->env, key, value);
	return 1;
}


static int
validate_task(struct task *t)
{
	return 1;
err:
	return 0;
}

static int
parse_user_tab_shortcut_task_entry(struct tab *c, char *line)
{
	struct task	t;
	struct task	*tp;
	char		*p;
	char		*shortcut;
	
	memset(&t, 0, sizeof t);
	
	shortcut = line;
	for (p = line; *p != '\0' && !isspace(*p); p++)
		;
	if (*p == '\0')
		return 0;
	if (*p) {
		*p++ = '\0';
		for (; *p != '\0' && isspace(*p); p++)
			*p = '\0';
	}

	if (!strcmp(shortcut, "@reboot"))
		t.run_once = 1;
	else if (!strcmp(shortcut, "@yearly") || !strcmp(shortcut, "@annually")) {

	} else if (!strcmp(shortcut, "@monthly")) {

	} else if (!strcmp(shortcut, "@weekly")) {

	} else if (!strcmp(shortcut, "@daily") || !strcmp(shortcut, "@midnight")) {

	} else if (!strcmp(shortcut, "@hourly")) {

	} else {
		return 0;
	}

	/* check optional flags*/
	if (*p == '-') {
		if (*(p+1) == '\0')
			return 0;
		for (; *p != '\0' && !isspace(*p); p++) {
			if (*p == 'n')
				t.n_flag = 1;
			else if (*p == 'q')
				t.q_flag = 1;
			else if (*p == 's')
				t.s_flag = 1;
			else
				return 0;
		}
		if (*p == '\0')
			return 0;
		if (*p) {
			*p++ = '\0';
			for (; *p != '\0' && isspace(*p); p++)
				*p = '\0';
		}
	}

	t.command = p;

	return 1;
}

static int
parse_time_field_atom(char *input, struct time_field_atom *tfa, enum time_field_type type)
{
	uint8_t minval = 0;
	uint8_t maxval = 0;
	char *stepstr;
	const char *errstr;
	char *rangep;

	switch (type) {
	case TFA_MINUTE:
		minval = 0;
		maxval = 59;
		break;
	case TFA_HOUR:
		minval = 0;
		maxval = 23;
		break;
	case TFA_DAY_OF_MONTH:
		minval = 1;
		maxval = 31;
		break;
	case TFA_MONTH:
		minval = 1;
		maxval = 12;
		break;
	case TFA_DAY_OF_WEEK:
		minval = 0;
		maxval = 7;
		break;
	default:
		fatalx("unexpected time field atom type: %d", type);
	}
	
	if ((stepstr = strchr(input, '/')) != NULL) {
		*stepstr++ = '\0';
	}
	if (stepstr != NULL) {
		tfa->step = strtonum(stepstr, minval, maxval, &errstr);
		if (errstr != NULL)
			return 0;
	}

	if (!strcmp(input, "*")) {
		tfa->minval = minval;
		tfa->maxval = maxval;
		return 1;
	}

	if (!strcmp(input, "~")) {
		tfa->minval = minval;
		tfa->maxval = maxval;
		tfa->rndval = 1;
		return 1;
	}

	if ((rangep = strchr(input, '-')) != NULL) {
		
	} else if ((rangep = strchr(input, '~')) != NULL) {
		tfa->rndval = 1;
	}

	if (rangep == NULL) {
		tfa->minval = strtonum(input, minval, maxval, &errstr);
		if (errstr != NULL)
			return 0;
		tfa->maxval = tfa->minval;
		return 1;
	}

	*rangep++ = '\0';
	if (*input == '\0') {
		/* original cron only allows omiting low or high for random */
		tfa->minval = minval;
		if (!tfa->rndval)
			return 0;
	} else {
		tfa->minval = strtonum(input, minval, maxval, &errstr);
		if (errstr != NULL)
			return 0;
	}

	if (*rangep == '\0') {
		/* original cron only allows omiting low or high for random */
		tfa->maxval = maxval;
		if (!tfa->rndval)
			return 0;
	} else {
		tfa->maxval = strtonum(rangep, minval, maxval, &errstr);
		if (errstr != NULL)
			return 0;
	}


	if (tfa->minval > tfa->maxval) {
		return 0;
	}

	return 1;
}

static int
parse_time_field(struct task *t, char *input, enum time_field_type type)
{
	char *atom;
	char *rest = input;

	while ((atom = strsep(&rest, ",")) != NULL) {
		struct time_field_atom tfa;
		struct time_field_atom *tfap;

		memset(&tfa, 0, sizeof tfa);
		if (!parse_time_field_atom(atom, &tfa, type)) {
			log_info("BROKEN FIELD: %s", atom);
			return 0;
		}

		if ((tfap = calloc(1, sizeof *tfap)) == NULL)
			return 0;
		*tfap = tfa;
		
		switch (type) {
		case TFA_MINUTE:
			SLIST_INSERT_HEAD(&t->minutes, tfap, entries);
			break;
		case TFA_HOUR:
			SLIST_INSERT_HEAD(&t->hours, tfap, entries);
			break;
		case TFA_DAY_OF_MONTH:
			SLIST_INSERT_HEAD(&t->days_of_month, tfap, entries);
			break;
		case TFA_MONTH:
			SLIST_INSERT_HEAD(&t->months, tfap, entries);
			break;
		case TFA_DAY_OF_WEEK:
			SLIST_INSERT_HEAD(&t->days_of_week, tfap, entries);
			break;
		default:
			free(tfap);
			return 0;
		}
	}
	
	return 1;
}

static int
expand_task_scheds(struct task *t, char *minute, char *hour, char *day_of_month, char *month, char *day_of_week)
{
	if (!parse_time_field(t, minute, TFA_MINUTE))
		return 0;
	
	if (!parse_time_field(t, hour, TFA_HOUR))
		return 0;

	if (!parse_time_field(t, day_of_month, TFA_DAY_OF_MONTH))
		return 0;

	if (!parse_time_field(t, month, TFA_MONTH))
		return 0;

	if (!parse_time_field(t, day_of_week, TFA_DAY_OF_WEEK))
		return 0;
	
	return 1;
}

static int
parse_user_tab_task_entry(struct tab *tabp, char *line)
{
	struct task	*taskp;
	uint32_t	taskid;
	char		*p;
	char		*minute;
	char		*hour;
	char		*day_of_month;
	char		*month;
	char		*day_of_week;


	if (*line == '@')
		return parse_user_tab_shortcut_task_entry(tabp, line);

	minute = strsep(&line, " \t");
	for (; *line != '\0' && isspace(*line); line++)
		;

	hour = strsep(&line, " \t");
	for (; *line != '\0' && isspace(*line); line++)
		;

	day_of_month = strsep(&line, " \t");
	for (; *line != '\0' && isspace(*line); line++)
		;

	month = strsep(&line, " \t");
	for (; *line != '\0' && isspace(*line); line++)
		;

	day_of_week = strsep(&line, " \t");
	for (; *line != '\0' && isspace(*line); line++)
		;

	if (minute == NULL || hour == NULL || day_of_month == NULL ||
	    month == NULL || day_of_week == NULL)
		return 0;

	if ((taskp = calloc(1, sizeof *taskp)) == NULL)
		return 0;
	task_init(taskp);

	/* check optional flags*/
	if (*p == '-') {
		if (*(p+1) == '\0')
			return 0;
		for (; *p != '\0' && !isspace(*p); p++) {
			if (*p == 'n')
				taskp->n_flag = 1;
			else if (*p == 'q')
				taskp->q_flag = 1;
			else if (*p == 's')
				taskp->s_flag = 1;
			else
				return 0;
		}
		if (*p == '\0')
			return 0;
		if (*p) {
			*p++ = '\0';
			for (; *p != '\0' && isspace(*p); p++)
				*p = '\0';
		}
	}

	if ((taskp->command = strdup(p)) == NULL)
		goto err;
	
	
	if (!expand_task_scheds(taskp, minute, hour, day_of_month, month, day_of_week))
		goto err;

	do {
		taskid = arc4random();
	} while (tree_check(&tabp->tasks, (uint64_t)taskid));
	tree_set(&tabp->tasks, (uint64_t)taskid, taskp);
	
	return 1;

err:
	task_cleanup(taskp);
	free(taskp);
	return 0;
}

static struct tab *
planning_parse_user_tab(FILE *fp, char *filename)
{
	struct tab *tab;
	char *line, *p;
	size_t len, lineno = 0;
	char delim[3] = { '\\', '\\', '#' };

	if ((tab = calloc(1, sizeof *tab)) == NULL)
		return NULL;
	tab_init(tab);

	while ((line = fparseln(fp, &len, &lineno, delim, 0)) != NULL) {
		for (p = line; *p != '\0' && isspace(*p); p++)
			;
		if (strlen(p) != 0) {
			if (isalpha(*p)) {
				if (!parse_env_entry(tab, p))
					goto err;
			} else {
				if (!parse_user_tab_task_entry(tab, p))
					goto err;
			}
		}
		free(line);
	}

	return tab;

err:
	tab_cleanup(tab);
	free(tab);
	return NULL;
}

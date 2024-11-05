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


static int	parse_env_entry(struct tab *, char *);
static int	parse_user_tab_task_entry(struct tab *, const char *, uid_t, char *);
static int	parse_user_tab_shortcut_task_entry(struct tab *, const char *, uid_t, char *);
static int	expand_task_scheds(struct task *, char *, char *, char *, char *, char *);
static int	parse_time_field(struct task *, char *, enum time_field_type);
static int	parse_time_field_atom(char *, struct time_field_atom *, enum time_field_type);


void
tab_init(struct tab *tabp)
{
	tabp->id = arc4random();
	dict_init(&tabp->env);
	tree_init(&tabp->tasks);
}

void
tab_cleanup(struct tab *tabp)
{
	void *iter = NULL;
	void *data = NULL;

	while (dict_iter(&tabp->env, &iter, (const char **)NULL, (void **)&data)) {
		free(data);
	}

	while (tree_iter(&tabp->tasks, &iter, (uint64_t *)NULL, (void **)&data)) {
		free(data);
	}
}

int
tab_plan(struct runq *runq, struct tab *tabp)
{
	void		*iter;
	struct task	*taskp;
	time_t		now, next;
	struct tm	*ti;
	char		buffer[80];

	
	iter = NULL;
	while (tree_iter(&tabp->tasks, &iter, NULL, (void **)&taskp)) {
		now = time(NULL);
		next = task_next_schedule(taskp, now);

		ti = localtime(&next);
		strftime(buffer, sizeof(buffer), "%Y-%m-%d-%H:%M", ti);

		log_info("[%016" PRIx64 "] scheduling task at %s for command [%s] as user %s (uid=%d)",
		    taskp->id, buffer, taskp->command, taskp->username, taskp->uid);

		if (!runq_schedule_at(runq, next, (void *)taskp)) {
			log_warn("[%016" PRIx64 "] failed to schedule", taskp->id);
			return 0;
		}		
	}
	return 1;
}

void
tab_unplan(struct runq *runq, struct tab *tabp)
{
	void		*iter;
	uint64_t	task_id;
	struct task	*taskp;
	time_t		now, next;

	struct tm	*ti;
	char		buffer[80];

	
	iter = NULL;
	while (tree_iter(&tabp->tasks, &iter, (uint64_t *)&task_id, (void **)&taskp)) {
		log_info("[%016" PRIx64 "] canceling", taskp->id);
		runq_cancel(runq, taskp);
	}
}

struct tab *
tab_parse_user(FILE *fp, const char *username, uid_t uid)
{
	struct tab *tabp;
	char *line, *p;
	size_t len, lineno = 0;
	char delim[3] = { '\\', '\\', '#' };

	if ((tabp = calloc(1, sizeof *tabp)) == NULL)
		goto err;

	tab_init(tabp);
	while ((line = fparseln(fp, &len, &lineno, delim, 0)) != NULL) {
		for (p = line; *p != '\0' && isspace(*p); p++)
			;
		if (strlen(p) != 0) {
			if (isalpha(*p)) {
				if (!parse_env_entry(tabp, p))
					goto err;
			} else {
				if (!parse_user_tab_task_entry(tabp, username, uid, p))
					goto err;
			}
		}
		free(line);
	}
	return tabp;

err:
	tab_cleanup(tabp);
	free(tabp);
	return NULL;
}

static int
parse_env_entry(struct tab *tabp, char *line)
{
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
	dict_set(&tabp->env, key, value);
	return 1;
}

static int
parse_user_tab_task_entry(struct tab *tabp, const char *username, uid_t uid, char *line)
{
	struct task	*taskp;
	uint64_t	taskid;
	char		*minute;
	char		*hour;
	char		*day_of_month;
	char		*month;
	char		*day_of_week;


	if (*line == '@')
		return parse_user_tab_shortcut_task_entry(tabp, username, uid, line);

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
	if (*line == '-') {
		if (*(line+1) == '\0')
			return 0;
		for (; *line != '\0' && !isspace(*line); line++) {
			if (*line == 'n')
				taskp->n_flag = 1;
			else if (*line == 'q')
				taskp->q_flag = 1;
			else if (*line == 's')
				taskp->s_flag = 1;
			else
				return 0;
		}
		if (*line == '\0')
			return 0;
		if (*line) {
			*line++ = '\0';
			for (; *line != '\0' && isspace(*line); line++)
				*line = '\0';
		}
	}

	if ((taskp->command = strdup(line)) == NULL)
		goto err;

	if ((taskp->username = strdup(username)) == NULL)
		goto err;
	taskp->uid = uid;

	if (!expand_task_scheds(taskp, minute, hour, day_of_month, month, day_of_week))
		goto err;

	taskid = (uint64_t)tabp->id<<32;
	do {
		taskid = (taskid & 0xffffffff00000000) | arc4random();
	} while (tree_check(&tabp->tasks, taskid));
	taskp->id = taskid;
	tree_set(&tabp->tasks, taskid, taskp);
	
	return 1;

err:
	task_cleanup(taskp);
	free(taskp);
	return 0;
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

	tfa->step = 1;
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
parse_user_tab_shortcut_task_entry(struct tab *c, const char *username, uid_t uid, char *line)
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

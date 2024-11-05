#	$OpenBSD: Makefile,v 1.6 2015/11/12 21:12:05 millert Exp $

PROG=	cron
SRCS=	cron.c		\
	config.c	\
	control.c	\
	dict.c		\
	iobuf.c		\
	ioev.c		\
	log.c		\
	mproc.c		\
	parent.c	\
	planner.c	\
	runq.c		\
	setup.c		\
	tab.c		\
	task.c		\
	tree.c

CFLAGS+=-I${.CURDIR}
LDADD+=	-levent -lutil
DPADD+=	${LIBEVENT} ${LIBUTIL}
MAN=	cron.8

.include <bsd.prog.mk>

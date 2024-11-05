struct mproc {
	pid_t		 pid;
	char		*name;
	int		 proc;
	void		(*handler)(struct mproc *, struct imsg *);
	struct imsgbuf	 imsgbuf;

	char		*m_buf;
	size_t		 m_alloc;
	size_t		 m_pos;
	uint32_t	 m_type;
	uint32_t	 m_peerid;
	pid_t		 m_pid;
	int		 m_fd;

	int		 enable;
	short		 events;
	struct event	 ev;
	void		*data;
};

struct msg {
	const uint8_t	*pos;
	const uint8_t	*end;
};

int mproc_fork(struct mproc *, const char*, char **);
void mproc_init(struct mproc *, int);
void mproc_clear(struct mproc *);
void mproc_enable(struct mproc *);
void mproc_disable(struct mproc *);
void mproc_event_add(struct mproc *);
void m_compose(struct mproc *, uint32_t, uint32_t, pid_t, int, void *, size_t);
void m_composev(struct mproc *, uint32_t, uint32_t, pid_t, int,
    const struct iovec *, int);
void m_forward(struct mproc *, struct imsg *);
void m_create(struct mproc *, uint32_t, uint32_t, pid_t, int);
void m_add(struct mproc *, const void *, size_t);
void m_add_int(struct mproc *, int);
void m_add_u8(struct mproc *, uint8_t);
void m_add_u32(struct mproc *, uint32_t);
void m_add_size(struct mproc *, size_t);
void m_add_uid(struct mproc *, uid_t);
void m_add_time(struct mproc *, time_t);
void m_add_timeval(struct mproc *, struct timeval *tv);
void m_add_string(struct mproc *, const char *);
void m_add_data(struct mproc *, const void *, size_t);
void m_add_evpid(struct mproc *, uint64_t);
void m_add_msgid(struct mproc *, uint32_t);
void m_add_id(struct mproc *, uint64_t);
void m_add_params(struct mproc *, struct dict *);
void m_close(struct mproc *);
void m_flush(struct mproc *);

void m_msg(struct msg *, struct imsg *);
int  m_is_eom(struct msg *);
void m_end(struct msg *);
void m_get_int(struct msg *, int *);
void m_get_size(struct msg *, size_t *);
void m_get_uid(struct msg *, uid_t *);
void m_get_u8(struct msg *, uint8_t *);
void m_get_u32(struct msg *, uint32_t *);
void m_get_time(struct msg *, time_t *);
void m_get_timeval(struct msg *, struct timeval *);
void m_get_string(struct msg *, const char **);
void m_get_data(struct msg *, const void **, size_t *);
void m_get_evpid(struct msg *, uint64_t *);
void m_get_msgid(struct msg *, uint32_t *);
void m_get_id(struct msg *, uint64_t *);
void m_get_params(struct msg *, struct dict *);
void m_clear_params(struct dict *);

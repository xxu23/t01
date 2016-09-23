#ifndef IO_IOENGINE_H
#define IO_IOENGINE_H

#define io_init	__attribute__((constructor))
#define io_exit	__attribute__((destructor))

#include "list.h"

struct ioengine_ops;

struct ioengine_data {
	void *private;
	struct ioengine_ops* io_ops;
};

struct ioengine_ops {
	struct list_head list;
	const char *name;
	int (*connect)(struct ioengine_data *, const char *);
	int (*disconnect)(struct ioengine_data *);
	int (*show_help)();
	int (*write)(struct ioengine_data *, const char *, int);
};


extern int load_ioengine(struct ioengine_data *, const char *);
extern int init_ioengine(struct ioengine_data *, const char *);
extern void close_ioengine(struct ioengine_data *);
extern int store_via_ioengine(struct ioengine_data *, void *, const char *, const char *, int);

extern void register_ioengine(struct ioengine_ops *);
extern void unregister_ioengine(struct ioengine_ops *);

extern int fio_show_ioengine_help(const char *engine);


#endif

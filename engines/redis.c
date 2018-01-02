/*
 * Redis engine
 *
 */
#define _GNU_SOURCE
#include <string.h>
#include "../ioengine.h"
#include "hiredis.h"
#include "zmalloc.h"
#include "logger.h"

static int redis_connect(struct ioengine_data *td, const char *args)
{
	redisContext *c;
	char *args2 = zstrdup(args);
	char *sep, *host = args2;
	int port = 6379;

	sep = strchr(args2, ':');
	if (sep) {
		*sep = 0;
		sep++;
		port = atoi(sep);
	}

	c = redisConnect(host, port);
	if (c != NULL && c->err) {
		t01_log(T01_WARNING, "failed to connect %s:%d: %s", 
			host, port, c->errstr);
		zfree(args2);
		return -1;
	}
	td->private = c;
	zfree(args2);
	return 0;
}

static int redis_disconnect(struct ioengine_data *td)
{
	redisContext *c = (redisContext *) td->private;
	redisFree(c);
	return 0;
}

static int redis_ping(struct ioengine_data *td) {
	redisContext *c = (redisContext *)td->private;
	redisReply *reply = (redisReply*)redisCommand(c, "ping");  
	if(reply == NULL) {
		return -1;
	} else {
		freeReplyObject(reply);
		return 0;
	}
}

static int redis_show_help()
{
	printf("--engine-opt=hostname[:port]\n"
	       "hostname   : Hostname for redis engine\n"
	       "port       : Port to use for redis TCP connections\n");
	return 0;
}

static int redis_write(struct ioengine_data *td, const char *args,
			int args_len, const char *buffer, int len, int flush)
{
	redisContext *c = (redisContext *) td->private;
	redisReply *reply;
	const char *v[3];
	size_t vlen[3];

	v[0] = "RPUSH";
	vlen[0] = 5;
	v[1] = args;
	vlen[1] = args_len;
	v[2] = buffer;
	vlen[2] = len;

	if (redisAppendCommandArgv(c, 3, v, vlen) < 0)
		return -1;

	if (flush) {
		int i;
		for (i = 0; i < flush; i++) {
			redisGetReply(c, &reply); 
			if (reply == NULL) {
				continue;
			}
			freeReplyObject(reply);
		}
		return len;
	} else {
		return len;
	}
}

static struct ioengine_ops ioengine = {
	.name = "redis",
	.connect = redis_connect,
	.disconnect = redis_disconnect,
	.ping = redis_ping,
	.show_help = redis_show_help,
	.write = redis_write,
};

static void io_init io_redis_register(void)
{
	register_ioengine(&ioengine);
}

static void io_exit io_redis_unregister(void)
{
	unregister_ioengine(&ioengine);
}

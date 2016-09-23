/*
 * Redis engine
 *
 */
#define _GNU_SOURCE 
#include <string.h>
#include "../ioengine.h"
#include "hiredis.h"

static int redis_connect(struct ioengine_data *td, const char * args)
{
	redisContext *c;
	char *sep, *host = args;
	int port = 6379;

	sep = strchr(args, ':');
	if (sep) {
		*sep = 0;
		sep++;
		port = atoi(sep);
	}

	c = redisConnect(host, port);
      if (c != NULL && c->err) {
		printf("failed to connect %s:%d: %s\n", host, port, c->errstr);
		return -1;
	}
      td->private = c;
	return 0;
}

static int redis_disconnect(struct ioengine_data *td)
{
	redisContext *c = (redisContext *)td->private;
	redisFree(c);
	return 0;
}

static int redis_show_help()
{
	printf("--engine-opt=hostname[:port]\n"
		"hostname   : Hostname for redis engine\n"
		"port       : Port to use for redis TCP connections\n");
	return 0;
}

static int redis_write(struct ioengine_data *td, const char* buffer, int len)
{
	redisContext *c = (redisContext *)td->private;
	redisReply *reply;
	const char *v[3];
	size_t vlen[3];

	v[0] = "RPUSH";
	vlen[0] = 5;
	v[1] = "inqueue";
	vlen[1] = 7;
	v[2] = buffer;
	vlen[2] = len;

      reply = redisCommandArgv(c, 3, v, vlen);
	if(reply){
		freeReplyObject(reply);
		return len;
	}
	return -1;
}

static struct ioengine_ops ioengine = {
	.name		= "redis",
	.connect	= redis_connect,
	.disconnect	= redis_disconnect,
	.show_help	= redis_show_help,
	.write	= redis_write,
};

static void io_init io_redis_register(void)
{
	register_ioengine(&ioengine);
}

static void io_exit io_redis_unregister(void)
{
	unregister_ioengine(&ioengine);
}

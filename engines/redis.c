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

static int redis_init(struct ioengine_data *td, const char *param)
{
    char *args = zstrdup(param), *input = args;
    char *state;
    int port = 6379;
    char *result = NULL;
    int i = 0;
    char *s[3] = {0};

    while((result = strtok_r(input, ":", &state)) != NULL)
    {
        if (i == 3)
            break;
        s[i++] = result;
        input = NULL;
    }
    td->host = i > 0 ? zstrdup(s[0]) : NULL;
    td->port = i > 1 ? atoi(s[1]) : port;
    td->topic = i > 2 ? zstrdup(s[2]) : "raw_queue";

    zfree(args);

    return 0;
}

static int redis_connect(struct ioengine_data *td)
{
	redisContext *c;
	char *host = td->host;
	int port = td->port;
    if (port == 0)
        port = 6379;

	c = redisConnect(host, port);
	if (c != NULL && c->err) {
		t01_log(T01_WARNING, "failed to connect %s:%d: %s", 
			host, port, c->errstr);
		return -1;
	}
	td->private_data = c;
	return 0;
}

static int redis_disconnect(struct ioengine_data *td)
{
	redisContext *c = (redisContext *) td->private_data;
	redisFree(c);
	return 0;
}

static int redis_ping(struct ioengine_data *td) {
	redisContext *c = (redisContext *)td->private_data;
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

static int redis_write(struct ioengine_data *td, const char *buffer, int len, int flush)
{
	redisContext *c = (redisContext *) td->private_data;
	redisReply *reply;
	const char *v[3];
	size_t vlen[3];

	v[0] = "RPUSH";
	vlen[0] = 5;
	v[1] = td->topic;
	vlen[1] = strlen(td->topic);
	v[2] = buffer;
	vlen[2] = len;

	if (redisAppendCommandArgv(c, 3, v, vlen) < 0)
		return -1;

	if (flush) {
		int i;
		for (i = 0; i < flush; i++) {
			redisGetReply(c, (void**)&reply);
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
    .init = redis_init,
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

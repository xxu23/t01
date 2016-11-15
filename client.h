#ifndef CLIENT_H
#define CLIENT_H

#include <arpa/inet.h>
#include <event.h>
#include <http_parser.h>

struct http_header;
struct http_query;

typedef enum {
	LAST_CB_NONE = 0,
	LAST_CB_KEY = 1,
	LAST_CB_VAL = 2} last_cb_t;

typedef enum {
	CLIENT_DISCONNECTED = -1,
	CLIENT_OOM = -2} client_error_t;

struct http_client {

	int fd;
	char ip[16];
	uint16_t port;

	struct event_base *base;
	struct event ev;

	/* HTTP parsing */
	struct http_parser parser;
	struct http_parser_settings settings;
	char *buffer;
	size_t sz;
	size_t request_sz; /* accumulated so far. */
	last_cb_t last_cb;

	/* various flags. */
	char keep_alive;
	char broken;
	char http_version;
	char failed_alloc;

	/* HTTP data */
	char *path;
	size_t path_sz;

	/* headers */
	struct http_header *headers;
	int header_count;

	/* queries */
	struct http_query *queries;
	int query_count;

	char *body;
	size_t body_sz;

	char *type; /* forced output content-type */
	char *jsonp; /* jsonp wrapper */
	char *separator; /* list separator for raw lists */
	char *filename; /* content-disposition */
};

struct http_client *
http_client_new(struct event_base *base, int fd, const char *ip, uint16_t port);

void
http_client_reset(struct http_client *c);

void
http_client_free(struct http_client *c);

int
http_client_read(struct http_client *c);

int
http_client_remove_data(struct http_client *c, size_t sz);

int
http_client_execute(struct http_client *c);

int
http_client_add_to_body(struct http_client *c, const char *at, size_t sz);

const char *
client_get_header(struct http_client *c, const char *key);

void
http_client_can_read(int fd, short event, void *p);

void
http_client_process(struct http_client *c);


#endif

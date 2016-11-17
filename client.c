#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <event.h>
#include <http_parser.h>
#include "client.h"
#include "http.h"
#include "zmalloc.h"
#include "logger.h"

#define CHECK_ALLOC(c, ptr) if(!(ptr)) { c->failed_alloc = 1; return -1;}

static int
http_client_on_url(struct http_parser *p, const char *at, size_t sz) {

	struct http_client *c = p->data;

	CHECK_ALLOC(c, c->path = zrealloc(c->path, c->path_sz + sz + 1));
	memcpy(c->path + c->path_sz, at, sz);
	c->path_sz += sz;
	c->path[c->path_sz] = 0;

	return 0;
}

/*
 * Called when the body is parsed.
 */
static int
http_client_on_body(struct http_parser *p, const char *at, size_t sz) {

	struct http_client *c = p->data;
	return http_client_add_to_body(c, at, sz);
}

int
http_client_add_to_body(struct http_client *c, const char *at, size_t sz) {

	CHECK_ALLOC(c, c->body = zrealloc(c->body, c->body_sz + sz + 1));
	memcpy(c->body + c->body_sz, at, sz);
	c->body_sz += sz;
	c->body[c->body_sz] = 0;

	return 0;
}

static int
http_client_on_header_name(struct http_parser *p, const char *at, size_t sz) {

	struct http_client *c = p->data;
	size_t n = c->header_count;

	/* if we're not adding to the same header name as last time, realloc to add one field. */
	if(c->last_cb != LAST_CB_KEY) {
		n = ++c->header_count;
		CHECK_ALLOC(c, c->headers = zrealloc(c->headers, n * sizeof(struct http_header)));
		memset(&c->headers[n-1], 0, sizeof(struct http_header));
	}

	/* Add data to the current header name. */
	CHECK_ALLOC(c, c->headers[n-1].key = zrealloc(c->headers[n-1].key,
			c->headers[n-1].key_sz + sz + 1));
	memcpy(c->headers[n-1].key + c->headers[n-1].key_sz, at, sz);
	c->headers[n-1].key_sz += sz;
	c->headers[n-1].key[c->headers[n-1].key_sz] = 0;

	c->last_cb = LAST_CB_KEY;

	return 0;
}

static char *
wrap_filename(const char *val, size_t val_len) {

	char format[] = "attachment; filename=\"";
	size_t sz = sizeof(format) - 1 + val_len + 1;
	char *p = zcalloc(sz + 1, 1);

	memcpy(p, format, sizeof(format)-1); /* copy format */
	memcpy(p + sizeof(format)-1, val, val_len); /* copy filename */
	p[sz-1] = '"';

	return p;
}

/*
 * Split query string into key/value pairs, process some of them.
 */
static int
http_client_on_query_string(struct http_parser *parser, const char *at, size_t sz) {

	struct http_client *c = parser->data;
	const char *p = at;
	size_t n = c->query_count;

	while(p < at + sz) {

		const char *key = p, *val;
		int key_len, val_len;
		char *eq = memchr(key, '=', sz - (p-at));
		if(!eq || eq > at + sz) { /* last argument */
			break;
		} else { /* found an '=' */
			char *amp;
			val = eq + 1;
			key_len = eq - key;
			p = eq + 1;

			amp = memchr(p, '&', sz - (p-at));
			if(!amp || amp > at + sz) {
				val_len = at + sz - p; /* last arg */
			} else {
				val_len = amp - val; /* cur arg */
				p = amp + 1;
			}

			/* Add data to the current query value. */
			n = ++c->query_count;
			CHECK_ALLOC(c, c->queries = zrealloc(c->queries, n * sizeof(struct http_query)));
			memset(&c->queries[n-1], 0, sizeof(struct http_query));

			CHECK_ALLOC(c, c->queries[n-1].key = zcalloc(key_len + 1, 1));
			memcpy(c->queries[n-1].key + c->queries[n-1].key_sz, key, key_len);
			c->queries[n-1].key_sz = key_len + 1;
			c->queries[n-1].key[c->queries[n-1].key_sz] = 0;

			CHECK_ALLOC(c, c->queries[n-1].val = zcalloc(val_len + 1, 1));
			memcpy(c->queries[n-1].val + c->queries[n-1].val_sz, val, val_len);
			c->queries[n-1].val_sz = val_len + 1;
			c->queries[n-1].val[c->queries[n-1].val_sz] = 0;


			if(key_len == 4 && strncmp(key, "type", 4) == 0) {
				c->type = zcalloc(1 + val_len, 1);
				memcpy(c->type, val, val_len);
			} else if((key_len == 5 && strncmp(key, "jsonp", 5) == 0)
				|| (key_len == 8 && strncmp(key, "callback", 8) == 0)) {
				c->jsonp = zcalloc(1 + val_len, 1);
				memcpy(c->jsonp, val, val_len);
			} else if(key_len == 3 && strncmp(key, "sep", 3) == 0) {
				c->separator = zcalloc(1 + val_len, 1);
				memcpy(c->separator, val, val_len);
			} else if(key_len == 8 && strncmp(key, "filename", 8) == 0) {
				c->filename = wrap_filename(val, val_len);
			}

			if(!amp) {
				break;
			}
		}
	}
	return 0;
}

static int
http_client_on_header_value(struct http_parser *p, const char *at, size_t sz) {

	struct http_client *c = p->data;
	size_t n = c->header_count;

	/* Add data to the current header value. */
	CHECK_ALLOC(c, c->headers[n-1].val = zrealloc(c->headers[n-1].val,
			c->headers[n-1].val_sz + sz + 1));
	memcpy(c->headers[n-1].val + c->headers[n-1].val_sz, at, sz);
	c->headers[n-1].val_sz += sz;
	c->headers[n-1].val[c->headers[n-1].val_sz] = 0;

	c->last_cb = LAST_CB_VAL;


	/* react to some values. */
	if(strncmp("Expect", c->headers[n-1].key, c->headers[n-1].key_sz) == 0) {
		if(sz == 12 && strncasecmp(at, "100-continue", sz) == 0) {
			/* support HTTP file upload */
			char http100[] = "HTTP/1.1 100 Continue\r\n\r\n";
			int ret = write(c->fd, http100, sizeof(http100)-1);
			(void)ret;
		}
	} else if(strncasecmp("Connection", c->headers[n-1].key, c->headers[n-1].key_sz) == 0) {
		if(sz == 10 && strncasecmp(at, "Keep-Alive", sz) == 0) {
			c->keep_alive = 1;
		}
	}

	return 0;
}

static int
http_client_on_message_complete(struct http_parser *p) {

	struct http_client *c = p->data;

	/* keep-alive detection */
	if (c->parser.flags & F_CONNECTION_CLOSE) {
		c->keep_alive = 0;
	} else if(c->parser.http_major == 1 && c->parser.http_minor == 1) { /* 1.1 */
		c->keep_alive = 1;
	}
	c->http_version = c->parser.http_minor;

	http_client_process(c);
	http_client_reset(c);

	return 0;
}

/**
 * Monitor client FD for possible reads.
 */
void
http_client_monitor_input(struct http_client *c) {

	event_set(&c->ev, c->fd, EV_READ, http_client_can_read, c);
	event_base_set(c->base, &c->ev);
	event_add(&c->ev, NULL);
}

struct http_client *
http_client_new(struct event_base *base, int fd, const char *ip, uint16_t port) {

	struct http_client *c = zcalloc(1, sizeof(struct http_client));

	c->fd = fd;
	c->base = base;
	if(ip) memcpy(c->ip, ip, 16);
	c->port = port;
    
	/* parser */
	http_parser_init(&c->parser, HTTP_REQUEST);
	c->parser.data = c;

	/* callbacks */
	c->settings.on_url = http_client_on_url;
	c->settings.on_query_string = http_client_on_query_string;
	c->settings.on_body = http_client_on_body;
	c->settings.on_message_complete = http_client_on_message_complete;
	c->settings.on_header_field = http_client_on_header_name;
	c->settings.on_header_value = http_client_on_header_value;

	c->last_cb = LAST_CB_NONE;

	http_client_monitor_input(c);

	return c;
}


void
http_client_reset(struct http_client *c) {

	int i;

	/* headers */
	for(i = 0; i < c->header_count; ++i) {
		zfree(c->headers[i].key);
		zfree(c->headers[i].val);
	}
	zfree(c->headers);
	c->headers = NULL;
	c->header_count = 0;

	/* queries */
	for(i = 0; i < c->query_count; ++i) {
		zfree(c->queries[i].key);
		zfree(c->queries[i].val);
	}
	zfree(c->queries);
	c->queries = NULL;
	c->query_count = 0;

	/* other data */
	zfree(c->body); c->body = NULL;
	c->body_sz = 0;
	zfree(c->path); c->path = NULL;
	c->path_sz = 0;
	zfree(c->type); c->type = NULL;
	zfree(c->jsonp); c->jsonp = NULL;
	zfree(c->filename); c->filename = NULL;
	c->request_sz = 0;

	/* no last known header callback */
	c->last_cb = LAST_CB_NONE;

	/* mark as broken if client doesn't support Keep-Alive. */
	if(c->keep_alive == 0) {
		c->broken = 1;
	}
}

void
http_client_free(struct http_client *c) {

	/*if(c->el && c->fd != -1) {
		aeDeleteFileEvent(c->el, c->fd, AE_READABLE);
		aeDeleteFileEvent(c->el, c->fd, AE_WRITABLE);
	}*/
	close(c->fd);
	http_client_reset(c);
	zfree(c->buffer);
	zfree(c);
}

int
http_client_read(struct http_client *c) {

	char buffer[4096] = {0};
	int ret;

	ret = read(c->fd, buffer, sizeof(buffer));
	if(ret <= 0) {
		/* broken link, free buffer and client object */
		t01_log(T01_DEBUG, "Client %s:%d [fd=%d] disconnect", c->ip, c->port, c->fd);
		http_client_free(c);
		return (int)CLIENT_DISCONNECTED;
	}

	/* save what we've just read */
	c->buffer = zrealloc(c->buffer, c->sz + ret);
	if(!c->buffer) {
		return (int)CLIENT_OOM;
	}
	memcpy(c->buffer + c->sz, buffer, ret);
	c->sz += ret;
	c->buffer[c->sz] = 0;

	/* keep track of total sent */
	c->request_sz += ret;

	return ret;
}

int
http_client_remove_data(struct http_client *c, size_t sz) {

	char *buffer;
	if(c->sz < sz)
		return -1;

	/* replace buffer */
	CHECK_ALLOC(c, buffer = zmalloc(c->sz - sz));
	memcpy(buffer, c->buffer + sz, c->sz - sz);
	zfree(c->buffer);
	c->buffer = buffer;
	c->sz -= sz;

	return 0;
}

int
http_client_execute(struct http_client *c) {

	int nparsed = http_parser_execute(&c->parser, &c->settings, c->buffer, c->sz);
	
	/* removed consumed data, all has been copied already. */
	zfree(c->buffer);
	c->buffer = NULL;
	c->sz = 0;
	
	return nparsed;
}

/*
 * Find header value, returns NULL if not found.
 */
const char *
client_get_header(struct http_client *c, const char *key) {

	int i;
	size_t sz = strlen(key);

	for(i = 0; i < c->header_count; ++i) {

		if(sz == c->headers[i].key_sz &&
			strncasecmp(key, c->headers[i].key, sz) == 0) {
			return c->headers[i].val;
		}

	}

	return NULL;
}

void
http_client_can_read(int fd, short event, void *p) {

	struct http_client *c = p;
	int ret, nparsed;

	(void)fd;

	ret = http_client_read(c);
	if(ret <= 0) {
		if((client_error_t)ret == CLIENT_DISCONNECTED) {
			return;
		} else if (c->failed_alloc || (client_error_t)ret == CLIENT_OOM) {
			http_send_error(c, 503, "Service Unavailable");
			return;
		}
	}
	
	/* run parser */
	nparsed = http_client_execute(c);
	
	if(c->failed_alloc) {
		c->broken = 1;
		http_send_error(c, 503, "Service Unavailable");
	} else if (c->parser.flags & F_CONNECTION_CLOSE) {
		c->broken = 1;
	} else if(nparsed != ret) {
		c->broken = 1;
		http_send_error(c, 400, "Bad Request");
	} 

	if(c->broken) { /* terminate client */
		t01_log(T01_DEBUG, "Terminate client %s:%d", c->ip, c->port);
		http_client_free(c);
	} else {
		/* start monitoring input again */
		http_client_monitor_input(c);
	}
}

/**
 * Called when a client has finished reading input and can create a cmd
 */
void
http_client_process(struct http_client *c) {

	/* check that the command can be executed */
	int ret;
	char *path = 1+c->path;
	size_t path_sz = c->path_sz-1;
	char *qmark = memchr(path, '?', path_sz);
	if(qmark) path_sz = qmark - path;

	switch(c->parser.method) {
		case HTTP_GET:
			t01_log(T01_DEBUG, "GET %s", c->path);
			ret = cmd_run_get(c, path, path_sz);
			break;

		case HTTP_POST:
			t01_log(T01_NOTICE, "POST %s", c->path);
			ret = cmd_run_post(c, path, path_sz, c->body, c->body_sz);
			break;

		case HTTP_PUT:
			t01_log(T01_NOTICE, "PUT %s", c->path);
			ret = cmd_run_put(c, path, path_sz, c->body, c->body_sz);
			break;

		case HTTP_DELETE:
			t01_log(T01_NOTICE, "DELETE %s", c->path);
			ret = cmd_run_delete(c, path, path_sz);
			break;

		case HTTP_OPTIONS:
			http_send_options(c);
			return;

		default:
			http_send_error(c, 405, "Method Not Allowed");
			return;
	}
}


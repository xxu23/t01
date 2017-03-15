/*
 * Copyright (c) 2016, YAO Wei <njustyw at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>

#include <evhttp.h>
#include "t01.h"
#undef offsetof
#include "list.h"
#include "anet.h"
#include "networking.h"
#include "rule.h"
#include "http.h"
#include "client.h"
#include "zmalloc.h"
#include "cJSON.h"
#include "logger.h"

#define MAX_ACCEPTS_PER_CALL 1000

static ZLIST_HEAD(slave_list);

struct slave_client {
	struct list_head list;
	int online;
	char ip[16];
	int port;
	int id;
	uint64_t cksum;
	uint64_t hits;
};

static void mark_slave_offline(const char *ip, int port)
{
	struct list_head *pos;
	list_for_each(pos, &slave_list) {
		struct slave_client *s =
		    list_entry(pos, struct slave_client, list);
		if (strcmp(s->ip, ip) == 0 && s->port == port) {
			s->online = 0;
			break;
		}
	}
}

void udp_server_can_read(int fd, short event, void *ptr)
{
	struct sockaddr_in addr;
	socklen_t len;
	int nread;
	struct log_rz lr;

	if ((nread =
	     recvfrom(fd, &lr, sizeof(lr), 0, (struct sockaddr *)&addr,
		      &len)) <= 0)
		return;
	else if (nread != sizeof(lr))
		return;

	if (lr.local_ip == 0)
		lr.local_ip = addr.sin_addr.s_addr;

	add_log_rz(&lr);
}

void server_can_accept(int fd, short event, void *ptr)
{
	int cport, cfd, max = MAX_ACCEPTS_PER_CALL;
	char cip[16];
	char err[ANET_ERR_LEN];

	while (max--) {
		cfd = anetTcpAccept(err, fd, cip, sizeof(cip), &cport);
		if (cfd == ANET_ERR) {
			if (errno != EWOULDBLOCK)
				t01_log(T01_WARNING,
					"Accepting client connection: %s", err);
			return;
		}
		t01_log(T01_DEBUG, "Accepted %s:%d [fd=%d]", cip, cport, cfd);
		http_client_new(base, cfd, cip, cport);
	}
}

struct cmd {
	struct http_client *client;
	int count;
	char **argv;
	size_t *argv_len;
	const char *body;
	size_t body_len;
};

static struct cmd *cmd_new(struct http_client *client, int count,
			   const char *body, size_t body_len)
{
	struct cmd *c = zcalloc(1, sizeof(struct cmd));
	if (!c)
		return NULL;

	c->client = client;
	c->count = count;
	c->argv = zcalloc(count, sizeof(char *));
	c->argv_len = zcalloc(count, sizeof(size_t));
	c->body = body;
	c->body_len = body_len;

	return c;
}

void cmd_free(struct cmd *c)
{
	int i;
	if (!c)
		return;

	for (i = 0; i < c->count; ++i) {
		zfree((char *)c->argv[i]);
	}
}

static char *decode_uri(const char *uri, size_t length, size_t * out_len,
			int always_decode_plus)
{
	char c;
	size_t i, j;
	int in_query = always_decode_plus;
	char *ret = zmalloc(length + 1);
	bzero(ret, length + 1);

	for (i = j = 0; i < length; i++) {
		c = uri[i];
		if (c == '?') {
			in_query = 1;
		} else if (c == '+' && in_query) {
			c = ' ';
		} else if (c == '%' && isxdigit((unsigned char)uri[i + 1]) &&
			   isxdigit((unsigned char)uri[i + 2])) {
			char tmp[] = { uri[i + 1], uri[i + 2], '\0' };
			c = (char)strtol(tmp, NULL, 16);
			i += 2;
		}
		ret[j++] = c;
	}
	*out_len = (size_t) j;

	return ret;
}

static struct cmd *cmd_init(struct http_client *c, const char *uri,
			    size_t uri_len, const char *body, size_t body_len)
{
	char *slash;
	const char *p, *cmd_name = uri;
	int cmd_len;
	int param_count = 0, cur_param = 1, i;
	struct cmd *cmd = NULL;

	for (p = uri; p && p < uri + uri_len; param_count++) {
		p = memchr(p + 1, '/', uri_len - (p + 1 - uri));
	}

	if (param_count == 0) {
		return NULL;
	}

	cmd = cmd_new(c, param_count, body, body_len);
	if (!cmd)
		return NULL;

	/* check if we only have one command or more. */
	slash = memchr(uri, '/', uri_len);
	if (slash) {
		cmd_len = slash - uri;
	} else {
		cmd_len = uri_len;
	}

	/* there is always a first parameter, it's the command name */
	cmd->argv[0] = zmalloc(cmd_len + 1);
	if (cmd->argv[0] == NULL) {
		zfree(cmd);
		return NULL;
	}
	memcpy(cmd->argv[0], cmd_name, cmd_len);
	cmd->argv[0][cmd_len] = 0;
	cmd->argv_len[0] = cmd_len + 1;

	p = cmd_name + cmd_len + 1;
	while (p < uri + uri_len) {
		const char *arg = p;
		int arg_len;
		char *next = memchr(arg, '/', uri_len - (arg - uri));
		if (!next || next > uri + uri_len) {	/* last argument */
			p = uri + uri_len;
			arg_len = p - arg;
		} else {	/* found a slash */
			arg_len = next - arg;
			p = next + 1;
		}

		/* record argument */
		if (arg_len > 0) {
			cmd->argv[cur_param] =
			    decode_uri(arg, arg_len, &cmd->argv_len[cur_param],
				       1);
			if (cmd->argv[cur_param] == NULL) {
				for (i = 0; i < cur_param; i++) 
					zfree(cmd->argv[i]);
				zfree(cmd);
				return NULL; 
			}
			cur_param++;
		}
	}

	for (i = cur_param; i < cmd->count; i++) {
		zfree(cmd->argv[i]);
		cmd->argv[i] = NULL;
		cmd->argv_len[i] = 0;
	}
	cmd->count = cur_param;

	return cmd;
}

static void send_client_reply(struct http_client *c, const char *p,
			      size_t sz, const char *content_type)
{
	const char *ct = content_type;
	struct http_response *resp;

	resp = http_response_init(c->base, 200, "OK");
	http_response_set_header(resp, "Content-Type", ct);
	http_response_set_body(resp, p, sz);
	http_response_set_keep_alive(resp, 1);
	http_response_write(resp, c->fd);
}

static int client_get_rule(struct http_client *c, struct cmd *cmd)
{
	uint32_t id = atoi(cmd->argv[1]);
	char *result = NULL;
	size_t len = 0;
	int ret = get_rule(id, &result, &len);
	if (ret == 0) {
		send_client_reply(c, result, len, "application/json");
		release_buffer(&result);
	} else {
		http_send_error(c, 404, "Not Found");
	}
	return ret;
}

static int client_enable_rule(struct http_client *c, struct cmd *cmd)
{
	uint32_t id = atoi(cmd->argv[1]);
	int ret = enable_rule(id);
	if (ret == 0) {
		send_client_reply(c, NULL, 0, "application/json");
	} else {
		http_send_error(c, 404, "Not Found");
	}
	return ret;
}

static int client_disable_rule(struct http_client *c, struct cmd *cmd)
{
	uint32_t id = atoi(cmd->argv[1]);
	int ret = disable_rule(id);
	if (ret == 0) {
		send_client_reply(c, NULL, 0, "application/json");
	} else {
		http_send_error(c, 404, "Not Found");
	}
	return ret;
}

static int client_get_ruleids(struct http_client *c, struct cmd *cmd)
{
	char *result = NULL;
	size_t len = 0;
	int32_t type = -1, offset = 0, limit = 0;
	int query_count = c->query_count, i;
	
	for (i = 0; i < query_count; i++) {
		if (strcasecmp(c->queries[i].key, "type") == 0)
			type = atoi(c->queries[i].val);
		else if (strcasecmp(c->queries[i].key, "offset") == 0)
			offset = atoi(c->queries[i].val);
		else if (strcasecmp(c->queries[i].key, "limit") == 0)
			limit = atoi(c->queries[i].val);
	}

	get_ruleids(type, offset, limit, &result, &len, 1);

	send_client_reply(c, result, len, "application/json");
	release_buffer(&result);

	return 0;
}

static int client_get_rules(struct http_client *c, struct cmd *cmd)
{
	int n = c->query_count, i, j = 0;
	uint32_t *ids = zmalloc(n * sizeof(uint32_t));
	char *result = NULL;
	size_t len = 0;

	for (i = 0; i < n; i++) {
		if (strcasecmp(c->queries[i].key, "id") == 0)
			ids[j++] = atoi(c->queries[i].val);
	}
	get_rules(ids, j, &result, &len);
	send_client_reply(c, result, len, "application/json");
	release_buffer(&result);

	return 0;
}

static int client_get_summary(struct http_client *c, struct cmd *cmd)
{
	int type = 0;
	int query_count = c->query_count, i, ret;
	char *result = NULL;
	size_t len = 0;

	for (i = 0; i < query_count; i++) {
		if (strcasecmp(c->queries[i].key, "type") == 0)
			type = atoi(c->queries[i].val);
	}
	
	ret = get_summary(type, &result, &len);
	if (ret == 0) {
		send_client_reply(c, result, len, "application/json");
		release_buffer(&result);
	} else {
		http_send_error(c, 404, "Not Found");
	}

	return ret;
}

static int client_get_hits(struct http_client *c, struct cmd *cmd)
{
	const int MAX_LIMIT = 100;
	int offset = 0, limit = MAX_LIMIT;
	uint32_t rule_id = 0;
	int query_count = c->query_count, i, j = 0;
	char *result = NULL;
	size_t len = 0;
	int ret;

	for (i = 0; i < query_count; i++) {
		if (strcasecmp(c->queries[i].key, "rule_id") == 0)
			rule_id = atoi(c->queries[i].val);
		else if (strcasecmp(c->queries[i].key, "offset") == 0)
			offset = atoi(c->queries[i].val);
		else if (strcasecmp(c->queries[i].key, "limit") == 0)
			limit = atoi(c->queries[i].val);
	}
	if (offset < 0)
		offset = 0;
	if (limit <= 0 || limit > MAX_LIMIT)
		limit = MAX_LIMIT;

	ret = get_hits(rule_id, offset, limit, &result, &len);
	if (ret == 0) {
		send_client_reply(c, result, len, "application/json");
		release_buffer(&result);
	} else {
		http_send_error(c, 404, "Not Found");
	}

	return ret;
}

void master_sync_rule_cb(struct evhttp_request *req, void *arg)
{
	struct evhttp_connection *conn = arg;
	char *address;
	uint16_t port;
	int code;

	evhttp_connection_get_peer(conn, &address, &port);
	if (!req) {
		t01_log(T01_WARNING, "Failed to connect to slave %s:%d",
			address, port);
		evhttp_connection_free(conn);
		mark_slave_offline(address, port);
		return;
	}

	code = evhttp_request_get_response_code(req);
	if (code == 200) {
		t01_log(T01_WARNING, "Succeed to sync rule with slave %s:%d",
			address, port);
	} else {
		if (code == 0)
			mark_slave_offline(address, port);
		t01_log(T01_WARNING, "Failed to sync rule with slave %s:%d",
			address, port);
	}
}

static void sync_slaves_rules(const char *path, int method,
			      const char *body, size_t len)
{
	struct list_head *pos;
	struct evhttp_connection *conn;
	struct evhttp_request *req;
	struct evbuffer *buffer;
	char buf[32];

	list_for_each(pos, &slave_list) {
		struct slave_client *s =
		    list_entry(pos, struct slave_client, list);
		if (s->online == 0)
			continue;
		t01_log(T01_NOTICE, "Connect slave[%s:%d] to sync rule", s->ip,
			s->port);

		conn = evhttp_connection_base_new(base, NULL, s->ip, s->port);
		req = evhttp_request_new(master_sync_rule_cb, conn);
		buffer = evhttp_request_get_output_buffer(req);

		evhttp_connection_free_on_completion(conn);
		evhttp_connection_set_timeout(conn, 5);
		evhttp_add_header(req->output_headers, "Connection",
				  "Keep-Alive");

		if (body && len) {
			evbuffer_add(buffer, body, len);
			evutil_snprintf(buf, sizeof(buf) - 1, "%lu",
					(unsigned long)len);
			evhttp_add_header(req->output_headers, "Content-Length",
					  buf);
		}

		evhttp_make_request(conn, req, method, path);
	}
}

static int client_create_rule(struct http_client *c, struct cmd *cmd)
{
	char *result = NULL;
	size_t len = 0;
	int ret = create_rule(cmd->body, cmd->body_len, &result, &len);
	if (ret == 0) {
		if (tconfig.work_mode & MASTER_MODE)
			sync_slaves_rules("/rules", EVHTTP_REQ_POST, result,
					  len);
		send_client_reply(c, result, len, "application/json");
		release_buffer(&result);
	} else {
		http_send_error(c, 400, "Bad Request");
	}
	return ret;
}

static int client_update_rule(struct http_client *c, struct cmd *cmd)
{
	uint32_t id = atoi(cmd->argv[1]);
	int ret = update_rule(id, cmd->body, cmd->body_len);
	if (ret == 0) {
		if (tconfig.work_mode & MASTER_MODE) {
			char path[128];
			snprintf(path, sizeof(path), "/rule/%u", id);
			sync_slaves_rules(path, EVHTTP_REQ_PUT, cmd->body,
					  cmd->body_len);
		}
		send_client_reply(c, NULL, 0, "application/json");
	} else {
		http_send_error(c, 400, "Bad Request");
	}
	return ret;
}

static int client_delete_rule(struct http_client *c, struct cmd *cmd)
{
	uint32_t id = atoi(cmd->argv[1]);
	int ret = delete_rule(id);
	if (ret == 0) {
		if (tconfig.work_mode & MASTER_MODE) {
			char path[128];
			snprintf(path, sizeof(path), "/rule/%u", id);
			sync_slaves_rules(path, EVHTTP_REQ_DELETE, NULL, 0);
		}
		send_client_reply(c, NULL, 0, "application/json");
	} else {
		http_send_error(c, 400, "Bad Request");
	}
	return ret;
}

static int client_get_server_info(struct http_client *c, struct cmd *cmd)
{
	cJSON *root = cJSON_CreateObject();
	char *result;
	uint64_t total_rules, enabled_rules;

	cJSON_AddNumberToObject(root, "upstart", upstart);
	cJSON_AddNumberToObject(root, "now", time(NULL));
	cJSON_AddNumberToObject(root, "used_memory", zmalloc_used_memory());

	calc_rules(&total_rules, &enabled_rules);
	cJSON_AddNumberToObject(root, "total_rules", total_rules);
	cJSON_AddNumberToObject(root, "enabled_rules", enabled_rules);

	if (tconfig.work_mode & NETMAP_MODE) {
		cJSON_AddStringToObject(root, "iface", tconfig.ifname);
		cJSON_AddStringToObject(root, "oface",
					tconfig.ofname[0] ? tconfig.
					ofname : tconfig.ifname);
		if (tconfig.mfname[0])
			cJSON_AddStringToObject(root, "mface", tconfig.mfname);
		cJSON_AddNumberToObject(root, "total_pkts_in", ip_packet_count);
		cJSON_AddNumberToObject(root, "total_pkts_out",
					ip_packet_count_out);
		cJSON_AddNumberToObject(root, "total_bytes_in", total_ip_bytes);
		cJSON_AddNumberToObject(root, "total_bytes_out",
					total_ip_bytes_out);
		cJSON_AddNumberToObject(root, "avg_pkts_in",
					pkts_per_second_in);
		cJSON_AddNumberToObject(root, "avg_pkts_out",
					pkts_per_second_out);
		cJSON_AddNumberToObject(root, "avg_bytes_in",
					bytes_per_second_in);
		cJSON_AddNumberToObject(root, "avg_bytes_out",
					bytes_per_second_out);
		cJSON_AddNumberToObject(root, "hits", hits);
		cJSON_AddNumberToObject(root, "id", tconfig.id);
	} else {
		struct list_head *pos;
		cJSON *array = cJSON_CreateArray(), *item;
		struct slave_client *s;
		uint64_t hits1 = 0, hits2 = calc_totalhits();

		list_for_each(pos, &slave_list) {
			s = list_entry(pos, struct slave_client, list);
			item = cJSON_CreateObject();
			cJSON_AddStringToObject(item, "ip", s->ip);
			cJSON_AddNumberToObject(item, "port", s->port);
			cJSON_AddNumberToObject(item, "online", s->online);
			cJSON_AddNumberToObject(item, "id", s->id);
			cJSON_AddItemToArray(array, item);
			hits1 += s->hits;
		}
		cJSON_AddItemToObject(root, "nodes", array);

		if (hits1 < hits2)
			hits1 = hits2;
		cJSON_AddNumberToObject(root, "hits", hits1);
	}

	result = cJSON_PrintUnformatted(root);
	send_client_reply(c, result, strlen(result), "application/json");

	cJSON_Delete(root);
	cJSON_FreePrint(result);
	return 0;
}

struct master_ev_args {
	struct evhttp_connection *conn;
	struct http_client *client;
};

void master_get_sinfo_cb(struct evhttp_request *req, void *arg)
{
	struct master_ev_args *ev_arg = arg;
	struct evhttp_connection *conn = ev_arg->conn;
	struct http_client *client = ev_arg->client;
	char *address;
	uint16_t port;
	int code;

	evhttp_connection_get_peer(conn, &address, &port);
	if (!req) {
		t01_log(T01_WARNING, "Failed to connect to slave %s:%d",
			address, port);
		evhttp_connection_free(conn);
		mark_slave_offline(address, port);
		zfree(ev_arg);
		return;
	}

	code = evhttp_request_get_response_code(req);
	if (code == 200) {
		size_t len = evbuffer_get_length(req->input_buffer);
		unsigned char *str = evbuffer_pullup(req->input_buffer, len);
		send_client_reply(client, str, len, "application/json");
	} else {
		if (code == 0)
			mark_slave_offline(address, port);
		t01_log(T01_WARNING, "Failed to sync rule with slave %s:%d",
			address, port);
	}
	zfree(ev_arg);
}

static int client_get_slave_info(struct http_client *c, struct cmd *cmd)
{
	char ip[48] = { 0 };
	int port = 0;
	int query_count = c->query_count, i, j = 0;
	struct evhttp_connection *conn;
	struct evhttp_request *req;
	struct evbuffer *buffer;
	struct master_ev_args *arg;

	if (tconfig.work_mode & NETMAP_MODE) {
		http_send_error(c, 400, "Bad Request");
		return 0;
	}

	for (i = 0; i < query_count; i++) {
		if (strcasecmp(c->queries[i].key, "ip") == 0)
			strncpy(ip, c->queries[i].val, sizeof(ip));
		else if (strcasecmp(c->queries[i].key, "port") == 0)
			port = atoi(c->queries[i].val);
	}
	if (port <= 0 || port >= 65535 || ip[0] == 0 || inet_addr(ip) == -1) {
		http_send_error(c, 400, "Bad Request");
		return 0;
	}

	arg = zmalloc(sizeof(*arg));
	conn = evhttp_connection_base_new(base, NULL, ip, port);
	req = evhttp_request_new(master_get_sinfo_cb, arg);
	arg->conn = conn;
	arg->client = c;
	evhttp_connection_free_on_completion(conn);
	evhttp_connection_set_timeout(conn, 5);
	evhttp_add_header(req->output_headers, "Connection", "Keep-Alive");
	evhttp_make_request(conn, req, EVHTTP_REQ_GET, "/info");

	return 0;
}

static int client_sync_rules(struct http_client *c, struct cmd *cmd)
{
	int ret = sync_rules(cmd->body, cmd->body_len);
	if (ret == 0) {
		send_client_reply(c, NULL, 0, "application/json");
	} else {
		http_send_error(c, 400, "Bad Request");
	}
	return ret;
}

static int client_registry_cluster(struct http_client *c, struct cmd *cmd)
{
	int i;
	int slave_port = 0, id = 0;
	uint64_t cksum = 0;
	uint64_t shits = 0;
	struct list_head *pos;
	struct slave_client *slave = NULL;

	for (i = 0; i < c->query_count; i++) {
		if (strcasecmp(c->queries[i].key, "port") == 0)
			slave_port = atoi(c->queries[i].val);
		else if (strcasecmp(c->queries[i].key, "id") == 0)
                        id = atoi(c->queries[i].val);
		else if (strcasecmp(c->queries[i].key, "crc64") == 0)
			sscanf(c->queries[i].val, "%llx", &cksum);
		else if (strcasecmp(c->queries[i].key, "hits") == 0)
                        sscanf(c->queries[i].val, "%llx", &shits);
	}

	if (slave_port <= 0 || slave_port >= 65535) {
		http_send_error(c, 400, "Bad Request");
		return -1;
	}

	list_for_each(pos, &slave_list) {
		struct slave_client *s =
		    list_entry(pos, struct slave_client, list);
		if (strcmp(s->ip, c->ip) == 0 && s->port == slave_port) {
			slave = s;
			break;
		}
	}
	if (!slave) {
		slave = zcalloc(1, sizeof(*slave));
		strncpy(slave->ip, c->ip, sizeof(slave->ip));
		slave->port = slave_port;
		list_add_tail(&slave->list, &slave_list);
		t01_log(T01_NOTICE, "Slave client %s:%d join", c->ip,
			slave_port);
	}
	slave->cksum = cksum;
	slave->id = id;
	slave->hits = shits;
	slave->online = 1;

	send_client_reply(c, NULL, 0, "application/json");
	return 0;
}

static struct http_cmd_table {
	int method;
	const char *command;
	size_t params;
	int (*action) (struct http_client * client, struct cmd * cmd);
} tables[] = {
	{
	HTTP_GET, "rule", 1, client_get_rule}, {
	HTTP_GET, "ruleids", 0, client_get_ruleids}, {
	HTTP_GET, "rules", 0, client_get_rules}, {
	HTTP_GET, "hits", 0, client_get_hits}, {
	HTTP_POST, "rules", 0, client_create_rule}, {
	HTTP_POST, "enablerule", 1, client_enable_rule}, {
	HTTP_POST, "disablerule", 1, client_disable_rule}, {
	HTTP_PUT, "rule", 1, client_update_rule}, {
	HTTP_DELETE, "rule", 1, client_delete_rule}, {
	HTTP_GET, "summary", 0, client_get_summary}, {
	HTTP_GET, "info", 0, client_get_server_info}, {
	HTTP_GET, "sinfo", 0, client_get_slave_info}, {
	HTTP_POST, "registry", 0, client_registry_cluster}, {
	HTTP_GET, "registry", 0, client_registry_cluster}, {
HTTP_POST, "rulessync", 0, client_sync_rules},};

static void cmd_dispatch(struct http_client *c, struct cmd *cmd, int method)
{
	int i;
	struct http_cmd_table *which = NULL;
	if (!cmd) {
		http_send_error(c, 404, "Not Found");
		return;
	}

	for (i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
		if (tables[i].method == method &&
		    tables[i].params == cmd->count - 1 &&
		    strcasecmp(tables[i].command, cmd->argv[0]) == 0) {
			which = &tables[i];
			break;
		}
	}

	if (which == NULL) {
		http_send_error(c, 404, "Not Found");
	} else {
		int ret = which->action(c, cmd);
	}
}

int cmd_run_get(struct http_client *c, const char *uri, size_t uri_len)
{
	struct cmd *cmd = cmd_init(c, uri, uri_len, NULL, 0);
	if (!cmd)
		return -1;

	cmd_dispatch(c, cmd, HTTP_GET);
	cmd_free(cmd);

	return 0;
}

int cmd_run_post(struct http_client *c, const char *uri, size_t uri_len,
		 const char *body, size_t body_len)
{
	struct cmd *cmd = cmd_init(c, uri, uri_len, body, body_len);
	if (!cmd)
		return -1;

	cmd_dispatch(c, cmd, HTTP_POST);
	cmd_free(cmd);

	return 0;
}

int cmd_run_put(struct http_client *c, const char *uri, size_t uri_len,
		const char *body, size_t body_len)
{
	struct cmd *cmd = cmd_init(c, uri, uri_len, body, body_len);
	if (!cmd)
		return -1;

	cmd_dispatch(c, cmd, HTTP_PUT);
	cmd_free(cmd);

	return 0;
}

int cmd_run_delete(struct http_client *c, const char *uri, size_t uri_len)
{
	struct cmd *cmd = cmd_init(c, uri, uri_len, NULL, 0);
	if (!cmd)
		return -1;

	cmd_dispatch(c, cmd, HTTP_DELETE);
	cmd_free(cmd);

	return 0;
}

void slave_request_cb(struct evhttp_request *req, void *arg)
{
	struct evhttp_connection *conn = arg;
	if (!req) {
		evhttp_connection_free(conn);
		return;
	}
}

int slave_registry_master(const char *master_ip, int master_port, int self_port)
{
	struct evhttp_connection *conn;
	struct evhttp_request *req;
	uint64_t cksum = calc_crc64_rules();
	char path[1024];

	conn = evhttp_connection_base_new(base, NULL, master_ip, master_port);
	req = evhttp_request_new(slave_request_cb, conn);
	evhttp_connection_free_on_completion(conn);
	evhttp_connection_set_timeout(conn, 5);
	evhttp_add_header(req->output_headers, "Connection", "Keep-Alive");
	snprintf(path, 1024, "/registry?port=%d&crc64=%llx&id=%d&hits=%llx", self_port, cksum, tconfig.id, hits);
	evhttp_make_request(conn, req, EVHTTP_REQ_GET, path);

	return 0;
}

void master_request_syncrules_cb(struct evhttp_request *req, void *arg)
{
	struct evhttp_connection *conn = arg;
	char *address;
	uint16_t port;
	int code;

	evhttp_connection_get_peer(conn, &address, &port);
	if (!req) {
		t01_log(T01_WARNING, "Failed to connect to slave %s:%d",
			address, port);
		evhttp_connection_free(conn);
		mark_slave_offline(address, port);
		return;
	}

	code = evhttp_request_get_response_code(req);
	if (code == 200) {
		t01_log(T01_WARNING, "Succeed to sync rules with slave %s:%d",
			address, port);
	} else {
		if (code == 0)
			mark_slave_offline(address, port);
		t01_log(T01_WARNING, "Failed to sync rules with slave %s:%d",
			address, port);
	}
}

int master_check_slaves()
{
	uint64_t cksum = calc_crc64_rules();
	struct list_head *pos;
	struct evhttp_connection *conn;
	struct evhttp_request *req;
	struct evbuffer *buffer;
	uint32_t *ids = NULL;
	size_t len = 0, len2 = 0;
	char *rules = NULL;
	char buf[32];

	list_for_each(pos, &slave_list) {
		struct slave_client *s =
		    list_entry(pos, struct slave_client, list);
		if (s->online == 0 || s->cksum == cksum)
			continue;

		t01_log(T01_NOTICE,
			"CRC not match: master %llx VS slave[%s:%d] %llx",
			cksum, s->ip, s->port, s->cksum);

		if (!ids && get_ruleids(0, 0, 0, (char **)&ids, &len, 0) < 0)
			continue;
		len /= sizeof(uint32_t);
		if (!rules && get_rules(ids, len, &rules, &len2) < 0)
			continue;

		conn = evhttp_connection_base_new(base, NULL, s->ip, s->port);
		req = evhttp_request_new(master_request_syncrules_cb, conn);
		buffer = evhttp_request_get_output_buffer(req);

		evhttp_connection_free_on_completion(conn);
		evhttp_connection_set_timeout(conn, 5);
		evhttp_add_header(req->output_headers, "Connection",
				  "Keep-Alive");

		evbuffer_add(buffer, rules, len2);
		evutil_snprintf(buf, sizeof(buf) - 1, "%lu",
				(unsigned long)len2);
		evhttp_add_header(req->output_headers, "Content-Length", buf);

		evhttp_make_request(conn, req, EVHTTP_REQ_POST, "/rulessync");
	}
}

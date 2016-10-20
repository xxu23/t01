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
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include "t01.h"
#include "ae.h"
#include "anet.h"
#include "networking.h"
#include "rule.h"
#include "http.h"
#include "client.h"
#include "zmalloc.h"
#include "cJSON.h"
#include "logger.h"

#define MAX_ACCEPTS_PER_CALL 1000

void tcp_server_can_accept(aeEventLoop * el, int fd, void *privdata, int mask)
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
		t01_log(T01_NOTICE, "Accepted %s:%d [fd=%d]", cip, cport, cfd);
		http_client_new(el, cfd, cip, cport);
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
	struct cmd *c = calloc(1, sizeof(struct cmd));

	c->client = client;
	c->count = count;
	c->argv = calloc(count, sizeof(char *));
	c->argv_len = calloc(count, sizeof(size_t));
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
		free((char *)c->argv[i]);
	}
}

static char *decode_uri(const char *uri, size_t length, size_t * out_len,
			int always_decode_plus)
{
	char c;
	size_t i, j;
	int in_query = always_decode_plus;
	char *ret = malloc(length + 1);

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

	/* check if we only have one command or more. */
	slash = memchr(uri, '/', uri_len);
	if (slash) {
		cmd_len = slash - uri;
	} else {
		cmd_len = uri_len;
	}

	/* there is always a first parameter, it's the command name */
	cmd->argv[0] = malloc(cmd_len + 1);
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
			cur_param++;
		}
	}

	for (i = cur_param; i < cmd->count; i++) {
		free(cmd->argv[i]);
		cmd->argv[i] = NULL;
		cmd->argv_len[i] = 0;
	}
	cmd->count = cur_param;

	return cmd;
}

static void send_client_reply(struct cmd *cmd, const char *p, size_t sz,
			      const char *content_type)
{
	const char *ct = content_type;
	struct http_response *resp;

	resp = http_response_init(200, "OK");
	http_response_set_header(resp, "Content-Type", ct);
	http_response_set_body(resp, p, sz);
	http_response_set_keep_alive(resp, 1);
	http_response_write(resp, cmd->client->fd);
}

static int client_get_rule(struct http_client *c, struct cmd *cmd)
{
	uint32_t id = atoi(cmd->argv[1]);
	char *result = NULL;
	size_t len = 0;
	int ret = get_rule(id, &result, &len);
	if (ret == 0) {
		send_client_reply(cmd, result, len, "application/json");
		release_buffer(&result);
	} else {
		http_send_error(c, 404, "Not Found");
	}
	return ret;
}

static int client_get_ruleids(struct http_client *c, struct cmd *cmd)
{
	char *result = NULL;
	size_t len = 0;
	get_ruleids(&result, &len);

	send_client_reply(cmd, result, len, "application/json");
	release_buffer(&result);

	return 0;
}

static int client_get_rules(struct http_client *c, struct cmd *cmd)
{
	int n = c->query_count, i, j = 0;
	uint32_t *ids = malloc(n * sizeof(uint32_t));
	char *result = NULL;
	size_t len = 0;

	for (i = 0; i < n; i++) {
		if (strcasecmp(c->queries[i].key, "id") == 0)
			ids[j++] = atoi(c->queries[i].val);
	}
	get_rules(ids, j, &result, &len);
	send_client_reply(cmd, result, len, "application/json");
	release_buffer(&result);

	return 0;
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
	if(offset < 0) offset = 0;
	if(limit <= 0 || limit > MAX_LIMIT) limit = MAX_LIMIT;

	ret = get_hits(rule_id, offset, limit, &result, &len);
	if(ret == 0){
		send_client_reply(cmd, result, len, "application/json");
		release_buffer(&result);
	} else {
		http_send_error(c, 404, "Not Found");	
	}

	return ret;
}

static int client_create_rule(struct http_client *c, struct cmd *cmd)
{
	char *result = NULL;
	size_t len = 0;
	int ret = create_rule(cmd->body, cmd->body_len, &result, &len);
	if (ret == 0) {
		send_client_reply(cmd, result, len, "application/json");
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
		send_client_reply(cmd, NULL, 0, "application/json");
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
		send_client_reply(cmd, NULL, 0, "application/json");
	} else {
		http_send_error(c, 400, "Bad Request");
	}
	return ret;
}

static int client_get_server_info(struct http_client *c, struct cmd *cmd)
{
	cJSON *root = cJSON_CreateObject();
	char *result;
	
	cJSON_AddStringToObject(root, "iface", ifname);
	cJSON_AddStringToObject(root, "oface", ofname[0]?ofname:ifname);
	cJSON_AddNumberToObject(root, "upstart", upstart);
	cJSON_AddNumberToObject(root, "now", time(NULL));
	cJSON_AddNumberToObject(root, "total_pkts_in", ip_packet_count);
	cJSON_AddNumberToObject(root, "total_pkts_out", ip_packet_count_out);
	cJSON_AddNumberToObject(root, "total_bytes_in", total_ip_bytes);
	cJSON_AddNumberToObject(root, "total_bytes_out", total_ip_bytes_out);
	cJSON_AddNumberToObject(root, "avg_pkts_in", pkts_per_second_in);
	cJSON_AddNumberToObject(root, "avg_pkts_out", pkts_per_second_out);
	cJSON_AddNumberToObject(root, "avg_bytes_in", bytes_per_second_in);
	cJSON_AddNumberToObject(root, "avg_bytes_out", bytes_per_second_out);
	cJSON_AddNumberToObject(root, "hits", hits);
	
	result = cJSON_Print(root);
	send_client_reply(cmd, result, strlen(result), "application/json");

	cJSON_Delete(root);
	cJSON_FreePrint(result);
	return 0;
}

static struct http_cmd_table {
	int method;
	const char *command;
	size_t params;
	int (*action) (struct http_client * client, struct cmd * cmd);
} tables[] = {
	{ HTTP_GET, "rule", 1, client_get_rule}, 
	{ HTTP_GET, "ruleids", 0, client_get_ruleids}, 
	{ HTTP_GET, "rules", 0, client_get_rules}, 
	{ HTTP_GET, "hits", 0, client_get_hits}, 
	{ HTTP_POST, "rules", 0, client_create_rule}, 
	{ HTTP_PUT, "rule", 1, client_update_rule}, 
	{ HTTP_DELETE, "rule", 1, client_delete_rule},
	{ HTTP_GET, "info", 0, client_get_server_info},
};

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

	cmd_dispatch(c, cmd, HTTP_GET);
	cmd_free(cmd);

	return 0;
}

int cmd_run_post(struct http_client *c, const char *uri, size_t uri_len,
		 const char *body, size_t body_len)
{
	struct cmd *cmd = cmd_init(c, uri, uri_len, body, body_len);

	cmd_dispatch(c, cmd, HTTP_POST);
	cmd_free(cmd);

	return 0;
}

int cmd_run_put(struct http_client *c, const char *uri, size_t uri_len,
		const char *body, size_t body_len)
{
	struct cmd *cmd = cmd_init(c, uri, uri_len, body, body_len);

	cmd_dispatch(c, cmd, HTTP_PUT);
	cmd_free(cmd);

	return 0;
}

int cmd_run_delete(struct http_client *c, const char *uri, size_t uri_len)
{
	struct cmd *cmd = cmd_init(c, uri, uri_len, NULL, 0);

	cmd_dispatch(c, cmd, HTTP_DELETE);
	cmd_free(cmd);

	return 0;
}

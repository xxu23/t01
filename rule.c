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
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "t01.h"
#include "rule.h"
#include "cJSON.h"
#include "ndpi_api.h"
#include "ndpi_util.h"
#include "ndpi_protocol_ids.h"
#include "logger.h"
#include "zmalloc.h"

#define T01_TDB_VERSION 1

#define T01_TDB_TYPE_RULE 1
#define T01_TDB_TYPE_HIT  2
#define T01_TDB_TYPE_EOF  255

#define MAX_HITS_PER_RULE 5000

static uint32_t max_id;

static inline uint8_t get_action(const char *action)
{
	if (strcmp(action, "reject") == 0)
		return T01_ACTION_REJECT;
	else if (strcmp(action, "redirect") == 0)
		return T01_ACTION_REDIRECT;
	else if (strcmp(action, "confuse") == 0)
		return T01_ACTION_CONFUSE;
	return 0;
}

static inline uint8_t get_protocol(const char *protocol, uint8_t * master,
				   NDPI_PROTOCOL_BITMASK * mask)
{
	int prot = 0;
	if (strcasecmp(protocol, "http") == 0) {
		*master = NDPI_PROTOCOL_HTTP;
		prot = IPPROTO_TCP;
	} else if (strcasecmp(protocol, "https") == 0) {
		*master = NDPI_PROTOCOL_SSL;
		prot = IPPROTO_TCP;
	} else if (strcasecmp(protocol, "dns") == 0) {
		*master = NDPI_PROTOCOL_DNS;
		prot = IPPROTO_UDP;
	} else if (strcasecmp(protocol, "ssh") == 0) {
		*master = NDPI_PROTOCOL_SSH;
		prot = IPPROTO_TCP;
	} else if (strcasecmp(protocol, "icmp") == 0) {
		*master = NDPI_PROTOCOL_IP_ICMP;
		prot = IPPROTO_ICMP;
	} else if (strcasecmp(protocol, "icmpv6") == 0) {
		*master = NDPI_PROTOCOL_IP_ICMPV6;
		prot = IPPROTO_ICMPV6;
	} else if (strcasecmp(protocol, "ipsec") == 0) {
		*master = NDPI_PROTOCOL_IP_IPSEC;
		prot = IPPROTO_IP;
	} else if (strcasecmp(protocol, "pptp") == 0) {
		*master = NDPI_PROTOCOL_PPTP;
		prot = IPPROTO_TCP;
	} else if (strcasecmp(protocol, "socks") == 0) {
		*master = NDPI_PROTOCOL_SOCKS;
		prot = IPPROTO_UDP;
	} else if (strcasecmp(protocol, "dhcp") == 0) {
		*master = NDPI_PROTOCOL_DHCP;
		prot = IPPROTO_UDP;
	} else if (strcasecmp(protocol, "tcp") == 0) {
		*master = 0;
		prot = IPPROTO_TCP;
	} else if (strcasecmp(protocol, "udp") == 0) {
		*master = 0;
		prot = IPPROTO_UDP;
	}
	if (mask && *master)
		NDPI_BITMASK_ADD(*mask, *master);
	return prot;
}

static void strrpl(char *pDstOut, const char *pSrcIn, const char *pSrcRpl,
		   const char *pDstRpl)
{
	const char *pi = pSrcIn;
	char *po = pDstOut;
	int nSrcRplLen = strlen(pSrcRpl);
	int nDstRplLen = strlen(pDstRpl);
	char *p = NULL;
	int nLen = 0;

	do {
		p = strstr(pi, pSrcRpl);
		if (p != NULL) {
			nLen = p - pi;
			memcpy(po, pi, nLen);
			memcpy(po + nLen, pDstRpl, nDstRplLen);
		} else {
			strcpy(po, pi);
			break;
		}

		pi = p + nSrcRplLen;
		po = po + nLen + nDstRplLen;
	} while (p != NULL);
}

static inline get_ip(const char *ip, u_int32_t * start, u_int32_t * end)
{
	if (strchr(ip, '*')) {
		char ip1[16], ip2[16];
		strrpl(ip1, ip, "*", "1");
		strrpl(ip2, ip, "*", "255");
		*start = inet_addr(ip1);
		*end = inet_addr(ip2);
		return 2;
	} else {
		*start = *end = inet_addr(ip);
		return 1;
	}
}

static int tdb_write_raw(FILE * fp, void *p, size_t len)
{
	len = fwrite(p, 1, len, fp);
	if (len < 0)
		return -1;
	return len;
}

static int tdb_load_raw(FILE * fp, void *p, size_t len)
{
	if (fread(p, 1, len, fp) < len)
		return -1;
	return len;
}

static int tdb_save_type(FILE * fp, unsigned char type)
{
	return tdb_write_raw(fp, &type, 1);
}

static int tdb_save_rule(FILE * fp, struct rule *r)
{
	return tdb_write_raw(fp, r, (char *)&r->list - (char *)r);
}

static int tdb_save_hit(FILE * fp, struct hit_record *h)
{
	return tdb_write_raw(fp, h, (char *)&h->list - (char *)h);
}

static int tdb_load_type(FILE * fp)
{
	unsigned char type;
	if (fread(&type, 1, 1, fp) <= 0)
		return -1;
	return type;
}

static int tdb_load_rule(FILE * fp, struct rule *r)
{
	size_t len = (char *)&r->list - (char *)r;
	if (fread(r, 1, len, fp) < len)
		return -1;
	return len;
}

static int tdb_load_hit(FILE * fp, struct hit_record *h)
{
	size_t len = (char *)&h->list - (char *)h;
	if (fread(h, 1, len, fp) < len)
		return -1;
	return len;
}

void transform_one_rule(struct rule *rule, NDPI_PROTOCOL_BITMASK * mask)
{
	if (rule->human_saddr[0])
		get_ip(rule->human_saddr, &rule->saddr0, &rule->saddr1);

	if (rule->human_daddr[0])
		get_ip(rule->human_daddr, &rule->daddr0, &rule->daddr1);

	if (rule->human_protocol[0])
		rule->protocol =
		    get_protocol(rule->human_protocol, &(rule->master_protocol),
				 mask);

	if (rule->human_action[0])
		rule->action = get_action(rule->human_action);
}

#define get_string_from_json(item, json, key, value) 	\
  item = cJSON_GetObjectItem(json, key); 			\
  if(item){ 							\
    strncpy(value, item->valuestring, sizeof(value));	\
  }									\

#define get_int_from_json(item, json, key, value) 	\
  item = cJSON_GetObjectItem(json, key); 		\
  if(item){ 							\
    value = item->valueint;                             \
  }									\

#define get_string_from_arrayjson(item, json, j, value) 	\
  item = cJSON_GetArrayItem(json, j);				\
  if(item) {								\
    strncpy(value[j], item->valuestring, sizeof(value[j]));	\
  }										\

static void parse_one_rule(cJSON *json, struct rule *rule)
{
	cJSON *item, *parent;

	get_string_from_json(item, json, "protocol", rule->human_protocol);
	get_string_from_json(item, json, "saddr", rule->human_saddr);
	get_string_from_json(item, json, "daddr", rule->human_daddr);
	get_int_from_json(item, json, "sport", rule->sport);
	get_int_from_json(item, json, "dport", rule->dport);
	get_int_from_json(item, json, "id", rule->id);

	parent = cJSON_GetObjectItem(json, "condition");
	if (parent) {
		get_string_from_json(item, parent, "host",
				     rule->condition.host);
	}

	get_string_from_json(item, json, "action", rule->human_action);

	parent = cJSON_GetObjectItem(json, "params");
	if (parent) {
		int m = cJSON_GetArraySize(parent);
		if (m <= 4) {
			int j;
			for (j = 0; j < m; j++) {
				get_string_from_arrayjson(item, parent, j,
							  rule->action_params);
			}
		}
	}
}

static int load_rules_from_json(const char *data, struct list_head *head,
				void *ndpi_mask)
{
	NDPI_PROTOCOL_BITMASK *mask = (NDPI_PROTOCOL_BITMASK *) ndpi_mask;
	cJSON *json = cJSON_Parse(data);
	if (!json) {
		t01_log(T01_WARNING, "Cannot parse json: %s",
			cJSON_GetErrorPtr());
		return -3;
	}

	char *msg = NULL;
	int ret = 0;
	int n = cJSON_GetArraySize(json);
	if (n == 0)
		goto out;

	int i;
	for (i = 0; i < n; i++) {
		cJSON *item = cJSON_GetArrayItem(json, i);
		if (!item) {
			t01_log(T01_WARNING, "Cannot parse json: %s",
				cJSON_GetErrorPtr());
			continue;
		}

		struct rule *rule = malloc(sizeof(*rule));
		if (!rule) {
			msg = "Out of memory";
			ret = -2;
			goto out;
		}
		bzero(rule, sizeof(*rule));
		INIT_LIST_HEAD(&rule->hit_head);

		parse_one_rule(item, rule);
		transform_one_rule(rule, mask);
		rule->used = 1;
		list_add_tail(&rule->list, head);
		if (rule->id == 0)
			rule->id = ++max_id;
		else if (rule->id > max_id)
			max_id = rule->id;
	}
	ret = n;

out:
	cJSON_Delete(json);
	if (ret < 0)
		t01_log(T01_WARNING, "Cannot parse json: %s", msg);
	return ret;
}

int load_rules(const char *filename, void *ndpi_mask)
{
	uint32_t dbid;
	int type, tdbver, i = 0;
	char buf[8];
	FILE *fp;
	struct rule *curr_rule;

	fp = fopen(filename, "r");
	if (fp == NULL)
		return -1;

	if (tdb_load_raw(fp, buf, 8) == 0)
		goto eoferr;

	if (memcmp(buf, "T01", 3) != 0 && memcmp(buf, "[", 1) != 0) {
		fclose(fp);
		t01_log(T01_WARNING,
			"Wrong signature trying to load DB from file");
		return -1;
	}

	if (memcmp(buf, "[", 1) == 0) {
		long size;
		char *data;
		int ret;

		fseek(fp, 0, SEEK_END);
		size = ftell(fp) + 8;
		fseek(fp, 0, SEEK_SET);
		data = (char *)malloc(size + 1);
		if (!data) {
			t01_log(T01_WARNING, "Out of memory!");
			goto eoferr;
		}
		fread(data, 1, size, fp);
		data[size] = '\0';
		fclose(fp);

		ret = load_rules_from_json(data, &rule_list, ndpi_mask);
		free(data);
		return ret;
	}

	tdbver = atoi(buf + 3);
	if (tdbver != T01_TDB_VERSION) {
		fclose(fp);
		t01_log(T01_WARNING, "Can't handle TDB format version %d",
			tdbver);
		return -1;
	}

	while (1) {
		if ((type = tdb_load_type(fp)) == -1)
			break;

		if (type == T01_TDB_TYPE_RULE) {
			struct rule *r = malloc(sizeof(*r));
			if (!r)
				goto eoferr;
			bzero(r, sizeof(*r));
			INIT_LIST_HEAD(&r->hit_head);
			if (tdb_load_rule(fp, r) == -1)
				goto eoferr;
			list_add_tail(&r->list, &rule_list);
			curr_rule = r;
			r->saved_hits = 0;
			i++;
			if (r->id > max_id) max_id = r->id;
		} else if (type == T01_TDB_TYPE_HIT) {
			struct hit_record *h = malloc(sizeof(*h));
			if (!h)
				goto eoferr;
			bzero(h, sizeof(*h));
			if (tdb_load_hit(fp, h) == -1)
				goto eoferr;
			if (curr_rule->saved_hits == MAX_HITS_PER_RULE) {
				free(h);
				continue;
			}
			list_add_tail(&h->list, &curr_rule->hit_head);
			curr_rule->saved_hits++;
		} else if (type == T01_TDB_TYPE_EOF) {
			break;
		}
	}

	fclose(fp);
	return i;

eoferr:			/* unexpected end of file is handled here with a fatal exit */
	t01_log(T01_WARNING,
		"Short read or OOM loading DB. Unrecoverable error, aborting now.");
	exit(1);
	return -1;
}

int add_one_hit_record(struct rule *r, uint64_t time,
		       uint32_t saddr, uint32_t daddr,
		       uint16_t sport, uint16_t dport,
		       uint8_t smac[], uint8_t dmac[])
{
	struct hit_record *h = malloc(sizeof(*h));
	if (!h)
		return -1;
	bzero(h, sizeof(*h));

	h->id = r->id;
	h->time = time;
	h->saddr = saddr;
	h->daddr = daddr;
	h->sport = sport;
	h->dport = dport;
	memcpy(h->smac, smac, 6);
	memcpy(h->dmac, dmac, 6);

	if (r->saved_hits == MAX_HITS_PER_RULE) {
		struct list_head *head = r->hit_head.next;
		struct hit_record *hh =
		    list_entry(head, struct hit_record, list);
		r->saved_hits--;
		list_del(head);
		free(hh);
	}

	list_add_tail(&h->list, &r->hit_head);
	r->hits++;
	r->saved_hits++;
	dirty++;

	return 0;
}

void destroy_rules()
{
	if (list_empty(&rule_list))
		return;

	struct list_head *pos, *n, *pos2, *n2, *hhead;
	struct rule *rule;
	struct hit_record *hit;

	list_for_each_safe(pos, n, &rule_list) {
		list_del(pos);
		rule = list_entry(pos, struct rule, list);
		hhead = &rule->hit_head;
		if (list_empty(hhead) == 0)
		list_for_each_safe(pos2, n2, hhead) {
			list_del(pos2);
			hit = list_entry(pos2, struct hit_record, list);
			free(hit);
		}
		free(rule);
	}
}

int save_rules(const char *filename)
{
	char tmpfile[256];
	FILE *fp;
	char magic[8];
	struct list_head *pos;
	struct rule *rule;

	snprintf(tmpfile, 256, "temp-%d.tdb", (int)getpid());
	fp = fopen(tmpfile, "w");
	if (!fp) {
		t01_log(T01_WARNING, "Failed opening .tdb for saving: %s",
			strerror(errno));
		return -1;
	}

	snprintf(magic, sizeof(magic), "T01%04d", T01_TDB_VERSION);
	if (tdb_write_raw(fp, magic, 8) == -1)
		goto werr;

	list_for_each(pos, &rule_list) {
		struct list_head *pos2;
		struct hit_record *hit;
		rule = list_entry(pos, struct rule, list);
		if (rule->used == 0)
			continue;

		if (tdb_save_type(fp, T01_TDB_TYPE_RULE) < 0)
			goto werr;
		if (tdb_save_rule(fp, rule) < 0)
			goto werr;

		list_for_each(pos2, &rule->hit_head) {
			hit = list_entry(pos2, struct hit_record, list);
			if (tdb_save_type(fp, T01_TDB_TYPE_HIT) < 0)
				goto werr;
			if (tdb_save_hit(fp, hit) < 0)
				goto werr;
		}
	}
	if (tdb_save_type(fp, T01_TDB_TYPE_EOF) < 0)
		goto werr;

	/* Make sure data will not remain on the OS's output buffers */
	if (fflush(fp) == EOF)
		goto werr;
	if (fsync(fileno(fp)) == -1)
		goto werr;
	if (fclose(fp) == EOF)
		goto werr;

	/* Use RENAME to make sure the DB file is changed atomically only
	 * if the generate DB file is ok. */
	if (rename(tmpfile, filename) == -1) {
		t01_log(T01_WARNING,
			"Error moving temp DB file on the final destination: %s",
			strerror(errno));
		unlink(tmpfile);
		return -1;
	}

	t01_log(T01_NOTICE, "DB saved on disk");
	dirty = 0;
	lastsave = time(NULL);
	lastbgsave_status = 0;
	return 0;

werr:
	t01_log(T01_WARNING, "Write error saving DB on disk: %s",
		strerror(errno));
	fclose(fp);
	unlink(tmpfile);
	return -1;
}

int save_rules_background(const char *filename)
{
	pid_t childpid;
	long long start;

	if (tdb_child_pid != -1)
		return -1;

	dirty_before_bgsave = dirty;

	if ((childpid = fork()) == 0) {
		int retval;
		/* Child */
		close_listening_sockets();
		retval = save_rules(filename);
		_exit((retval == 0) ? 0 : 1);
	} else {
		/* Parent */
		if (childpid == -1) {
			lastbgsave_status = -1;
			t01_log(T01_WARNING,
				"Can't save in background: fork: %s",
				strerror(errno));
			return -1;
		}
		t01_log(T01_NOTICE, "Background saving started by pid %d",
			childpid);
		//server.rdb_save_time_start = time(NULL);
		tdb_child_pid = childpid;
		return 0;
	}
	return 0;		/* unreached */
}

static void tdb_remove_tempfile(pid_t childpid)
{
	char tmpfile[256];
	snprintf(tmpfile, 256, "temp-%d.tdb", (int)childpid);
	unlink(tmpfile);
}

void background_save_done_handler(int exitcode, int bysignal)
{
	if (!bysignal && exitcode == 0) {
		t01_log(T01_NOTICE,
			"Background saving terminated with success");
		dirty = dirty - dirty_before_bgsave;
		lastsave = time(NULL);
		lastbgsave_status = 0;
	} else if (!bysignal && exitcode != 0) {
		t01_log(T01_WARNING, "Background saving error");
		lastbgsave_status = -1;
	} else {
		t01_log(T01_WARNING,
			"Background saving terminated by signal %d", bysignal);
		tdb_remove_tempfile(tdb_child_pid);
		if (bysignal != SIGUSR1)
			lastbgsave_status = -1;
	}

	tdb_child_pid = -1;
}

void release_buffer(char **out)
{
	if (*out)
		free(*out);
}

static cJSON *rule2cjson(struct rule *rule)
{
	cJSON *root = cJSON_CreateObject(), *array;
	int n = 0, i;
	const char *strings[4] = { rule->action_params[0],
		rule->action_params[1],
		rule->action_params[1],
		rule->action_params[3]
	};

	cJSON_AddNumberToObject(root, "id", rule->id);
	if (rule->human_protocol[0])
		cJSON_AddStringToObject(root, "protocol", rule->human_protocol);
	if (rule->human_saddr[0])
		cJSON_AddStringToObject(root, "saddr", rule->human_saddr);
	if (rule->human_daddr[0])
		cJSON_AddStringToObject(root, "daddr", rule->human_daddr);
	if (rule->human_action[0])
		cJSON_AddStringToObject(root, "action", rule->human_action);
	if (rule->condition.host[0])
		cJSON_AddStringToObject(root, "condition",
					rule->condition.host);
	if (rule->sport)
		cJSON_AddNumberToObject(root, "sport", rule->sport);
	if (rule->dport)
		cJSON_AddNumberToObject(root, "dport", rule->dport);

	for (i = 0;
	     i < sizeof(rule->action_params) / sizeof(rule->action_params[0]);
	     i++) {
		if (rule->action_params[i][0] == 0)
			break;
		n++;
	}
	if (n > 0) {
		array = cJSON_CreateStringArray(strings, n);
		cJSON_AddItemToObject(root, "params", array);
	}

	return root;
}

static char *cjson2string(cJSON * root)
{
	char *render, *result;

	render = cJSON_Print(root);
	result = malloc(strlen(render) + 1);
	strcpy(result, render);
	cJSON_Delete(root);
	cJSON_FreePrint(render);

	return result;

}

static char *rule2jsonstr(struct rule *rule)
{
	cJSON *root = rule2cjson(rule);
	return cjson2string(root);
}

int get_ruleids(char **out, size_t * out_len)
{
	uint32_t *ids;
	struct list_head *pos;
	int n = 0, i = 0;
	list_for_each(pos, &rule_list) {
		struct rule *rule = list_entry(pos, struct rule, list);
		if (rule->used == 0)
			continue;
		n++;
	}

	ids = (uint32_t *) malloc(sizeof(uint32_t) * n);
	bzero(ids, sizeof(uint32_t) * n);
	if (!ids)
		return -1;
	list_for_each(pos, &rule_list) {
		struct rule *rule = list_entry(pos, struct rule, list);
		if (rule->used == 0)
			continue;
		ids[i++] = rule->id;
	}

	cJSON *array = cJSON_CreateIntArray((int *)ids, n);
	*out = cjson2string(array);
	*out_len = strlen(*out);

	return 0;
}

int get_rule(uint32_t id, char **out, size_t * out_len)
{
	struct list_head *pos;
	struct rule *rule = NULL;
	list_for_each(pos, &rule_list) {
		struct rule *rule2 = list_entry(pos, struct rule, list);
		if (rule2->id == id && rule2->used == 1) {
			rule = rule2;
			break;
		}
	}

	if (!rule)
		return -1;

	*out = rule2jsonstr(rule);
	*out_len = strlen(*out);

	return 0;
}

int get_rules(uint32_t * ids, size_t len, char **out, size_t * out_len)
{
	int i;
	struct list_head *pos;
	cJSON *root = cJSON_CreateArray();

	list_for_each(pos, &rule_list) {
		struct rule *rule = list_entry(pos, struct rule, list);
		if (rule->used == 0)
			continue;
		for (i = 0; i < len; i++) {
			if (rule->id == ids[i]) {
				cJSON_AddItemToArray(root, rule2cjson(rule));
				break;
			}
		}
	}

	*out = cjson2string(root);
	*out_len = strlen(*out);

	return 0;
}

static cJSON *hit2cjson(struct hit_record *hit)
{
	cJSON *root = cJSON_CreateObject();
	int n = 0, i;
	char ip[48];

	cJSON_AddNumberToObject(root, "id", hit->id);
	cJSON_AddNumberToObject(root, "time", hit->time);
	if (hit->sport)
		cJSON_AddNumberToObject(root, "sport", hit->sport);
	if (hit->dport)
		cJSON_AddNumberToObject(root, "dport", hit->dport);

	if (hit->saddr) {
		inet_ntop(AF_INET, &hit->saddr, ip, sizeof(ip));
		cJSON_AddStringToObject(root, "saddr", ip);
	}

	if (hit->daddr) {
		inet_ntop(AF_INET, &hit->daddr, ip, sizeof(ip));
		cJSON_AddStringToObject(root, "daddr", ip);
	}

	sprintf(ip, "%02x-%02x-%02x-%02x-%02x-%02x",
		hit->smac[0], hit->smac[1], hit->smac[2],
		hit->smac[3], hit->smac[4], hit->smac[5]);
	cJSON_AddStringToObject(root, "smac", ip);

	sprintf(ip, "%02x-%02x-%02x-%02x-%02x-%02x",
		hit->dmac[0], hit->dmac[1], hit->dmac[2],
		hit->dmac[3], hit->dmac[4], hit->dmac[5]);
	cJSON_AddStringToObject(root, "dmac", ip);

	return root;
}

int get_hits(uint32_t rule_id, int offset, int limit, char **out,
	     size_t * out_len)
{
	struct list_head *pos;
	struct rule *rule = NULL;
	struct hit_record *hit;
	cJSON *root = cJSON_CreateArray();
	int i = 0;

	list_for_each(pos, &rule_list) {
		struct rule *rule2 = list_entry(pos, struct rule, list);
		if (rule2->id == rule_id && rule2->used == 1) {
			rule = rule2;
			break;
		}
	}

	if (!rule )
		return -1;

	list_for_each(pos, &rule->hit_head) {
		if (i++ < offset)
			continue;
		hit = list_entry(pos, struct hit_record, list);
		printf("rule %p hit %p\n", rule, hit);
		cJSON_AddItemToArray(root, hit2cjson(hit));
		if (--limit == 0)
			break;
	}

	*out = cjson2string(root);
	*out_len = strlen(*out);

	return 0;
}

int update_rule(uint32_t id, const char *body, int body_len)
{
	struct list_head *pos;
	struct rule new_rule;	
	cJSON *root = cJSON_Parse(body);
	if (!root) {
		t01_log(T01_WARNING, "Cannot parse json: %s",
			cJSON_GetErrorPtr());
		return -1;
	}
	bzero(&new_rule, sizeof(new_rule));
	parse_one_rule(root, &new_rule);
	new_rule.id = id;
	cJSON_Delete(root);

	list_for_each(pos, &rule_list) {
		struct rule *rule = list_entry(pos, struct rule, list);
		if (rule->id == id && rule->used == 1) {
			memcpy(rule, &new_rule, offsetof(struct rule, protocol));
			transform_one_rule(rule, NULL);
			return 0;
		}
	}
	return -1;
}

int delete_rule(uint32_t id)
{
	struct list_head *pos, *n;
	struct rule *rule;
	struct hit_record *hit;
	list_for_each_safe(pos, n, &rule_list) {
		rule = list_entry(pos, struct rule, list);
		if (rule->id == id && rule->used == 1) {
			struct list_head *pos2, *n2, *hhead;
			hhead = &rule->hit_head;
			rule->used = 0;
			if (list_empty(hhead) == 0)
			list_for_each_safe(pos2, n2, hhead) {
				list_del(pos2);
				hit = list_entry(pos2, struct hit_record, list);
				free(hit);
			}
			bzero(rule, offsetof(struct rule, list));
			return 0;
		}
	}

	return -1;
}

int create_rule(const char *body, int body_len, char **out, size_t *out_len)
{
	int offset;
	struct rule src_rule, *new_rule = NULL;
	struct list_head *pos;
	cJSON *root;

	root = cJSON_Parse(body);
	if (!root) {
		t01_log(T01_WARNING, "Cannot parse json: %s",
			cJSON_GetErrorPtr());
		return -1;
	}
	bzero(&src_rule, sizeof(src_rule));
	parse_one_rule(root, &src_rule);
	cJSON_Delete(root);

	/* Find a recycled rule */
	list_for_each(pos, &rule_list) {
		struct rule *rule = list_entry(pos, struct rule, list);
		if (rule->used == 0) {
			new_rule = rule;
			break;
		}
	}

	/* Not found, malloc a rule*/
	if (!new_rule) {
		new_rule = malloc(sizeof(*new_rule));
		if (!new_rule) {
			return -1;
		}
		bzero(new_rule, sizeof(*new_rule));
		INIT_LIST_HEAD(&new_rule->hit_head);
		list_add_tail(&new_rule->list, &rule_list);
	}

	memcpy(new_rule, &src_rule, offsetof(struct rule, protocol));
	transform_one_rule(new_rule, NULL);
	new_rule->used = 1;
	new_rule->id = ++max_id;

	root = cJSON_CreateObject();
	cJSON_AddNumberToObject(root, "id", new_rule->id);
	*out = cjson2string(root);
	*out_len = strlen(*out);

	return 0;
}

struct rule *match_rule_from_packet(void *flow_, void *packet)
{
	struct ndpi_flow_info *flow = (struct ndpi_flow_info *)flow_;
	struct list_head *pos;
	list_for_each(pos, &rule_list) {
		struct rule *rule = list_entry(pos, struct rule, list);
		if (rule->used == 0)
			continue;

		if (flow->protocol == NDPI_PROTOCOL_UNKNOWN)
			continue;

		if (rule->protocol != flow->protocol)
			continue;

		if (rule->master_protocol) {
			uint8_t master_protocol =
			    flow->detected_protocol.master_protocol;
			if (master_protocol == 0)
				master_protocol =
				    flow->detected_protocol.protocol;
			if (master_protocol != rule->master_protocol)
				continue;
		}

		if (rule->dport || rule->sport || rule->daddr0 || rule->saddr0) {
			if (rule->dport && rule->dport != flow->dst_port)
				continue;
			if (rule->daddr0
			    && (flow->dst_ip < rule->daddr0
				|| flow->dst_ip > rule->daddr1))
				continue;
			if (rule->sport && rule->sport != flow->src_port)
				continue;
			if (rule->saddr0
			    && (flow->src_ip < rule->saddr0
				|| flow->src_ip > rule->saddr1))
				continue;
		}

		char *host = flow->host_server_name;
		if (host[0] == 0 || flow->ssl.client_certificate[0] != 0
		    || flow->ssl.server_certificate[0] != 0)
			host =
			    flow->ssl.client_certificate[0] ==
			    0 ? flow->ssl.server_certificate : flow->ssl.
			    client_certificate;
		if (rule->condition.host[0]
		    && strcasecmp(rule->condition.host, host) != 0)
			continue;

		return rule;
	}

	return NULL;
}

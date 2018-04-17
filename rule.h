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

/* inclusion guard */
#ifndef __RULE_H__
#define __RULE_H__

#include "list.h"

#define HITS_THRESHOLD_PER_SECOND 3000

#ifdef __cplusplus
extern "C" {
#endif

extern uint64_t version;

struct log_rz
{	
	uint8_t smac[6];
	uint8_t dmac[6];
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t local_ip;
	uint32_t time;
	uint32_t rule_id;
	uint8_t rule_type:4;
	uint8_t rule_action:4;
	uint8_t proto;
	uint16_t pktlen;
};

struct hit_record {
	uint32_t id;
	uint32_t rule_id;
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	uint8_t smac[6];
	uint8_t dmac[6];
	uint64_t time;
	uint32_t localip;
	uint8_t proto;
	uint16_t pktlen;
	struct list_head list;
};

#pragma pack(1)
struct rule {
	uint32_t id;
	char padding[4];
	uint64_t version;	
	char human_protocol[16];
	char human_saddr[16];
	char human_daddr[16];
	char human_action[16];
	char human_match[16];
	char human_which[16];
	char description[144];
	char payload[256];
	char action_params[256];
	uint16_t sport;
	uint16_t dport;
	int type;
	uint8_t protocol;
	uint8_t master_protocol;
	uint8_t which:4;
	uint8_t match:4;
	uint8_t used:2;
	uint8_t disabled:2;
	uint8_t action:4;
	uint32_t saddr0, saddr1;
	uint32_t daddr0, daddr1;
	uint32_t saved_hits;
	uint64_t hits;
	struct list_head list;
	struct list_head hit_head;
};
#pragma pack()

#define T01_ACTION_REDIRECT 		1
#define T01_ACTION_REJECT		2
#define T01_ACTION_CONFUSE		3
#define T01_ACTION_MIRROR		4

#define T01_WHICH_HOST 			1
#define T01_WHICH_URL			2

#define T01_MATCH_MATCH 		1
#define T01_MATCH_REGEX			2

int init_rules(int hsize);

int load_rules(const char *filename);

int save_rules(const char *filename);

int save_rules_background(const char *filename);

void destroy_rules();

uint64_t calc_crc64_rules();

uint64_t calc_totalhits();

void calc_rules(uint64_t *total, uint64_t *enabled);

struct ndpi_flow_info;
struct rule *match_rule_after_detected(struct ndpi_flow_info *flow);

struct rule *match_rule_from_htable_after_detected(struct ndpi_flow_info *flow);

struct rule *match_rule_before_mirrored(struct ndpi_flow_info *flow);

int add_hit_record(struct rule *r, uint64_t time, uint32_t saddr,
	 		uint32_t daddr, uint16_t sport, uint16_t dport,
			uint8_t smac[], uint8_t dmac[], uint32_t localip,
			uint8_t proto, uint16_t pktlen);

int add_log_rz(struct log_rz *lr);

void release_buffer(char **out);

int get_ruleids(int type, uint8_t match, uint8_t disabled, uint8_t action,
		const char *kw, int offset, int limit, 
		char **out, size_t *out_len, int json);

int get_rule(uint32_t id, char **out, size_t *out_len);

int disable_rule(uint32_t id);

int enable_rule(uint32_t id);

int get_summary(int type, char **out, size_t *out_len);

int get_rules(uint32_t *id, size_t len, char **out, size_t *out_len);

int get_hits(uint32_t rule_id, int offset, int limit, char **out,
	     size_t *out_len);

int delete_rule(uint32_t id);

int update_rule(uint32_t id, const char *body, int body_len);

int create_rule(const char *body, int body_len, char **out, size_t *out_len);

int sync_rules(const char *body, int body_len);

void background_save_done_handler(int exitcode, int bysignal);

#ifdef __cplusplus
extern "C" {
#endif

#endif /* __RULE_H__ */
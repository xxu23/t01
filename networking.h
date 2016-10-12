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
#ifndef __NETWORKING_H__
#define __NETWORKING_H__

struct t01_header
{
	char magic[4];
	uint8_t command;
	int8_t response; 
	uint16_t seq;
	int body_len;
	char body[0];
};

#define T01_HEADER_MAGIC	"T01"

#define INIT_T01_HEADER(cmd, resp) {T01_HEADER_MAGIC, cmd, resp, 0, 0}
#define IS_HEADER_VALID(hdr) (memcmp(T01_HEADER_MAGIC, (hdr).magic, 3) == 0)

#define T01_COMMAND_GET_RULE 	1
#define T01_COMMAND_PUT_RULE 	2
#define T01_COMMAND_DEL_RULE 	3
#define T01_COMMAND_ADD_RULE 	4
#define T01_COMMAND_GET_RULES 	5

#define T01_ERR_NOTFOUND		-1
#define T01_ERR_NOTSUPPORT	-2
#define T01_ERR_INTERNAL		-3


struct t01_rule
{
	uint32_t id;
	char human_protocol[16];
	char human_saddr[16];
	char human_daddr[16];
	uint16_t sport;
	uint16_t dport;
	char human_action[16];
	char match_payload[256];
	char action_params[4][256];
};

/* Networking and Client related operations */

void acceptHandler(aeEventLoop *el, int fd, void *privdata, int mask);
void acceptTcpHandler(aeEventLoop *el, int fd, void *privdata, int mask);
void acceptUnixHandler(aeEventLoop *el, int fd, void *privdata, int mask);
void readQueryFromClient(aeEventLoop *el, int fd, void *privdata, int mask);


#endif /* __NETWORKING_H__ */

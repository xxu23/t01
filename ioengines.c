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
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <assert.h>

#include "ioengine.h"
#include "ndpi_api.h"
#include "ndpi_util.h"
#include "zmalloc.h"
#include "msgpack.h"
#include "logger.h"

static LIST_HEAD(engine_list);

void unregister_ioengine(struct ioengine_ops *ops)
{
	t01_log(T01_DEBUG, "ioengine %s unregistered", ops->name);
	list_del(&ops->list);
}

void register_ioengine(struct ioengine_ops *ops)
{
	t01_log(T01_DEBUG, "ioengine %s registered", ops->name);
	list_add(&ops->list, &engine_list);
}

void close_ioengine(struct ioengine_data *td)
{
	t01_log(T01_DEBUG, "close ioengine %s", td->io_ops->name);
	if (td->io_ops->disconnect) {
		td->io_ops->disconnect(td);
		td->private = NULL;
	}
}

int init_ioengine(struct ioengine_data* td, const char *args)
{
	t01_log(T01_NOTICE, "init ioengine %s with opt %s", td->io_ops->name, args);
	if (td->io_ops->connect) {
		return td->io_ops->connect(td, args);
	}
	return -1;
}

int store_via_ioengine(struct ioengine_data *td, void *flow_, const char* protocol, const char * packet, int pkt_len)
{
	struct ndpi_flow_info *flow = (struct ndpi_flow_info *)flow_;
	int (*write)(struct ioengine_data *, const char *, int) = td->io_ops->write;
	if(!write) return 0;

	u_int32_t src_ip = flow->src_ip;
	u_int32_t dst_ip = flow->dst_ip;
	int src_port = flow->src_port;
	int dst_port = flow->dst_port;
	u_int64_t ts = flow->last_seen;
	u_int detected_protocol;
	int map_size = 6, len;

	msgpack_sbuffer sbuf;
	msgpack_sbuffer_init(&sbuf);
	msgpack_packer pk;
	msgpack_packer_init(&pk, &sbuf, msgpack_sbuffer_write);

	if(flow->detected_protocol.master_protocol) 
		detected_protocol = flow->detected_protocol.master_protocol;
	else 
		detected_protocol = flow->detected_protocol.protocol;

	if(detected_protocol == NDPI_PROTOCOL_HTTP) {
		const char* payload = packet + flow->payload_offset;
		pkt_len -= flow->payload_offset;
		if(pkt_len <= 0) goto clean;

		map_size += 2;
		msgpack_pack_map(&pk, map_size);
		
		msgpack_pack_str(&pk, 4);
    		msgpack_pack_str_body(&pk, "host", 4);
		len = strlen(flow->host_server_name);
		msgpack_pack_str(&pk, len);
    		msgpack_pack_str_body(&pk, flow->host_server_name, len);

		msgpack_pack_str(&pk, 4);
    		msgpack_pack_str_body(&pk, "body", 4);
		//len = strlen(payload);
		msgpack_pack_str(&pk, pkt_len);
    		msgpack_pack_str_body(&pk, payload, pkt_len);
	} else if(detected_protocol == NDPI_PROTOCOL_DNS ||
		detected_protocol == NDPI_PROTOCOL_SSL) {
		char * host = NULL;
		map_size += 1;
		msgpack_pack_map(&pk, map_size);
		
		if(detected_protocol == NDPI_PROTOCOL_DNS){
			host = flow->host_server_name;
		} else {
			if(flow->ssl.client_certificate[0]) 
				host = flow->ssl.client_certificate;
      		else if(flow->ssl.server_certificate[0]) 
				host = flow->ssl.server_certificate;
		}

		msgpack_pack_str(&pk, 4);
    		msgpack_pack_str_body(&pk, "host", 4);
		if(host) {
			len = strlen(host);
			msgpack_pack_str(&pk, len);
    			msgpack_pack_str_body(&pk, host, len);
		} else {
			msgpack_pack_nil(&pk);
		}
	} else {
		msgpack_pack_map(&pk, map_size);
	}

	char l[48], u[48];
	inet_ntop(AF_INET, &src_ip, l, sizeof(l));
	inet_ntop(AF_INET, &dst_ip, u, sizeof(u));

	msgpack_pack_str(&pk, 8);
    	msgpack_pack_str_body(&pk, "protocol", 8);
	len = strlen(protocol);
	msgpack_pack_str(&pk, len);
    	msgpack_pack_str_body(&pk, protocol, len);

	msgpack_pack_str(&pk, 8);
    	msgpack_pack_str_body(&pk, "src_ip", 8);
	len = strlen(l);
	msgpack_pack_str(&pk, len);
    	msgpack_pack_str_body(&pk, l, len);

	msgpack_pack_str(&pk, 8);
    	msgpack_pack_str_body(&pk, "dst_ip", 8);
	len = strlen(u);
	msgpack_pack_str(&pk, len);
    	msgpack_pack_str_body(&pk, u, len);
	
	msgpack_pack_str(&pk, 10);
    	msgpack_pack_str_body(&pk, "src_port", 10);
	msgpack_pack_int(&pk, src_port);	

	msgpack_pack_str(&pk, 10);
    	msgpack_pack_str_body(&pk, "dst_port", 10);
	msgpack_pack_int(&pk, dst_port);

	msgpack_pack_str(&pk, 4);
    	msgpack_pack_str_body(&pk, "when", 4);
    	msgpack_pack_uint32(&pk, ts/1000);

	len = write(td, sbuf.data, sbuf.size);
clean:
	msgpack_sbuffer_destroy(&sbuf);
	return len; 
}


static struct ioengine_ops *find_ioengine(const char *name)
{
	struct ioengine_ops *ops;
	struct list_head *entry;

	list_for_each(entry, &engine_list) {
		ops = list_entry(entry, struct ioengine_ops, list);
		if (!strcmp(name, ops->name))
			return ops;
	}

	return NULL;
}

int load_ioengine(struct ioengine_data* data, const char *name)
{
	struct ioengine_ops *ops;
	char engine[64];

	t01_log(T01_NOTICE, "load ioengine %s", name);

	engine[sizeof(engine) - 1] = '\0';
	strncpy(engine, name, sizeof(engine) - 1);

	ops = find_ioengine(engine);
	if (!ops) {
		t01_log(T01_WARNING, "engine %s not loadable", name);
		return -1;
	}

	data->io_ops = ops;
	return 0;
}

int fio_show_ioengine_help(const char *engine)
{
	struct list_head *entry;
	struct ioengine_ops* io_ops;
	struct ioengine_data id;
	int ret = 1;

	if (!engine || !*engine) {
		printf("Available IO engines:\n");
		list_for_each(entry, &engine_list) {
			io_ops = list_entry(entry, struct ioengine_ops, list);
			printf("\t%s\n", io_ops->name);
		}
		return 0;
	}

	if (load_ioengine(&id, engine) < 0) {
		printf("IO engine %s not found\n", engine);
		return 1;
	} else {
		io_ops = id.io_ops;
	}

	if (io_ops->show_help)
		ret = io_ops->show_help();
	else
		printf("IO engine %s has no options\n", io_ops->name);

	return ret;
}

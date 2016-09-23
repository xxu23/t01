/*
 * The io parts of the fio tool, includes workers for sync and mmap'ed
 * io, as well as both posix and linux libaio support.
 *
 * sync io is implemented on top of aio.
 *
 * This is not really specific to fio, if the get_io_u/put_io_u and
 * structures was pulled into this as well it would be a perfectly
 * generic io engine that could be used for other projects.
 *
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

static LIST_HEAD(engine_list);

void unregister_ioengine(struct ioengine_ops *ops)
{
	printf("ioengine %s unregistered\n", ops->name);
	list_del(&ops->list);
}

void register_ioengine(struct ioengine_ops *ops)
{
	printf("ioengine %s registered\n", ops->name);
	list_add(&ops->list, &engine_list);
}

void close_ioengine(struct ioengine_data *td)
{
	printf("close ioengine %s\n", td->io_ops->name);

	if (td->io_ops->disconnect) {
		td->io_ops->disconnect(td);
		td->private = NULL;
	}
}

int init_ioengine(struct ioengine_data* td, const char *args)
{
	printf("init ioengine %s with opt %s\n", td->io_ops->name, args);

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

	u_int32_t lower_ip = flow->lower_ip;
	u_int32_t upper_ip = flow->upper_ip;
	int lower_port = ntohs(flow->lower_port);
	int upper_port = ntohs(flow->upper_port);
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
		char* payload = packet + flow->payload_offset;
		pkt_len -= flow->payload_offset;

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
		char * host;
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
		len = strlen(host);
		msgpack_pack_str(&pk, len);
    		msgpack_pack_str_body(&pk, host, len);
	} else {
		msgpack_pack_map(&pk, map_size);
	}

	char l[48], u[48];
      inet_ntop(AF_INET, &lower_ip, l, sizeof(l));
	inet_ntop(AF_INET, &upper_ip, u, sizeof(u));

	msgpack_pack_str(&pk, 8);
    	msgpack_pack_str_body(&pk, "protocol", 8);
	len = strlen(protocol);
	msgpack_pack_str(&pk, len);
    	msgpack_pack_str_body(&pk, protocol, len);

	msgpack_pack_str(&pk, 8);
    	msgpack_pack_str_body(&pk, "lower_ip", 8);
	len = strlen(l);
	msgpack_pack_str(&pk, len);
    	msgpack_pack_str_body(&pk, l, len);

	msgpack_pack_str(&pk, 8);
    	msgpack_pack_str_body(&pk, "upper_ip", 8);
	len = strlen(u);
	msgpack_pack_str(&pk, len);
    	msgpack_pack_str_body(&pk, u, len);
	
	msgpack_pack_str(&pk, 10);
    	msgpack_pack_str_body(&pk, "lower_port", 10);
	msgpack_pack_int(&pk, lower_port);	

	msgpack_pack_str(&pk, 10);
    	msgpack_pack_str_body(&pk, "upper_port", 10);
	msgpack_pack_int(&pk, upper_port);

	msgpack_pack_str(&pk, 4);
    	msgpack_pack_str_body(&pk, "when", 4);
    	msgpack_pack_uint32(&pk, ts/1000);

	len = write(td, sbuf.data, sbuf.size);
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

	printf("load ioengine %s\n", name);

	engine[sizeof(engine) - 1] = '\0';
	strncpy(engine, name, sizeof(engine) - 1);

	ops = find_ioengine(engine);
	if (!ops) {
		fprintf(stderr, "engine %s not loadable\n", name);
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

	io_ops = load_ioengine(&id, engine);
	if (!io_ops) {
		printf("IO engine %s not found\n", engine);
		return 1;
	}

	if (io_ops->show_help)
		ret = io_ops->show_help();
	else
		printf("IO engine %s has no options\n", io_ops->name);

	return ret;
}

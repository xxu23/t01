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

#define NETMAP_WITH_LIBS 1
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/sysinfo.h>
#include <sys/socket.h>

#include <ndpi_api.h>
#include "ndpi_util.h"
#include "pktgen.h"
#include "rule.h"
#include "anet.h"
#include "logger.h"
#include "networking.h"
#include "ioengine.h"
#include "t01.h"
#include "zmalloc.h"
#include <cJSON.h>
#include <net/netmap_user.h>
#include <event.h>

struct backup_data {
	char *buffer;
	int len;
	struct ndpi_flow_info *flow;
};

int dirty = 0;
int dirty_before_bgsave;
int lastbgsave_status;
time_t lastsave;
pid_t tdb_child_pid = -1;
time_t upstart;
uint64_t total_flow_bytes = 0;
uint64_t raw_packet_count = 0;
uint64_t ip_packet_count = 0;
uint64_t ip_packet_count_out = 0;
uint64_t total_wire_bytes = 0, total_ip_bytes = 0;
uint64_t total_ip_bytes_out = 0;
uint64_t tcp_count = 0, udp_count = 0;
uint64_t hits = 0;
uint64_t bytes_per_second_in = 0;
uint64_t bytes_per_second_out = 0;
uint64_t pkts_per_second_in = 0;
uint64_t pkts_per_second_out = 0;
struct event_base *base;
struct t01_config tconfig;

static struct ndpi_workflow *workflow;
static ZLIST_HEAD(filter_buffer_list);
static ZLIST_HEAD(hitslog_list);
static struct timeval upstart_tv;
static char master_address[64];
static char hit_address[64];
static char conffile[256];
static struct backup_data backup_copy[MAX_BACKUP_DATA];
static int bak_produce_idx = 0;
static int bak_consume_idx = 0;
static int tcp_sofd;
static int udp_logfd;
static struct nm_desc *nmr, *out_nmr;
static uint8_t shutdown_app = 0;
static struct ioengine_data backup_engine;
static struct ioengine_data mirror_engine;
static int backup = 0;
static int mirror = 0;
static int enable_all_protocol = 1;
static struct timeval last_report_ts;
static NDPI_PROTOCOL_BITMASK ndpi_mask;
static pthread_spinlock_t mirror_lock;
static pthread_spinlock_t hitlog_lock;

static struct filter_strategy {
	uint8_t protocol;
	uint16_t port;
} filters[MAX_FILTERS];
static int n_filters;

struct filter_buffer {
	struct list_head list;
	uint64_t ts;
	int len;
	int protocol;
	uint32_t saddr;
	uint32_t daddr;
	uint16_t sport;
	uint16_t dport;
	char buffer[0];
};

struct hits_log_rz {
	struct list_head list;
	struct log_rz hit;
};

static void process_hitslog(struct rule *rule, struct ndpi_flow_info *flow,
			    uint8_t * packet)
{
	if (tconfig.work_mode & SLAVE_MODE ||
		(tconfig.hit_ip[0] && tconfig.hit_port)) {
		/* Send log to master or log server */
		struct hits_log_rz *hl = zcalloc(1, sizeof(*hl));
		if (!hl)
			return;
		rule->hits++;
		hl->hit.rule_id = rule->id;
		hl->hit.rule_type = rule->action;
		hl->hit.pktlen = flow->pktlen;
		hl->hit.proto = flow->protocol;
		hl->hit.time = flow->last_seen / 1000;
		hl->hit.src_ip = flow->src_ip;
		hl->hit.dst_ip = flow->dst_ip;
		hl->hit.src_port = flow->src_port;
		hl->hit.dst_port = flow->dst_port;
		memcpy(hl->hit.smac, packet + 6, 6);
		memcpy(hl->hit.dmac, packet, 6);

		pthread_spin_lock(&hitlog_lock);
		list_add_tail(&hl->list, &hitslog_list);
		pthread_spin_unlock(&hitlog_lock);
	} else {
		/* Store in local disk */
		add_hit_record(rule, flow->last_seen / 1000,
			       flow->src_ip, flow->dst_ip,
			       flow->src_port, flow->dst_port,
			       (uint8_t *) packet + 6, (uint8_t *) packet,
			       0, flow->protocol, flow->pktlen);
	}
}

static int mirror_filter_from_rule(struct ndpi_flow_info *flow, void *packet)
{
	struct rule *rule = match_rule_before_mirrored(flow, packet);
	if (!rule)
		return 0;

	process_hitslog(rule, flow, (uint8_t *) packet);

	return 1;
}

static int netflow_data_filter(struct ndpi_flow_info *flow, void *packet)
{
	int i;

	for (i = 0; i < n_filters; i++) {
		if (filters[i].protocol == 0) {
			if (filters[i].port == flow->dst_port)
				return 1;
		} else if (filters[i].protocol == flow->protocol &&
			   filters[i].port == flow->dst_port)
			return 1;
	}
	return 0;
}

static void netflow_data_clone(void *data, uint32_t n,
			       uint8_t protocol, uint64_t ts,
			       uint32_t saddr, uint16_t sport,
			       uint32_t daddr, uint16_t dport)
{
	struct filter_buffer *fb = zmalloc(sizeof(struct filter_buffer) + n);
	if (!fb)
		return;
	memcpy(fb->buffer, data, n);
	fb->len = n;
	fb->protocol = protocol;
	fb->ts = ts;
	fb->saddr = saddr;
	fb->sport = sport;
	fb->daddr = daddr;
	fb->dport = dport;

	pthread_spin_lock(&mirror_lock);
	list_add_tail(&fb->list, &filter_buffer_list);
	pthread_spin_unlock(&mirror_lock);
}

static void create_pidfile(void)
{
	FILE *fp = fopen(DEFAULT_PID_FILE, "w");
	if (fp) {
		fprintf(fp, "%d\n", (int)getpid());
		fclose(fp);
	}
}

static void daemonize(void)
{
	int fd;

	if (fork() != 0)
		exit(0);	/* parent exits */
	setsid();		/* create a new session */

	/* Every output goes to /dev/null. If Redis is daemonized but
	 * the 'logfile' is set to 'stdout' in the configuration file
	 * it will not log at all. */
	if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		if (fd > STDERR_FILENO)
			close(fd);
	}
}

#define get_string_from_json(item, json, key, value) 	\
  item = cJSON_GetObjectItem(json, key); 			\
  if(item){ 							\
    strncpy(value, item->valuestring, sizeof(value));	\
  }									\

#define get_int_from_json(item, json, key, value) 	\
  item = cJSON_GetObjectItem(json, key); 			\
  if(item){ 							\
    value = item->valueint;                             \
  }

static void load_config(const char *filename)
{
	FILE *fp;
	long size;
	char *data;
	cJSON *json, *item;
	char wm[64];

	/* Read content from file */
	fp = fopen(filename, "r");
	if (fp == NULL) {
		t01_log(T01_WARNING,
		"Cannot read config %s: %s, aborting now", filename, strerror(errno));
		exit(1);
	}
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	data = (char *)zmalloc(size + 1);
	if (!data) {
		t01_log(T01_WARNING, "Out of memory!");
		exit(1);
	}
	fread(data, 1, size, fp);
	data[size] = '\0';
	fclose(fp);

	json = cJSON_Parse(data);
	if (!json) {
		t01_log(T01_WARNING, "Cannot parse json: %s", cJSON_GetErrorPtr());
		exit(1);
	}
	zfree(data);

	get_string_from_json(item, json, "ifname", tconfig.ifname);
	get_string_from_json(item, json, "ofname", tconfig.ofname);
	get_string_from_json(item, json, "ruledb", tconfig.ruledb);
	get_string_from_json(item, json, "logfile", tconfig.logfile);
	get_string_from_json(item, json, "filter", tconfig.filter);
	get_string_from_json(item, json, "engine", tconfig.engine);
	get_string_from_json(item, json, "engine_opt", tconfig.engine_opt);
	get_int_from_json(item, json, "daemon", tconfig.daemon_mode);
	get_string_from_json(item, json, "master_ip", tconfig.master_ip);
	get_int_from_json(item, json, "master_port", tconfig.master_port);
	get_string_from_json(item, json, "rule_ip", tconfig.rule_ip);
	get_int_from_json(item, json, "rule_port", tconfig.rule_port);
	get_string_from_json(item, json, "hit_ip", tconfig.hit_ip);
	get_int_from_json(item, json, "hit_port", tconfig.hit_port);
	get_int_from_json(item, json, "verbose", tconfig.verbose);
	get_string_from_json(item, json, "work_mode", wm);
	if(strcasecmp(wm, "slave") == 0)
		tconfig.work_mode = SLAVE_MODE;
	else if(strcasecmp(wm, "master") == 0)
		tconfig.work_mode = MASTER_MODE;
	else if(strcasecmp(wm, "netmap") == 0)
		tconfig.work_mode =NETMAP_MODE;

	cJSON_Delete(json);
}

static void usage()
{
	const char *cmd = "t01";
	fprintf(stderr,
		"Usage: %s [options]\n"
		"\nOptions:\n"
		"\t-c filename               configuration file\n"
		"\t-i interface              interface that captures incoming traffic\n"
		"\t-o interface              interface that sends outcoming traffic (default same as incoming interface)\n"
		"\t-r ruledb                 rule db file that saving rule and hit record\n"
		"\t-b ip                     ip address binded for rule management\n"
		"\t-p port                   port listening for rule management (default 9899)\n"
		"\t-S | -M                   slave or master mode for rule management\n"
		"\t-d                        run in daemon mode or not\n"
		"\t-j ip:port                master address for rule management cluster (eg 192.168.1.2:9898)\n"
		"\t-H ip:port                udp server address for rule hits\n"
		"\t-F filter                 filter strategy for mirroring netflow (eg 80/tcp,53/udp)\n"
		"\t-e engine                 backend engine to store network flow data\n"
		"\t-E eigine_opt             arguments attached to specified engine\n"
		"\t-v verbosity              logger levels (0:debug, 1:verbose, 2:notice, 3:warning)\n"
		"\t-l log_file               logger into file or screen\n"
		"", cmd);

	exit(0);
}

static void parse_options(int argc, char **argv)
{
	int opt;

	while ((opt =
		getopt(argc, argv, "SMdhc:i:o:r:e:b:p:E:v:l:F:j:H:")) != EOF) {
		switch (opt) {
		case 'S':
			tconfig.work_mode |= SLAVE_MODE;
			break;

		case 'M':
			tconfig.work_mode |= MASTER_MODE;
			break;

		case 'd':
			tconfig.daemon_mode = 1;
			break;

		case 'i':
			strncpy(tconfig.ifname, optarg, sizeof(tconfig.ifname));
			break;

		case 'o':
			strncpy(tconfig.ofname, optarg, sizeof(tconfig.ofname));
			break;

		case 'j':
			strncpy(master_address, optarg, sizeof(master_address));
			break;

		case 'H':
			strncpy(hit_address, optarg, sizeof(hit_address));
			break;

		case 'p':
			tconfig.rule_port = atoi(optarg);
			break;

		case 'b':
			strncpy(tconfig.rule_ip, optarg,
				sizeof(tconfig.rule_ip));
			break;

		case 'r':
			strncpy(tconfig.ruledb, optarg, sizeof(tconfig.ruledb));
			break;

		case 'c':
			strncpy(conffile, optarg, sizeof(conffile));
			break;

		case 'v':
			tconfig.verbose = atoi(optarg);
			break;

		case 'l':
			strncpy(tconfig.logfile, optarg,
				sizeof(tconfig.logfile));
			break;

		case 'F':
			strncpy(tconfig.filter, optarg, sizeof(tconfig.filter));
			break;

		case 'e':
			strcpy(tconfig.engine, optarg);
			break;

		case 'E':
			strcpy(tconfig.engine_opt, optarg);
			break;

		case 'h':
			usage();
			break;

		default:
			usage();
			break;
		}
	}

	if(conffile[0])
		load_config(conffile);

	// check parameters
	if (master_address[0]) {
		parseipandport(master_address, tconfig.master_ip,
			       sizeof(tconfig.master_ip), &tconfig.master_port);
	}
	if (hit_address[0]) {
		parseipandport(hit_address, tconfig.hit_ip,
			       sizeof(tconfig.hit_ip), &tconfig.hit_port);
	}
	if (tconfig.work_mode & SLAVE_MODE && tconfig.work_mode & MASTER_MODE) {
		fprintf(stderr, "Both master and slave mode is not support\n");
		usage();
	}
	if ((tconfig.work_mode & SLAVE_MODE || tconfig.work_mode & MASTER_MODE)
	    && tconfig.master_ip[0] == 0) {
		fprintf(stderr,
			"Master address should be specified in master/slave mode\n");
		usage();
	}
	if (tconfig.work_mode & SLAVE_MODE || tconfig.work_mode == NONE_MODE)
		tconfig.work_mode |= NETMAP_MODE;

	if (tconfig.work_mode & NETMAP_MODE && tconfig.ifname[0] == 0
	    && tconfig.ruledb[0] == 0) {
		fprintf(stderr,
			"Incoming interface should be specified in netmap/slave mode\n");
		usage();
	}
	if (tconfig.ruledb[0] == 0)
		strcpy(tconfig.ruledb, DEFAULT_RULEDB);
	if (tconfig.rule_port == 0)
		tconfig.rule_port = DEFAULT_RULE_PORT;
}

static void signal_hander(int sig)
{
	static int called = 0;
	int save = dirty != 0;
	t01_log(T01_WARNING, "Received control-C, shutdowning");
	if (called)
		return;
	else
		called = 1;
	if (save) {
		t01_log(T01_NOTICE,
			"Saving the final TDB snapshot before exiting.");
		if (save_rules(tconfig.ruledb) != 0) {
			t01_log(T01_WARNING,
				"Error trying to save the DB, can't exit.");
			return;
		}

		if (tconfig.daemon_mode) {
			t01_log(T01_NOTICE, "Removing the pid file.");
			unlink(DEFAULT_PID_FILE);
		}
	}
	shutdown_app = 1;
	event_base_loopexit(base, NULL);
}

static char *format_traffic(float numBits, int bits, char *buf)
{
	char unit;

	if (bits)
		unit = 'b';
	else
		unit = 'B';

	if (numBits < 1024) {
		snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
	} else if (numBits < 1048576) {
		snprintf(buf, 32, "%.2f K%c", (float)(numBits) / 1024, unit);
	} else {
		float tmpMBits = ((float)numBits) / 1048576;

		if (tmpMBits < 1024) {
			snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
		} else {
			tmpMBits /= 1024;

			if (tmpMBits < 1024) {
				snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
			} else {
				snprintf(buf, 32, "%.2f T%c",
					 (float)(tmpMBits) / 1024, unit);
			}
		}
	}

	return (buf);
}

static char *format_packets(float numPkts, char *buf)
{

	if (numPkts < 1000) {
		snprintf(buf, 32, "%.2f", numPkts);
	} else if (numPkts < 1000000) {
		snprintf(buf, 32, "%.2f K", numPkts / 1000);
	} else {
		numPkts /= 1000000;
		snprintf(buf, 32, "%.2f M", numPkts);
	}

	return (buf);
}

static int manage_interface_promisc_mode(const char *interface, int on)
{
	// We need really any socket for ioctl
	int fd;
	struct ifreq ethreq;
	int ioctl_res;
	int promisc_enabled_on_device;
	int ioctl_res_set;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (!fd) {
		t01_log(T01_WARNING,
			"Can't create socket for promisc mode manager");
		return -1;
	}

	bzero(&ethreq, sizeof(ethreq));
	strncpy(ethreq.ifr_name, interface, IFNAMSIZ);

	ioctl_res = ioctl(fd, SIOCGIFFLAGS, &ethreq);
	if (ioctl_res == -1) {
		t01_log(T01_WARNING, "Can't get interface flags");
		return -1;
	}

	promisc_enabled_on_device = ethreq.ifr_flags & IFF_PROMISC;
	if (on) {
		if (promisc_enabled_on_device) {
			t01_log(T01_DEBUG,
				"Interface %s in promisc mode already",
				interface);
			return 0;
		} else {
			t01_log(T01_DEBUG,
				"Interface %s in non promisc mode now, switch it on",
				interface);
			ethreq.ifr_flags |= IFF_PROMISC;
			ioctl_res_set = ioctl(fd, SIOCSIFFLAGS, &ethreq);
			if (ioctl_res_set == -1) {
				t01_log(T01_WARNING,
					"Can't set interface flags");
				return -1;
			}

			return 1;
		}
	} else {
		if (!promisc_enabled_on_device) {
			t01_log(T01_DEBUG,
				"Interface %s in normal mode already",
				interface);
			return 0;
		} else {
			t01_log(T01_DEBUG,
				"Interface in promisc mode now, switch it off");
			ethreq.ifr_flags &= ~IFF_PROMISC;
			ioctl_res_set = ioctl(fd, SIOCSIFFLAGS, &ethreq);
			if (ioctl_res_set == -1) {
				t01_log(T01_WARNING,
					"Can't set interface flags");
				return -1;
			}

			return 1;
		}
	}
}

static void on_protocol_discovered(struct ndpi_workflow *workflow,
				   struct ndpi_flow_info *flow, void *header,
				   void *packet)
{

	if (flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) {
		flow->detected_protocol =
		    ndpi_guess_undetected_protocol(workflow->ndpi_struct,
						   flow->protocol,
						   ntohl(flow->lower_ip),
						   ntohs(flow->lower_port),
						   ntohl(flow->upper_ip),
						   ntohs(flow->upper_port));
		flow->detected_protocol.master_protocol = NDPI_PROTOCOL_UNKNOWN;
	}

	if (backup) {
		int next_idx = bak_produce_idx + 1;
		if (next_idx >= MAX_BACKUP_DATA)
			next_idx -= MAX_BACKUP_DATA;
		if (likely(next_idx != bak_consume_idx)) {
			struct backup_data *d = &backup_copy[bak_produce_idx];
			struct nm_pkthdr *h = (struct nm_pkthdr *)header;

			d->len = h->len;
			d->buffer = zmalloc(h->len);
			memcpy(d->buffer, packet, h->len);
			d->flow = flow;
next:
			bak_produce_idx++;
			if (bak_produce_idx == MAX_BACKUP_DATA)
				bak_produce_idx = 0;
		}
	}

	struct rule *rule = match_rule_after_detected(flow, packet);
	if (!rule)
		return;
	process_hitslog(rule, flow, packet);

	char result[1500] = { 0 };
	int len = make_packet(rule, packet, result, sizeof(result), flow);
	if (len) {
		nm_inject(out_nmr, result, len);
		total_ip_bytes_out += len;
		ip_packet_count_out++;

		if (tconfig.verbose) {
			char l[48], u[48];
			char msg[4096];
			int offset = 0;
			inet_ntop(AF_INET, &flow->src_ip, l, sizeof(l));
			inet_ntop(AF_INET, &flow->dst_ip, u, sizeof(u));
			offset +=
			    snprintf(msg, sizeof(msg) - offset,
				     "Rule %d Hits: %s %s:%u <-> %s:%u ",
				     rule->id, ipproto_name(flow->protocol), l,
				     flow->src_port, u, flow->dst_port);

			if (flow->detected_protocol.master_protocol) {
				char buf[64];
				offset +=
				    snprintf(msg + offset, sizeof(msg) - offset,
					     "[proto: %u.%u/%s]",
					     flow->detected_protocol.
					     master_protocol,
					     flow->detected_protocol.protocol,
					     ndpi_protocol2name(workflow->
								ndpi_struct,
								flow->
								detected_protocol,
								buf,
								sizeof(buf)));
			} else
				offset +=
				    snprintf(msg + offset, sizeof(msg) - offset,
					     "[proto: %u/%s]",
					     flow->detected_protocol.protocol,
					     ndpi_get_proto_name
					     (workflow->ndpi_struct,
					      flow->detected_protocol.
					      protocol));

			offset +=
			    snprintf(msg + offset, sizeof(msg) - offset,
				     "[%u pkts/%llu bytes]", flow->packets,
				     flow->bytes);

			if (flow->host_server_name[0] != '\0')
				offset +=
				    snprintf(msg + offset, sizeof(msg) - offset,
					     "[Host: %s]",
					     flow->host_server_name);
			if (flow->ssl.client_certificate[0] != '\0')
				offset +=
				    snprintf(msg + offset, sizeof(msg) - offset,
					     "[SSL client: %s]",
					     flow->ssl.client_certificate);
			if (flow->ssl.server_certificate[0] != '\0')
				offset +=
				    snprintf(msg + offset, sizeof(msg) - offset,
					     "[SSL server: %s]",
					     flow->ssl.server_certificate);

			t01_log(T01_NOTICE, msg);
		}
	}
}

struct ndpi_workflow *setup_detection()
{
	struct ndpi_workflow *workflow;
	struct ndpi_workflow_prefs prefs;
	struct sysinfo si;
	u_int32_t max_ndpi_flows;

	sysinfo(&si);
	max_ndpi_flows = si.totalram / 2 / sizeof(struct ndpi_flow_info);
	if (max_ndpi_flows > MAX_NDPI_FLOWS)
		max_ndpi_flows = MAX_NDPI_FLOWS;

	memset(&prefs, 0, sizeof(prefs));
	prefs.decode_tunnels = 0;
	prefs.num_roots = NUM_ROOTS;
	prefs.max_ndpi_flows = max_ndpi_flows;
	prefs.quiet_mode = 0;

	workflow = ndpi_workflow_init(&prefs);

	ndpi_workflow_set_flow_detected_callback(workflow,
						 on_protocol_discovered,
						 (void *)(uintptr_t) workflow);
	ndpi_set_mirror_data_callback(workflow,
				      mirror_filter_from_rule,
				      mirror ? netflow_data_clone : NULL,
				      mirror ? netflow_data_filter : NULL);

	// enable all protocols
	NDPI_BITMASK_SET_ALL(ndpi_mask);
	ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &ndpi_mask);

	// clear memory for results
	memset(workflow->stats.protocol_counter, 0,
	       sizeof(workflow->stats.protocol_counter));
	memset(workflow->stats.protocol_counter_bytes, 0,
	       sizeof(workflow->stats.protocol_counter_bytes));
	memset(workflow->stats.protocol_flows, 0,
	       sizeof(workflow->stats.protocol_flows));

	return workflow;
}

static void *mirror_thread(void *args)
{
	t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);

	while (!shutdown_app) {
		struct list_head *pos, *n;
		struct filter_buffer *fb;

		list_for_each_safe(pos, n, &filter_buffer_list) {
			pthread_spin_lock(&mirror_lock);
			list_del(pos);
			pthread_spin_unlock(&mirror_lock);
			fb = list_entry(pos, struct filter_buffer, list);
			store_raw_via_ioengine(&mirror_engine, fb->buffer,
					       fb->len, fb->protocol, fb->ts,
					       fb->saddr, fb->sport, fb->daddr,
					       fb->dport);
			zfree(fb);
		}
	}

	t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
	return NULL;
}

static void *backup_thread(void *args)
{
	struct timespec ts = {.tv_sec = 0,.tv_nsec = 1 };
	char protocol[64];
	t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);

	while (!shutdown_app) {
		if (bak_consume_idx == bak_produce_idx) {
			nanosleep(&ts, NULL);
			continue;
		}
		struct backup_data *d = &backup_copy[bak_consume_idx];
		struct ndpi_flow_info *flow = (struct ndpi_flow_info *)d->flow;

		/*Whether the flow info is deleted? */
		if (flow->magic != NDPI_FLOW_MAGIC
		    || flow->last_seen + MAX_IDLE_TIME < workflow->last_time)
			goto next;

		if (flow->detected_protocol.master_protocol)
			ndpi_protocol2name(workflow->ndpi_struct,
					   flow->detected_protocol, protocol,
					   sizeof(protocol));
		else
			strcpy(protocol,
			       ndpi_get_proto_name(workflow->ndpi_struct,
						   flow->detected_protocol.
						   protocol));

		store_payload_via_ioengine(&backup_engine, flow, protocol,
					   d->buffer, d->len);

next:
		zfree(d->buffer);
		bak_consume_idx++;
		if (bak_consume_idx == MAX_BACKUP_DATA)
			bak_consume_idx = 0;
	}

	t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
	return NULL;
}

static void statistics_cb(evutil_socket_t fd, short event, void *arg)
{
	struct ndpi_stats *stat = &workflow->stats;
	struct timeval curr_ts;
	uint64_t tot_usec, since_usec;
	uint64_t total_hits = 0;
	unsigned int avg_pkt_size = 0;
	uint64_t curr_raw_packet_count =
	    stat->raw_packet_count - raw_packet_count;
	uint64_t curr_ip_packet_count = stat->ip_packet_count - ip_packet_count;
	uint64_t curr_total_wire_bytes =
	    stat->total_wire_bytes - total_wire_bytes;
	uint64_t curr_total_ip_bytes = stat->total_ip_bytes - total_ip_bytes;
	uint64_t curr_tcp_count = stat->tcp_count - tcp_count;
	uint64_t curr_udp_count = stat->udp_count - udp_count;
	uint64_t curr_hits;

	gettimeofday(&curr_ts, NULL);
	tot_usec =
	    curr_ts.tv_sec * 1000000 + curr_ts.tv_usec -
	    (last_report_ts.tv_sec * 1000000 + last_report_ts.tv_usec);
	since_usec =
	    curr_ts.tv_sec * 1000000 + curr_ts.tv_usec -
	    (upstart_tv.tv_sec * 1000000 + upstart_tv.tv_usec);
	last_report_ts = curr_ts;

	raw_packet_count = stat->raw_packet_count;
	ip_packet_count = stat->ip_packet_count;
	total_wire_bytes = stat->total_wire_bytes;
	total_ip_bytes = stat->total_ip_bytes;
	tcp_count = stat->tcp_count;
	udp_count = stat->udp_count;
	total_hits = calc_totalhits();

	if (since_usec > 0) {
		pkts_per_second_in = ip_packet_count * 1000000.0f / since_usec;
		pkts_per_second_out =
		    ip_packet_count_out * 1000000.0f / since_usec;
		bytes_per_second_in =
		    total_ip_bytes * 8.0f * 1000000 / since_usec;
		bytes_per_second_out =
		    total_ip_bytes_out * 8.0f * 1000000 / since_usec;
	}

	printf("\nTraffic statistics:\n");
	printf("\tEthernet bytes:        %-13llu\n", curr_total_wire_bytes);
	printf("\tIP bytes:              %-13llu\n", curr_total_ip_bytes);
	printf
	    ("\tIP packets:            %-13llu of %llu packets total\n",
	     curr_ip_packet_count, curr_raw_packet_count);
	printf("\tTCP Packets:           %-13lu\n", curr_tcp_count);
	printf("\tUDP Packets:           %-13lu\n", curr_udp_count);

	if (tot_usec > 0) {
		char buf[32], buf1[32];
		float t =
		    (float)(curr_ip_packet_count * 1000000) / (float)tot_usec;
		float b =
		    (float)(curr_total_wire_bytes * 8 * 1000000) /
		    (float)tot_usec;
		float traffic_duration = tot_usec;
		printf("\tTraffic throughput:    %s pps / %s/sec\n",
		       format_packets(t, buf), format_traffic(b, 1, buf1));
		printf("\tTraffic duration:      %.3f sec\n",
		       traffic_duration / 1000000);
		printf("\tIncoming throughput:   %s pps / %s/sec\n",
		       format_packets(pkts_per_second_in, buf),
		       format_traffic(bytes_per_second_in, 1, buf1));
		printf("\tOutcoming throughput:  %s pps / %s/sec\n",
		       format_packets(pkts_per_second_out, buf),
		       format_traffic(bytes_per_second_out, 1, buf1));
	}

	curr_hits = total_hits - hits;
	printf("\tRules hits:            %-13lu (total %llu)\n",
	       curr_hits, total_hits);
	hits = total_hits;
}

static void rulesaving_cb(evutil_socket_t fd, short event, void *arg)
{
	time_t unix_time = time(NULL);

	static struct saveparam {
		time_t seconds;
		int changes;
	} saveparams[] = { {
	300, 1}, {
	60, 30}, {
	5, 500}, {
	1, HITS_THRESHOLD_PER_SECOND}};

	/* Check if a background saving or AOF rewrite in progress terminated. */
	if (tdb_child_pid != -1) {
		int statloc;
		pid_t pid;

		if ((pid = wait3(&statloc, WNOHANG, NULL)) != 0) {
			int exitcode = WEXITSTATUS(statloc);
			int bysignal = 0;

			if (WIFSIGNALED(statloc))
				bysignal = WTERMSIG(statloc);
			if (pid == tdb_child_pid) {
				background_save_done_handler(exitcode,
							     bysignal);
			} else {
				t01_log(T01_WARNING,
					"Warning, detected child with unmatched pid: %ld",
					(long)pid);
			}
		}
	} else {
		int j;
		for (j = 0; j < sizeof(saveparams) / sizeof(saveparams[0]); j++) {
			struct saveparam *sp = saveparams + j;
			if (dirty >= sp->changes
			    && unix_time - lastsave > sp->seconds
			    && lastbgsave_status == 0) {
				t01_log(T01_NOTICE,
					"%d changes in %d seconds. Saving...",
					sp->changes, (int)sp->seconds);
				save_rules_background(tconfig.ruledb);
				break;
			}
		}
	}
}

static void slave_cb(evutil_socket_t fd, short event, void *arg)
{
	slave_registry_master(tconfig.master_ip, tconfig.master_port,
			      tconfig.rule_port);
}

static void master_cb(evutil_socket_t fd, short event, void *arg)
{
	master_check_slaves();
}

static void *hitslog_thread(void *args)
{
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	int fd;
	char err[ANET_ERR_LEN];
	char *udp_ip;
	int udp_port;
	size_t offset = 0;
	int log_len;

	t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);
	if(tconfig.hit_ip[0] && tconfig.hit_port) {
		udp_ip = tconfig.hit_ip;
		udp_port = tconfig.hit_port;
		offset = offsetof(struct log_rz, src_ip);
		log_len = sizeof(struct log_rz) - offset;
	} else {
		udp_ip = tconfig.master_ip;
		udp_port = tconfig.master_port;
		offset = 0;
		log_len = sizeof(struct log_rz);
	}
	fd = anetCreateUdpSocket(err, udp_ip, udp_port,
				 (struct sockaddr *)&addr, addr_len);
	if (fd < 0) {
		t01_log(T01_WARNING, "Cannot create socket: %s", err);
		goto leave;
	}

	while (!shutdown_app) {
		struct list_head *pos, *n;
		struct hits_log_rz *hlr;

		list_for_each_safe(pos, n, &hitslog_list) {
			hlr = list_entry(pos, struct hits_log_rz, list);
			pthread_spin_lock(&hitlog_lock);
			list_del(pos);
			pthread_spin_unlock(&hitlog_lock);			

			anetUdpWrite(fd, (char *)&hlr->hit+offset, log_len,
				     (struct sockaddr *)&addr, addr_len);
			zfree(hlr);
		}
	}

	close(fd);

leave:
	t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
	return NULL;
}

static void *libevent_thread(void *args)
{
	struct event ev0, ev1, ev2, ev3, ev4;
	struct timeval tv2, tv3, tv4;

	/* initialize libevent */
	t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);
	base = event_base_new();

	/* start hit log udp server */
	if (udp_logfd > 0) {
		event_set(&ev0, udp_logfd, EV_READ | EV_PERSIST,
			  udp_server_can_read, NULL);
		event_base_set(base, &ev0);
		event_add(&ev0, NULL);
	}

	/* start rule management server */
	if (tcp_sofd > 0) {
		event_set(&ev1, tcp_sofd, EV_READ | EV_PERSIST,
			  server_can_accept, NULL);
		event_base_set(base, &ev1);
		event_add(&ev1, NULL);
	}

	/* Initalize timeout event */
	if (tconfig.work_mode & NETMAP_MODE) {
		event_assign(&ev2, base, -1, EV_PERSIST, statistics_cb,
			     (void *)&ev2);
		evutil_timerclear(&tv2);
		tv2.tv_sec = 2;
		event_add(&ev2, &tv2);
	}

	if (tconfig.work_mode & NETMAP_MODE || tconfig.work_mode & MASTER_MODE) {
		evutil_timerclear(&tv3);
		tv3.tv_usec = 1000;
		event_assign(&ev3, base, -1, EV_PERSIST, rulesaving_cb,
			     (void *)&ev3);
		event_add(&ev3, &tv3);
	}

	if (tconfig.work_mode & SLAVE_MODE) {
		evutil_timerclear(&tv4);
		tv4.tv_sec = 5;
		event_assign(&ev4, base, -1, EV_PERSIST, slave_cb,
			     (void *)&ev4);
		event_add(&ev4, &tv4);
	} else if (tconfig.work_mode & MASTER_MODE) {
		evutil_timerclear(&tv4);
		tv4.tv_sec = 5;
		event_assign(&ev4, base, -1, EV_PERSIST, master_cb,
			     (void *)&ev4);
		event_add(&ev4, &tv4);
	}

	event_base_dispatch(base);

	t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
}

static inline int receive_packets(struct netmap_ring *ring,
				  struct ndpi_workflow *workflow)
{
	u_int cur, rx, n;
	struct nm_pkthdr hdr;
	cur = ring->cur;
	n = nm_ring_space(ring);
	for (rx = 0; rx < n; rx++) {
		struct netmap_slot *slot = &ring->slot[cur];
		char *data = NETMAP_BUF(ring, slot->buf_idx);
		hdr.ts = ring->ts;
		hdr.len = hdr.caplen = slot->len;
		cur = nm_ring_next(ring, cur);
		ndpi_workflow_process_packet(workflow, &hdr, (u_char *) data);
	}

	ring->head = ring->cur = cur;
	return (rx);
}

static void *netmap_thread(void *args)
{
	int i;
	struct pollfd pfd[2];
	int nfds = 1;
	struct netmap_ring *rxring = NULL;
	struct netmap_if *nifp = nmr->nifp;

	t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);
	memset(pfd, 0, sizeof(pfd));
	pfd[0].fd = nmr->fd;
	pfd[0].events = POLLIN;
	if (out_nmr != nmr) {
		pfd[1].fd = out_nmr->fd;
		pfd[1].events = POLLOUT;
		nfds++;
	}

	while (!shutdown_app) {
		/* should use a parameter to decide how often to send */
		pfd[0].revents = pfd[1].revents = 0;
		if (poll(pfd, nfds, 1000) < nfds) {
			continue;
		}

		for (i = nmr->first_rx_ring; i <= nmr->last_rx_ring; i++) {
			rxring = NETMAP_RXRING(nifp, i);
			if (nm_ring_empty(rxring))
				continue;
			receive_packets(rxring, workflow);
		}

		ndpi_workflow_clean_idle_flows(workflow, 0);
	}

	t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
	return NULL;
}

static void main_thread()
{
	int err, i, nthreads = 0;
	pthread_t threads[5];

	gettimeofday(&last_report_ts, NULL);

	if (tconfig.work_mode & NETMAP_MODE &&
	    pthread_create(&threads[nthreads++], NULL, netmap_thread,
			   NULL) != 0) {
		t01_log(T01_WARNING, "Can't create netmap thread: %s",
			strerror(errno));
		exit(1);
	} else {
		sleep(1);
	}

	if ((tconfig.work_mode & SLAVE_MODE || 
	     (tconfig.hit_ip[0] && tconfig.hit_port)) &&
	    pthread_create(&threads[nthreads++], NULL, hitslog_thread,
			   NULL) != 0) {
		t01_log(T01_WARNING, "Can't create hitslog thread: %s",
			strerror(errno));
		exit(1);
	}

	if ((tconfig.work_mode & NETMAP_MODE || tconfig.work_mode & MASTER_MODE)
	    && pthread_create(&threads[nthreads++], NULL, libevent_thread,
			      NULL) != 0) {
		t01_log(T01_WARNING, "Can't create libevent thread: %s",
			strerror(errno));
		exit(1);
	}

	if (backup
	    && pthread_create(&threads[nthreads++], NULL, backup_thread,
			      NULL) != 0) {
		t01_log(T01_WARNING, "Can't create backup thread: %s",
			strerror(errno));
		backup = 0;
		nthreads--;
	}

	if (mirror
	    && pthread_create(&threads[nthreads++], NULL, mirror_thread,
			      NULL) != 0) {
		t01_log(T01_WARNING, "Can't create mirror thread: %s",
			strerror(errno));
		mirror = 0;
		nthreads--;
	}

	for (i = 0; i < nthreads; i++) {
		pthread_join(threads[i], NULL);
	}
}

static void init_system()
{
	if (tconfig.daemon_mode) {
		daemonize();
		create_pidfile();
	}

	zmalloc_enable_thread_safeness();
	event_set_mem_functions(zmalloc, zrealloc, zfree);

	init_log(tconfig.verbose, tconfig.logfile);
	lastsave = upstart = time(NULL);
	gettimeofday(&upstart_tv, NULL);
}

static void init_netmap()
{
	struct nmreq req;
	char interface[64];

	manage_interface_promisc_mode(tconfig.ifname, 1);
	t01_log(T01_DEBUG,
		"Please disable all types of offload for this NIC manually: ethtool -K %s gro off gso off tso off lro off",
		tconfig.ifname);

	bzero(&req, sizeof(req));
	sprintf(interface, "netmap:%s", tconfig.ifname);
	nmr = nm_open(interface, &req, 0, NULL);
	if (nmr == NULL) {
		t01_log(T01_WARNING, "Unable to open %s: %s", tconfig.ifname,
			strerror(errno));
		exit(1);
	}

	if (tconfig.ofname[0] == 0
	    || strcmp(tconfig.ifname, tconfig.ofname) == 0) {
		out_nmr = nmr;
	} else {
		manage_interface_promisc_mode(tconfig.ofname, 1);
		t01_log(T01_DEBUG,
			"Please disable all types of offload for this NIC manually: ethtool -K %s gro off gso off tso off lro off",
			tconfig.ofname);
		sprintf(interface, "netmap:%s", tconfig.ofname);
		out_nmr = nm_open(interface, &req, 0, NULL);
		if (out_nmr == NULL) {
			t01_log(T01_WARNING,
				"Unable to open %s: %s, use %s instead",
				tconfig.ofname, strerror(errno),
				tconfig.ifname);
			out_nmr = nmr;
		}
	}

	workflow = setup_detection();
}

static void init_engine()
{
	if (tconfig.filter[0]) {
		char *temp = zstrdup(tconfig.filter), *p, *last = NULL;
		p = strtok_r(temp, ",", &last);
		while (p != NULL) {
			char protocol[64] = { 0 }, port[10] = {
			0};
			char *q = strstr(p, "/");
			if (q) {
				strncpy(port, p, q - p);
				strncpy(protocol, q + 1, strlen(q) - 1);
			} else {
				strcpy(port, p);
				strcpy(protocol, "all");
			}
			filters[n_filters].port = atoi(port);
			if (strcasecmp(protocol, "tcp") == 0)
				filters[n_filters].protocol = IPPROTO_TCP;
			else if (strcasecmp(protocol, "udp") == 0)
				filters[n_filters].protocol = IPPROTO_UDP;
			else if (strcasecmp(protocol, "all") == 0)
				filters[n_filters].protocol = 0;
			else
				filters[n_filters].protocol = 0xff;
			if (filters[n_filters].protocol != 0xff)
				n_filters++;
			if (MAX_FILTERS == n_filters)
				break;

			p = strtok_r(NULL, ",", &last);
		}
		zfree(temp);
	}

	pthread_spin_init(&mirror_lock, 0);
	if (tconfig.engine[0] && tconfig.engine_opt[0]) {
		if (load_ioengine(&backup_engine, tconfig.engine) < 0 ||
		    load_ioengine(&mirror_engine, tconfig.engine) < 0) {
			t01_log(T01_WARNING, "Unable to load engine %s",
				tconfig.engine);
		}

		if (init_ioengine(&mirror_engine, tconfig.engine_opt) < 0) {
			t01_log(T01_WARNING, "Unable to init mirror engine %s",
				tconfig.engine);
		} else {
			mirror = 1;
		}

		if (init_ioengine(&backup_engine, tconfig.engine_opt) < 0) {
			t01_log(T01_WARNING, "Unable to init backup engine %s",
				tconfig.engine);
		} else {
			backup = 1;
		}
	}
}

static void init_rulemgmt()
{
	char err[ANET_ERR_LEN];
	char *bind_ip;
	int port;

	if (tconfig.ruledb[0]) {
		int rule_num = load_rules(tconfig.ruledb);
		if (rule_num > 0) {
			t01_log(T01_NOTICE, "Load %d rules from file %s",
				rule_num, tconfig.ruledb);
		} else {
			rule_num = 0;
		}
	}

	if (tconfig.work_mode & NETMAP_MODE) {
		bind_ip = tconfig.rule_ip;
		port = tconfig.rule_port;
	} else {
		bind_ip = tconfig.master_ip;
		port = tconfig.master_port;
	}

	/* Open the TCP listening socket for the user commands. */
	if (port != 0) {
		if (bind_ip[0] == 0) {
			tcp_sofd = anetTcpServer(err, port, NULL, 64);
		} else {
			tcp_sofd = anetTcpServer(err, port, bind_ip, 64);
		}

		if (tcp_sofd == ANET_ERR) {
			t01_log(T01_WARNING,
				"Could not create server tcp listening socket %s:%d: %s",
				bind_ip[0] ? bind_ip : "*", port, err);
			exit(1);
		}
		t01_log(T01_NOTICE, "Succeed to bind tcp %s:%d", bind_ip, port);
		anetNonBlock(NULL, tcp_sofd);

		if (tconfig.work_mode & MASTER_MODE) {
			udp_logfd = anetUdpServer(err, port, bind_ip);
			if (udp_logfd == ANET_ERR) {
				t01_log(T01_WARNING,
					"Could not create server udp listening socket %s:%d: %s",
					bind_ip[0] ? bind_ip : "*", port, err);
				exit(1);
			}
			t01_log(T01_NOTICE, "Succeed to bind udp %s:%d",
				bind_ip, port);
			anetNonBlock(NULL, udp_logfd);
		}
	}

	/* Abort if there are no listening sockets at all. */
	if (tcp_sofd < 0) {
		t01_log(T01_WARNING,
			"Configured to not listen anywhere, exiting.");
		exit(1);
	}

	pthread_spin_init(&hitlog_lock, 0);
}

void close_listening_sockets()
{
	if (tcp_sofd != -1)
		close(tcp_sofd);
	if (udp_logfd != -1)
		close(udp_logfd);
}

static void exit_netmap()
{
	if (out_nmr != nmr)
		nm_close(out_nmr);
	nm_close(nmr);
}

static void exit_rulemgmt()
{
	if (tconfig.work_mode & NETMAP_MODE)
		destroy_rules();
	close_listening_sockets();
}

int main(int argc, char **argv)
{
	parse_options(argc, argv);

	init_system();
	init_engine();
	if (tconfig.work_mode & NETMAP_MODE)
		init_netmap();
	if (tconfig.work_mode & NETMAP_MODE || tconfig.work_mode & MASTER_MODE)
		init_rulemgmt();

	signal(SIGINT, signal_hander);
	signal(SIGTERM, signal_hander);
	main_thread();

	if (tconfig.work_mode & NETMAP_MODE)
		exit_netmap();
	if (tconfig.work_mode & NETMAP_MODE || tconfig.work_mode & MASTER_MODE)
		exit_rulemgmt();

	return 0;
}

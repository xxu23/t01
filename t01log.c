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
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <pthread.h>

#include "mysql.h"
#include "list.h"
#include "logger.h"
#include "anet.h"
#include "event.h"
#include "zmalloc.h"

#pragma pack(1)
struct log_rz_2
{	
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t local_ip;
	uint32_t time;
	uint32_t rule_id;
	uint8_t rule_type;
	uint8_t proto;
	uint16_t pktlen;
	struct list_head list;
};
#pragma pack()

#define BATCH_INSERT 64
#define MAX_THREADS 16

static struct list_head lists[ MAX_THREADS];
static pthread_t tids[MAX_THREADS];
static int consumed_pkts[MAX_THREADS];
static uint64_t total_pkts = 0;
static uint64_t last_pkts = 0;
static uint64_t total_consumed_pkts = 0;
static uint64_t last_consumed_pkts = 0;
static int shutdown_app = 0;

static char host[128];
static int port = 3306;
static char username[128];
static char password[128];
static char logfile[256];
static int daemon_mode = 0;
static int nthreads = 4;

static void *mysql_thread(void *args)
{
	long tid = (long)args;
	uint64_t total_pkt = 0;
	uint64_t last_pkt = 0;
	int cur_pkt = 0;
	char cmd[4096 * BATCH_INSERT];
	int offset = 0;
	MYSQL mysql;
	int st;

	t01_log(T01_NOTICE, "Enter thread %s:%d", __FUNCTION__, tid);	
	
	mysql_init(&mysql);
 	if (!mysql_real_connect(&mysql, host, username, password,"t01log", port, 0, 0)) {
		t01_log(T01_WARNING, "Cannot connect to mysql %s:%d: %s", host, port, mysql_error(&mysql));
 		return NULL;
	}
	
	if (mysql_query(&mysql, "set autocommit=0;") != 0) {
		t01_log(T01_WARNING, "Cannot disable auto commit: %s", mysql_error(&mysql));
	}

	while (!shutdown_app) {
		struct list_head *pos, *n;
		struct log_rz_2 *log;

		list_for_each_safe(pos, n, &lists[tid]) {
			log = list_entry(pos, struct log_rz_2, list);
			//pthread_spin_lock(&hitlog_lock);
			list_del(pos);
			//pthread_spin_unlock(&hitlog_lock);	

			if(cur_pkt == 0) {
				st = mysql_query(&mysql,"START TRANSACTION"); 
				if(st != 0) {
					t01_log(T01_WARNING, "Failed to transaction %s", mysql_error(&mysql));
		 			return;
				}
			}

			if (cur_pkt % BATCH_INSERT == 0)
				offset = sprintf(cmd, "insert into t01log values(%u,%u,%d,%d,%u,%u,%u,%d,%d,%d)",
					log->src_ip, log->dst_ip, log->src_port, log->dst_port, log->local_ip,
					log->time, log->rule_id, log->rule_type, log->proto, log->pktlen);
			else {
				int len = sprintf(cmd+offset, ", (%u,%u,%d,%d,%u,%u,%u,%d,%d,%d)",
					log->src_ip, log->dst_ip, log->src_port, log->dst_port, log->local_ip,
					log->time, log->rule_id, log->rule_type, log->proto, log->pktlen);
				offset += len;
			}			
			zfree(log);
			consumed_pkts[tid]++;

			if (++cur_pkt % BATCH_INSERT != 0) 
				continue;

			st = mysql_query(&mysql, cmd);
			if (st != 0) {
				t01_log(T01_WARNING, "Failed to insert %s", mysql_error(&mysql));
				continue;
			}

			if(cur_pkt == 1024*12) {
		 		st = mysql_query(&mysql,"COMMIT"); 
				if(st != 0) {
					t01_log(T01_WARNING, "Failed to commit %s", mysql_error(&mysql));
		 			continue;
				}
				cur_pkt = 0;
			}
		}
	}

	mysql_close(&mysql);
	t01_log(T01_NOTICE, "Leave thread %s:%d", __FUNCTION__, tid);
	return NULL;
}

void udp_server_can_read(int fd, short event, void *ptr)
{
	struct sockaddr_in addr;
	socklen_t len;
	int nread;
	int pktlen = offsetof(struct log_rz_2, list);
	struct log_rz_2 *log;
	static int idx = 0;

	log = zmalloc(sizeof(*log));
	if (!log) {
		struct log_rz_2 log2;
		recvfrom(fd, &log2, pktlen, 0, (struct sockaddr *)&addr, &len);
		return;
	}

	nread = recvfrom(fd, log, pktlen, 0, (struct sockaddr *)&addr, &len);
	if (nread <= 0)
		return;
	else if (nread != pktlen)
		return;

	if (log->local_ip == 0)
		log->local_ip = addr.sin_addr.s_addr;

	list_add_tail(&log->list, &lists[idx]);
	idx ++;
	if(idx == nthreads) idx = 0;

	total_pkts ++;
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

static void setup_threads()
{
	int i;

	for(i = 0; i < nthreads; i++) {
		INIT_LIST_HEAD(&lists[i]);
	}

	for(i = 0; i < nthreads; i++) {
		pthread_create(&tids[i], NULL, mysql_thread, (void *)i);
	}
}

static void finish_threads()
{
	int i;

	for(i = 0; i < nthreads; i++) {
                pthread_join(tids[i], NULL);
        }
}

void time_cb(evutil_socket_t fd, short event, void *arg)
{
	uint64_t pkt = total_pkts - last_pkts;
	uint64_t bytes = pkt * offsetof(struct log_rz_2, list);
	char buf[32], buf1[32];
	int i;
	uint64_t total = 0;

	t01_log(T01_NOTICE, "Traffic throughput: %s pps / %s/sec", 
		format_packets(pkt, buf), format_traffic(bytes, 0, buf1));
	last_pkts = total_pkts;

	for (i = 0;  i < nthreads; i++)
                total += consumed_pkts[i];
        total_consumed_pkts = total;
	pkt = total_consumed_pkts - last_consumed_pkts;
	bytes = pkt * offsetof(struct log_rz_2, list);
	t01_log(T01_NOTICE, "MySQL throughput: %s pps / %s/sec",
                format_packets(pkt, buf), format_traffic(bytes, 0, buf1));
	last_consumed_pkts = total_consumed_pkts;
}

struct event_base *base;
	
static void signal_hander(int sig)
{
	static int called = 0;
	t01_log(T01_WARNING, "Received control-C, shutdowning");
	if (called)
		return;
	else
		called = 1;
	shutdown_app = 1;
	event_base_loopexit(base, NULL);
}

static void usage()
{
	const char *cmd = "t01log";
	fprintf(stderr,
		"Usage: %s [options]\n"
		"\nOptions:\n"
		"\t-H host                   Connect to MySQL host\n"
		"\t-P port                   Port number to use for connecting to MySQL\n"
		"\t-u username               User for login MySQL\n"
		"\t-p password               Password to use when connecting to MySQL\n"
		"\t-d                        run in daemon mode or not\n"
		"\t-l log_file               logger into file or screen\n"
		"\t-T num                    Thread number to interact with MySQL\n"
		"", cmd);

	exit(0);
}

static void parse_options(int argc, char **argv)
{
	int opt;

	while ((opt =
		getopt(argc, argv, "dH:P:u:p:l:T:")) != EOF) {
		switch (opt) {
		case 'd':
			daemon_mode = 1;
			break;

		case 'H':
			strncpy(host, optarg, sizeof(host));
			break;

		case 'P':
			port = atoi(optarg);
			break;

		case 'T':
			nthreads = atoi(optarg);
			break;

		case 'u':
			strncpy(username, optarg, sizeof(username));
			break;

		case 'p':
			strncpy(password, optarg, sizeof(password));
			break;

		case 'l':
			strncpy(logfile, optarg, sizeof(logfile));
			break;

		case 'h':
			usage();
			break;

		default:
			usage();
			break;
		}
	}

	if (username[0] == 0 || password[0] == 0 || host[0] == 0) {
		usage();
	}
	if (nthreads > MAX_THREADS || nthreads <= 0)
		nthreads = 4;
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

int main(int argc, char *argv[])
{
	struct event ev, ev2;
	struct timeval tv;
	char err[256];
	int logfd;

	parse_options(argc, argv);
	if (daemon_mode) {
		daemonize();
	}
	init_log(T01_NOTICE, logfile);

	signal(SIGINT, signal_hander);
	signal(SIGTERM, signal_hander);

	setup_threads();

	logfd = anetUdpServer(err, 8061, "0.0.0.0");
	if (logfd == ANET_ERR) {
		t01_log(T01_WARNING,
			"Could not create server udp listening socket: %s", err);
		exit(1);
	}
	anetNonBlock(NULL, logfd);

	base = event_base_new();

	event_set(&ev, logfd, EV_READ | EV_PERSIST, udp_server_can_read, NULL);
	event_base_set(base, &ev);
	event_add(&ev, NULL);

	evutil_timerclear(&tv);
	tv.tv_sec = 1;
	event_assign(&ev2, base, -1, EV_PERSIST, time_cb, (void *)&ev2);
	event_add(&ev2, &tv);

	event_base_dispatch(base);

	close(logfd);

	finish_threads();

	return 0;
}

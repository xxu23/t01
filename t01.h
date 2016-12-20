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

#ifndef _T01_H_
#define _T01_H_

#define MAX_FILTERS 5000
#define DEFAULT_RULE_PORT 9899
#define DEFAULT_RULEDB "/var/lib/t01/dump.tdb"
#define DEFAULT_PID_FILE "/var/run/t01.pid"
#define MAX_BACKUP_DATA 65536

enum t01_work_mode {NONE_MODE=0x00, NETMAP_MODE=0x01, SLAVE_MODE=0x02, MASTER_MODE=0x04};

extern struct event_base *base;
extern int dirty;
extern int dirty_before_bgsave;
extern lastbgsave_status;
extern time_t lastsave;
extern pid_t tdb_child_pid;

extern time_t upstart;

struct t01_config {
	char ifname[32];
	char ofname[32];
	char ruledb[256];
	char logfile[256];
	char filter[MAX_FILTERS * 16];
	char engine[64];
	char engine_opt[256];
	int daemon_mode;
	char master_ip[32];
	int master_port;
	char rule_ip[32];
	int rule_port;
	char hit_ip[32];
	int hit_port;
	int verbose;
	int id;
	enum t01_work_mode work_mode;
};

extern struct t01_config tconfig;

extern uint64_t total_flow_bytes;
extern uint64_t raw_packet_count;
extern uint64_t ip_packet_count;
extern uint64_t ip_packet_count_out;
extern uint64_t total_wire_bytes, total_ip_bytes;
extern uint64_t total_ip_bytes_out;
extern uint64_t tcp_count, udp_count;
extern uint64_t hits; 
extern uint64_t bytes_per_second_in;
extern uint64_t bytes_per_second_out;
extern uint64_t pkts_per_second_in;
extern uint64_t pkts_per_second_out;

void close_listening_sockets();

void release_memory();

#endif

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

#include <stdint.h>

#define MAX_FILTERS 5000
#define DEFAULT_RULE_PORT 9899
#define DEFAULT_RULEDB "/var/lib/t01/dump.tdb"
#define DEFAULT_PID_FILE "/var/run/t01.pid"
#define MAX_PCAP_DATA 1600
#define PCAP_PROMISC 1
#define PCAP_TIMEOUT 0
#define MAX_PKT_LEN 1536

#ifdef __cplusplus
extern "C" {
#endif

enum t01_work_mode {
    MASTER_MODE = 0x01, ATTACK_MODE = 0x02, MIRROR_MODE = 0x04, SLAVE_MODE = 0x06
};

enum t01_eth_mode {
    NETMAP_MODE = 0x010, LIBPCAP_MODE = 0x20, PFRING_MODE = 0x40
};

extern struct event_base *base;
extern int dirty;
extern int dirty_before_bgsave;
extern int lastbgsave_status;
extern time_t lastsave;
extern pid_t tdb_child_pid;
extern char **argv_;
extern time_t upstart;

struct t01_config {
    char ifname[128];
    char ofname[32];
    char mfname[32];
    char ruledb[256];
    char logfile[256];
    char filter[MAX_FILTERS * 16];
    char engine[64];
    char mirror_engine_opt[256];
    int engine_reconnect;
    int engine_threads;
    int daemon_mode;
    char master_ip[32];
    uint16_t master_port;
    char rule_ip[32];
    uint16_t rule_port;
    char hit_ip[32];
    uint16_t hit_port;
    char remote_ip[32];
    uint16_t remote_port;
    int verbose;
    int sampling;
    int id;
    int max_clients;
    int cpu_thread;
    int raw_socket;
    int restart_if_crash;
    enum t01_work_mode work_mode;
    enum t01_eth_mode eth_mode;
    char this_mac_addr[32];
    char next_mac_addr[32];
    unsigned char this_mac[6];
    unsigned char next_mac[6];
    char detected_protocol[1024];
    char *bpf; /* bpf for libpcap */
};

extern struct t01_config tconfig;

extern uint64_t raw_packet_count;
extern uint64_t ip_packet_count;
extern uint64_t ip_packet_count_out;
extern uint64_t total_wire_bytes, total_ip_bytes;
extern uint64_t total_ip_bytes_out;
extern uint64_t tcp_count, udp_count;
extern uint64_t hits;
extern uint64_t cur_bytes_per_second_in;
extern uint64_t bytes_per_second_in;
extern uint64_t bytes_per_second_out;
extern uint64_t cur_pkts_per_second_in;
extern uint64_t pkts_per_second_in;
extern uint64_t pkts_per_second_out;

void close_listening_sockets();

#ifdef __cplusplus
}
#endif

#endif
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

#define _GNU_SOURCE
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
#include <sched.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <ndpi_api.h>
#include "ndpi_util.h"
#include "ndpi_protocol_ids.h"
#include "pktgen.h"
#include "rule.h"
#include "logger.h"
#include "t01.h"
#include "cJSON.h"
#include <net/netmap_user.h>
#include <event.h>

#define MAX_URLS 1000

static char urls[MAX_URLS][1024];
static int n_url = 0;
static int ids[MAX_URLS];
static struct ndpi_flow_info *flows[MAX_URLS];

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
static struct timeval upstart_tv;
static char conffile[256];
static uint8_t shutdown_app = 0;
static uint8_t cpu_thread = 0;
static struct timeval last_report_ts;
static uint64_t total_hits = 0;
static uint64_t total_matching = 0;
static uint64_t last_hits = 0;

static int match_type = 0;


static void load_config(const char *filename) {
    FILE *fp;
    char line[1024];
    n_url = 0;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        t01_log(T01_WARNING,
                "Cannot read config %s: %s, aborting now", filename, strerror(errno));
        exit(1);
    }

    while (!feof(fp)) {
        memset(line, 0, sizeof(line));
        fgets(line, sizeof(line), fp);
        if (line[0] == 0 || line[0] == ' ')
            continue;
        if (line[strlen(line) - 1] == '\n')
            line[strlen(line) - 1] = 0;
        if (line[0] == 0)
            continue;

        memcpy(urls[n_url++], line, sizeof(line));
    }
    fclose(fp);

    t01_log(T01_NOTICE, "total %d urls", n_url);
    printf("---n_url = %d\n", n_url);
}

static void usage() {
    const char *cmd = "tests_rule";
    fprintf(stderr,
            "Usage: %s [options]\n"
                    "\nOptions:\n"
                    "\t-c filename        configuration file\n"
                    "\t-t match_type	  0(linkedlist), 1(hashtable)\n"
                    "\n", cmd);

    exit(0);
}

static void parse_options(int argc, char **argv) {
    int opt;

    while ((opt =
                    getopt(argc, argv, "ht:c:C:")) != EOF) {
        switch (opt) {
            case 'c':
                strncpy(conffile, optarg, sizeof(conffile));
                break;

            case 't':
                match_type = atoi(optarg);
                break;

            case 'C':
                cpu_thread = atoi(optarg);
                break;

            case 'h':
                usage();
                break;

            default:
                usage();
                break;
        }
    }

    if (conffile[0])
        load_config(conffile);
}

static void setup_rules() {
    int i;
    int j = 0;
    for (j = 0; j < 5; j++)
        for (i = 0; i < n_url; i++) {
            char ip[16];
            cJSON *root = cJSON_CreateObject();
            cJSON *condition = cJSON_CreateObject();
            const char *param[1] = {"202.127.26.199:8080"};
            cJSON *params = cJSON_CreateStringArray(param, 1);

            sprintf(ip, "192.168.1.%d", i % 254 + 1);
            cJSON_AddStringToObject(root, "saddr", ip);
            /*
            if (i % 2 == 0)
                cJSON_AddStringToObject(root, "saddr", "192.168.1.2");
            else if (i % 3 == 0)
                cJSON_AddStringToObject(root, "saddr", "192.168.1.3");
            else if (i % 5 == 0)
                cJSON_AddStringToObject(root, "saddr", "192.168.1.1");
            else if (i % 7 == 0)
                cJSON_AddStringToObject(root, "saddr", "192.168.1.7");
            */

            if (i % 2 == 0)
                cJSON_AddNumberToObject(root, "dport", 80);
            else if (i % 3 == 0)
                cJSON_AddNumberToObject(root, "dport", 8080);

            cJSON_AddStringToObject(root, "protocol", "http");
            cJSON_AddStringToObject(root, "action", "redirect");

            cJSON_AddStringToObject(condition, "match", "match");
            cJSON_AddStringToObject(condition, "which", i % 2 == 0 ? "host" : "url");
            cJSON_AddStringToObject(condition, "payload", urls[i]);
            cJSON_AddItemToObject(root, "condition", condition);

            cJSON_AddItemToObject(root, "params", params);

            char *json = cJSON_PrintUnformatted(root);
            cJSON_Delete(root);

            char *result;
            size_t len;
            int r = create_rule(json, strlen(json), &result, &len);
            cJSON_FreePrint(json);
            if (r != 0) continue;

            root = cJSON_Parse(result);
            if (!root) continue;

            cJSON *item = cJSON_GetObjectItem(root, "id");
            if (item) ids[i] = item->valueint;
            cJSON_Delete(root);
        }
}

static void setup_ndpi_flows() {
    int i;
    for (i = 0; i < n_url; i++) {
        char ip[16];
        struct ndpi_flow_info *f1 = malloc(sizeof(struct ndpi_flow_info));
        struct ndpi_flow_info *f2 = malloc(sizeof(struct ndpi_flow_info));
        struct ndpi_flow_struct *fs1 = malloc(sizeof(struct ndpi_flow_struct));
        struct ndpi_flow_struct *fs2 = malloc(sizeof(struct ndpi_flow_struct));
        //f1->src_ip = f2->src_ip = i % 10 == 0 ? inet_addr("192.168.1.1") : inet_addr("192.168.100.1");

        /*if (i % 2 == 0)
            f1->src_ip = f2->src_ip = inet_addr("192.168.1.2");
        else if (i % 3 == 0)
            f1->src_ip = f2->src_ip = inet_addr("192.168.1.3");
        else if (i % 5 == 0)
            f1->src_ip = f2->src_ip = inet_addr("192.168.1.1");
        else if (i % 7 == 0)
            f1->src_ip = f2->src_ip = inet_addr("192.168.1.7");
        else if (i % 9 == 0)
            f1->src_ip = f2->src_ip = inet_addr("192.168.1.9");
        else
            f1->src_ip = f2->src_ip = inet_addr("192.168.1.10");
        */

        if (i % 2 == 0)
            sprintf(ip, "192.168.1.%d", i % 254 + 1);
        else
            sprintf(ip, "192.168.2.%d", i % 254 + 1);
        f1->src_ip = f2->src_ip = inet_addr(ip);

        f1->dst_ip = f2->dst_ip = rand() % 0xffffffff;
        f1->dst_port = f2->src_port = i % 2 == 0 ? 80 : 9090;
        f1->src_port = f2->dst_port = rand() % 10000 + 20000;
        f1->detection_completed = f2->detection_completed = 0;
        f1->protocol = f2->protocol = i % 15 == 0 ? 17 : 6;
        f1->detected_protocol.master_protocol = f2->detected_protocol.master_protocol =
                i % 15 == 0 ? NDPI_PROTOCOL_DNS : NDPI_PROTOCOL_HTTP;
        memcpy(f1->host_server_name, urls[i], 192);
        memcpy(f1->ssl.client_certificate, urls[i], 48);
        memcpy(f1->ssl.server_certificate, urls[i], 48);
        memcpy(f2->host_server_name, urls[i], 192);
        memcpy(f2->ssl.client_certificate, urls[i], 48);
        memcpy(f2->ssl.server_certificate, urls[i], 48);
        strcat(f2->host_server_name, "abcdefg");
        strcat(f2->ssl.client_certificate, "1234567890");
        strcat(f2->ssl.server_certificate, "ABCDEFG");
        fs1->http.url = strdup(urls[i]);
        fs2->http.url = strdup("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        f1->ndpi_flow = fs1;
        f2->ndpi_flow = fs2;

        flows[2 * i] = f1;
        flows[2 * i + 1] = f2;
    }
}

static void signal_hander(int sig) {
    static int called = 0;
    t01_log(T01_WARNING, "Received control-C, shutdowning");
    if (called)
        return;
    else
        called = 1;

    int i;
    for (i = 0; i < n_url; i++)
        delete_rule(ids[i]);
    shutdown_app = 1;
    event_base_loopexit(base, NULL);
}

static char *format_packets(float numPkts, char *buf) {

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

static void setup_cpuaffinity(int index, const char *name) {
    cpu_set_t m;
    CPU_ZERO(&m);
    CPU_SET(index - 1, &m);

    if (-1 == pthread_setaffinity_np(pthread_self(), sizeof(m), &m)) {
        t01_log(T01_WARNING, "failed to bind cpu %d to thread %s: %s",
                index, name, strerror(errno));
        return;
    }
    t01_log(T01_NOTICE, "succeed to bind cpu %d to thread %s",
            index, name);
}

static void *rulematch_thread(void *args) {
    int core = *((int *) args);

    if (core > 0)
        setup_cpuaffinity(core, __FUNCTION__);

    t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);

    setup_rules();
    setup_ndpi_flows();

    while (!shutdown_app) {
        int idx = rand() % n_url;
        struct ndpi_flow_info *flow2 = flows[idx * 2 + 1];
        int j = 0;
        for (j = 0; j < 10240; j++) {
            struct rule *rule2 =
                    match_type == 0 ? match_rule_after_detected(flow2) : match_rule_from_htable_after_detected(flow2);
            total_matching++;
            if (!rule2) continue;
            total_hits++;
        }
        struct ndpi_flow_info *flow1 = flows[idx * 2];
        struct rule *rule1 = match_rule_after_detected(flow1);
        total_matching++;
        if (!rule1)
            continue;
        total_hits++;
    }

    t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
    return NULL;
}


static void statistics_cb(evutil_socket_t fd, short event, void *arg) {
    struct timeval curr_ts;
    uint64_t tot_usec, since_usec;
    uint64_t curr_raw_packet_count = total_matching - raw_packet_count;
    uint64_t curr_hits = total_hits - last_hits;

    gettimeofday(&curr_ts, NULL);
    tot_usec =
            curr_ts.tv_sec * 1000000 + curr_ts.tv_usec -
            (last_report_ts.tv_sec * 1000000 + last_report_ts.tv_usec);
    since_usec =
            curr_ts.tv_sec * 1000000 + curr_ts.tv_usec -
            (upstart_tv.tv_sec * 1000000 + upstart_tv.tv_usec);
    last_report_ts = curr_ts;

    raw_packet_count = total_matching;

    if (since_usec > 0) {
        pkts_per_second_in = raw_packet_count * 1000000.0f / since_usec;
    }

    printf("\nTraffic statistics:\n");
    printf("\tMatching packets:      %llu packets total\n", curr_raw_packet_count);

    if (tot_usec > 0) {
        char buf[32];
        float t = curr_raw_packet_count * 1000000.0f / tot_usec;
        float traffic_duration = tot_usec;
        printf("\tTraffic throughput:    %s pps\n", format_packets(t, buf));
        printf("\tTraffic duration:      %.3f sec\n",
               traffic_duration / 1000000);
        printf("\tMean throughput:       %s pps\n",
               format_packets(pkts_per_second_in, buf));
    }

    printf("\tRules hits:            %llu\n", curr_hits);
    last_hits = total_hits;
}

static void *libevent_thread(void *args) {
    struct event ev0, ev1, ev2, ev3, ev4;
    struct timeval tv2, tv3, tv4;
    int core = *((int *) args);

    if (core > 0)
        setup_cpuaffinity(core, __FUNCTION__);

    /* initialize libevent */
    t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);
    base = event_base_new();


    event_assign(&ev2, base, -1, EV_PERSIST, statistics_cb,
                 (void *) &ev2);
    evutil_timerclear(&tv2);
    tv2.tv_sec = 2;
    event_add(&ev2, &tv2);

    event_base_dispatch(base);

    t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
}

static void main_thread() {
    int err, i, nthreads = 0, j = 0;
    pthread_t threads[2];
    int affinity[2] = {0};

    for (i = 0; i < 2; i++) {
        if (cpu_thread > 0)
            affinity[i] = cpu_thread + i;
    }

    gettimeofday(&last_report_ts, NULL);

    if (pthread_create(&threads[nthreads++], NULL, rulematch_thread,
                       &affinity[j++]) != 0) {
        t01_log(T01_WARNING, "Can't create rulematch thread: %s",
                strerror(errno));
        exit(1);
    }

    if (pthread_create(&threads[nthreads++], NULL, libevent_thread,
                       &affinity[j++]) != 0) {
        t01_log(T01_WARNING, "Can't create libevent thread: %s",
                strerror(errno));
        exit(1);
    }

    for (i = 0; i < nthreads; i++) {
        pthread_join(threads[i], NULL);
    }
}

static void init_system() {
    lastsave = upstart = time(NULL);
    gettimeofday(&upstart_tv, NULL);
    init_rules(0);
}

void close_listening_sockets() {
}

int main(int argc, char **argv) {
    parse_options(argc, argv);

    init_system();

    signal(SIGINT, signal_hander);
    signal(SIGTERM, signal_hander);
    main_thread();

    return 0;
}
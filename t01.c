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
#include <errno.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <inttypes.h>
#include <net/if.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/resource.h>

#include <ndpi_api.h>
#include <event.h>
#include <pcap.h>
#include <pfring.h>
#include <stdint.h>

#include "t01.h"
#include "config.h"
#include "ndpi_util.h"
#include "pktgen.h"
#include "rule.h"
#include "anet.h"
#include "logger.h"
#include "ioengine.h"
#include "http-server.h"
#include "zmalloc.h"
#include "util.h"
#include "atomicvar.h"
#include "myqueue.h"


#define MAX_THREADS 64
#define MAX_ENGINE_THREADS 8

struct attack_header {
    char magic[8];
    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    int self_len;
    int data_len;
};

#define MAGIC "\x7aT\x85@\xaf$\xd0$"

#define INIT_HEADER(sip, dip, sport, dport, len) \
    {MAGIC, sip, dip, sport, dport, sizeof(struct attack_header), len};

struct attack_data {
    struct ndpi_flow_info *flow;
    struct rule *rule;
    char buffer[1560];
    int len;
    uint8_t smac[6];
    uint8_t dmac[6];
};

int dirty = 0;
int dirty_before_bgsave;
int lastbgsave_status;
time_t lastsave;
pid_t tdb_child_pid = -1;
time_t upstart;
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
uint64_t cur_bytes_per_second_in = 0;
uint64_t cur_pkts_per_second_in = 0;
uint64_t total_pkts_ndpi = 0;
uint64_t last_pkts_ndpi = 0;
uint64_t pkts_ndpi_per_second = 0;
struct event_base *base;
struct evhttp *http;
struct evhttp_bound_socket *handle;
char **argv_;
struct t01_config tconfig;

static struct ndpi_workflow *workflow;
static myqueue attack_queue;
static ZLIST_HEAD(hitslog_list);
static struct timeval upstart_tv;
static int udp_logfd;
static struct nm_desc *nmr, *out_nmr;
static int sendfd;
static uint8_t shutdown_app = 0;
static myqueue mirror_queues[MAX_ENGINE_THREADS];
static struct ioengine_data mirror_engines[MAX_ENGINE_THREADS];
static int is_mirror = 0;
static int is_attack = 0;
static int enable_all_protocol = 1;
static struct timeval last_report_ts;
static NDPI_PROTOCOL_BITMASK ndpi_mask;
static pthread_spinlock_t hitlog_lock;
static char *bind_ip;
static int bind_port;
static char errBuf[PCAP_ERRBUF_SIZE];
static pcap_t *device;
static pcap_t *out_device;
static pfring *in_ring;
static pfring *out_ring;
static pthread_t threads[MAX_THREADS];
static int affinity[MAX_THREADS] = {0};
static int nthreads;
static uint64_t total_out_mqueue;
static uint64_t total_in_mqueue;
static uint64_t last_out_mqueue;
static uint64_t last_in_mqueue;

static struct filter_strategy {
    uint8_t protocol;
    uint16_t port;
} filters[MAX_FILTERS];
static int n_filters;

struct filter_buffer {
    uint64_t ts;
    int len;
    int protocol;
    uint32_t hash_idx;
    char buffer[0];
};

struct hits_log_rz {
    struct list_head list;
    struct log_rz hit;
};

static void process_hitslog(struct rule *rule, struct ndpi_flow_info *flow,
                            uint8_t *smac, uint8_t *dmac) {
    if (tconfig.work_mode & SLAVE_MODE ||
        (tconfig.hit_ip[0] && tconfig.hit_port)) {
        /* Send log to master or log server */
        struct hits_log_rz *hl = tcalloc(1, sizeof(*hl));
        if (!hl)
            return;
        rule->hits++;
        hl->hit.rule_id = rule->id;
        hl->hit.rule_type = rule->type;
        hl->hit.rule_action = rule->action;
        hl->hit.pktlen = flow->pktlen;
        hl->hit.proto = flow->protocol;
        hl->hit.time = flow->last_seen / 1000;
        hl->hit.src_ip = flow->src_ip;
        hl->hit.dst_ip = flow->dst_ip;
        hl->hit.src_port = flow->src_port;
        hl->hit.dst_port = flow->dst_port;
        hl->hit.local_ip = 0;
        memcpy(hl->hit.smac, smac, 6);
        memcpy(hl->hit.dmac, dmac, 6);

        pthread_spin_lock(&hitlog_lock);
        list_add_tail(&hl->list, &hitslog_list);
        pthread_spin_unlock(&hitlog_lock);
    } else {
        /* Store in local disk */
        add_hit_record(rule, flow->last_seen / 1000,
                       flow->src_ip, flow->dst_ip,
                       flow->src_port, flow->dst_port,
                       smac, dmac,
                       0, flow->protocol, flow->pktlen);
    }
}

static int mirror_filter_from_rule(struct ndpi_flow_info *flow, void *packet) {
    struct rule *rule = match_rule_before_mirrored(flow);
    if (!rule)
        return 0;

    process_hitslog(rule, flow, (uint8_t *) packet + 6, (uint8_t *) packet);

    return 1;
}

static inline int netflow_data_filter(struct ndpi_flow_info *flow, void *packet) {
    if (n_filters == 0)
        return 1;

    int i;
    for (i = 0; i < n_filters; i++) {
        if (filters[i].protocol == 0) {
            if (filters[i].port == 0)
                return 1;
            else if (filters[i].port == flow->dst_port ||
                    filters[i].port == flow->src_port)
                return 1;
        } else if (filters[i].protocol == flow->protocol &&
                (filters[i].port == 0 || filters[i].port == flow->dst_port ||
                        filters[i].port == flow->src_port))
            return 1;
    }
    return 0;
}

static void netflow_data_clone(void *data, uint32_t n, uint32_t hash_idx,
                               uint8_t protocol, uint64_t ts) {
    static int round = 0;
    struct filter_buffer *fb = zmalloc(sizeof(struct filter_buffer) + n);
    if (!fb)
        return;

    memcpy(fb->buffer, data, n);
    fb->len = n;
    fb->hash_idx = hash_idx;
    fb->protocol = protocol;
    fb->ts = ts;

    if (myqueue_push(mirror_queues[round], fb) != 0) {
        zfree(fb);
    } else {
        total_in_mqueue++;
        if (++round >= tconfig.engine_threads)
            round = 0;
    }
}

static void mirror_match_filter(struct ndpi_workflow * workflow, struct nm_pkthdr *header, const u_char *packet){
    u_int64_t time = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);
    if(workflow->last_time > time) {
        time = workflow->last_time;
    }
    workflow->last_time = time;
    workflow->stats.raw_packet_count++;
    workflow->stats.ip_packet_count++;
    workflow->stats.total_wire_bytes += header->len + 24 ;
    workflow->stats.total_ip_bytes += header->len;

    if (n_filters == 0 || header->len <= 64)
        return;

    uint8_t protocol;
    uint16_t src_port;
    uint16_t dst_port;
    struct iphdr *ippkt = (struct iphdr *) &packet[sizeof(struct ndpi_ethhdr)];
    protocol = ippkt->protocol;
    
    if(protocol == 6) {
        workflow->stats.tcp_count++;
        struct tcphdr *tcppkt = (struct tcphdr *)(ippkt + 1);
        src_port = htons(tcppkt->source);
        dst_port = htons(tcppkt->dest);
        workflow->stats.port_counter[dst_port]++;
        workflow->stats.port_counter_bytes[dst_port] += header->len;
    } else if(protocol == 17){
        workflow->stats.udp_count++;
        struct udphdr *udppkt = (struct udphdr *)(ippkt + 1);
        src_port = htons(udppkt->source);
        dst_port = htons(udppkt->dest);
        workflow->stats.port_counter[dst_port]++;
        workflow->stats.port_counter_bytes[dst_port] += header->len;
    } else {
        return;
    } 

    int i;
    int matched = 0;
    for (i = 0; i < n_filters; i++) {
        uint8_t fprotocol = filters[i].protocol;
        uint16_t fport = filters[i].port;
        if (fprotocol == 0) {
            if (fport == 0){
                matched = 1;
                break;
            } else if (fport == dst_port || fport == src_port){
                matched = 1;
                break;
            }
        } else if (fprotocol == protocol && (fport == 0 || fport == dst_port || fport == src_port)){
                matched = 1;
                break;
        }
    }

    if (matched) {
        uint32_t idx = ippkt->saddr + ippkt->daddr + ippkt->protocol + src_port + dst_port;
        netflow_data_clone(packet, header->len, idx, protocol, workflow->last_time);
    }
}

static void create_pidfile(void) {
    FILE *fp = fopen(DEFAULT_PID_FILE, "w");
    if (fp) {
        fprintf(fp, "%d\n", (int) getpid());
        fclose(fp);
    }
}

static void daemonize(void) {
    int fd;

    if (fork() != 0)
        exit(0);    /* parent exits */
    setsid();        /* create a new session */

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

static void segv_handler(int sig, siginfo_t *info, void *secret) {
    int childpid;

    t01_log(T01_WARNING,
            "    T01 crashed by signal: %d", sig);
    t01_log(T01_WARNING,
            "    SIGSEGV caused by address: %p", (void *) info->si_addr);

    evhttp_free(http);
    event_base_loopexit(base, NULL);

    if ((childpid = fork()) != 0) {
        struct sigaction act;
        sigemptyset(&act.sa_mask);
        act.sa_flags = SA_NODEFER | SA_ONSTACK | SA_RESETHAND;
        act.sa_handler = SIG_DFL;
        sigaction(sig, &act, NULL);
        kill(getpid(), sig);
        exit(0);    /* parent exits */
    }
    t01_log(T01_WARNING, "Restarting childpid %d", getpid());

    execv(argv_[0], argv_);
}

static void signal_hander(int sig) {
    static int called = 0;
    int save = dirty != 0;
    t01_log(T01_WARNING, "Received control-C, shutdowning");
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
    if (tconfig.work_mode & SLAVE_MODE) {
        if (tconfig.eth_mode & LIBPCAP_MODE) {
            pcap_breakloop(device);
        } else if (tconfig.eth_mode & PFRING_MODE) {
            pfring_breakloop(in_ring);
        }
    }
    event_base_loopexit(base, NULL);
}

static void on_protocol_discovered(struct ndpi_workflow *workflow,
                                   struct ndpi_flow_info *flow, void *header,
                                   void *packet) {
    if ((tconfig.verbose & 2) && flow->log_flag) {
        t01_log(T01_NOTICE, "Completed nDPI : %x:%d <--> %x:%d",
                flow->src_ip, flow->src_port,
                flow->dst_ip, flow->dst_port);
    }

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

    total_pkts_ndpi++;
    struct rule *rule = match_rule_from_htable_after_detected(flow);
    if ((tconfig.verbose & 2) && flow->log_flag) {
        t01_log(T01_NOTICE, "Completed rule matching : %x:%d <--> %x:%d",
                flow->src_ip, flow->src_port,
                flow->dst_ip, flow->dst_port);
    }
    if (!rule)
        return;

    if (is_mirror && rule->action == T01_ACTION_MIRROR) {
        netflow_data_clone(packet, workflow->__packet_header->len, flow->hash_idx,
                           flow->protocol, workflow->last_time);
        return;
    } else if (is_attack == 0)
        return;

    struct attack_data *attack = zmalloc(sizeof(*attack));
    if (!attack)
        return;
    char *result = attack->buffer;
    int len = sizeof(attack->buffer);
    len = make_packet(rule, packet, result, len, flow);
    if (len == 0) {
        zfree(attack);
        return;
    }
    attack->len = len;
    attack->rule = rule;
    attack->flow = flow;
    memcpy(attack->smac, (uint8_t *) packet + 6, 6);
    memcpy(attack->dmac, (uint8_t *) packet, 6);
    if (myqueue_push(attack_queue, attack) < 0) {
        zfree(attack);
    } else {
        total_ip_bytes_out += len;
        ip_packet_count_out++;
    }
    if (tconfig.verbose & 2) {
        t01_log(T01_NOTICE, "Completed packet faking : %x:%d <--> %x:%d",
                flow->src_ip, flow->src_port,
                flow->dst_ip, flow->dst_port);
    }
}

static void setup_ndpi_protocol_mask(struct ndpi_workflow *workflow) {
    char *protocols = zstrdup(tconfig.detected_protocol);
    if (protocols[0] == 0 || strstr(protocols, "all")) {
        // enable all protocols
        t01_log(T01_NOTICE, "Enable all procotols into ndpi mask");
        NDPI_BITMASK_SET_ALL(ndpi_mask);
        ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &ndpi_mask);
        zfree(protocols);
        return;
    }

    char *p, *q;
    uint8_t prot = 0;
    p = strtok_r(protocols, ",", &q);
    while (p != NULL) {
        if (strcasecmp(p, "http") == 0)
            prot = NDPI_PROTOCOL_HTTP;
        else if (strcasecmp(p, "dns") == 0)
            prot = NDPI_PROTOCOL_DNS;
        else if (strcasecmp(p, "pptp") == 0)
            prot = NDPI_PROTOCOL_PPTP;
        else if (strcasecmp(p, "ssh") == 0)
            prot = NDPI_PROTOCOL_SSH;
        else if (strcasecmp(p, "https") == 0)
            prot = NDPI_PROTOCOL_SSL;
        else if (strcasecmp(p, "socks") == 0)
            prot = NDPI_PROTOCOL_SOCKS;
        else if (strcasecmp(p, "ipsec") == 0)
            prot = NDPI_PROTOCOL_IP_IPSEC;
        else if (strcasecmp(p, "pop") == 0)
            prot = NDPI_PROTOCOL_MAIL_POP;
        else if (strcasecmp(p, "smtp") == 0)
            prot = NDPI_PROTOCOL_MAIL_SMTP;
        else if (strcasecmp(p, "imap") == 0)
            prot = NDPI_PROTOCOL_MAIL_IMAP;

        if (prot > 0) {
            t01_log(T01_NOTICE, "Add procotol %s into ndpi mask", p);
            NDPI_BITMASK_ADD(ndpi_mask, prot);
        }

        p = strtok_r(NULL, ",", &q);
    }
    ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &ndpi_mask);
    zfree(protocols);
}

struct ndpi_workflow *setup_detection() {
    struct ndpi_workflow *workflow;
    struct ndpi_workflow_prefs prefs;
    uint64_t total_ram = get_total_ram();
    u_int32_t max_ndpi_flows;

    max_ndpi_flows = total_ram / 2 / sizeof(struct ndpi_flow_info);
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
                                             (void *) (uintptr_t) workflow);
    ndpi_set_mirror_data_callback(workflow,
                                  is_mirror ? netflow_data_clone : NULL,
                                  is_mirror ? netflow_data_filter : NULL);

    setup_ndpi_protocol_mask(workflow);

    // clear memory for results
    memset(workflow->stats.protocol_counter, 0,
           sizeof(workflow->stats.protocol_counter));
    memset(workflow->stats.protocol_counter_bytes, 0,
           sizeof(workflow->stats.protocol_counter_bytes));
    memset(workflow->stats.protocol_flows, 0,
           sizeof(workflow->stats.protocol_flows));
    memset(workflow->stats.port_counter_bytes, 0,
           sizeof(workflow->stats.port_counter_bytes));
    memset(workflow->stats.port_counter, 0,
           sizeof(workflow->stats.port_counter));

    return workflow;
}

static void setup_cpuaffinity(int index, const char *name) {
    cpu_set_t m;

    index = affinity[index] + tconfig.cpu_thread;
    CPU_ZERO(&m);
    CPU_SET(index, &m);

    if (-1 == pthread_setaffinity_np(pthread_self(), sizeof(m), &m)) {
        t01_log(T01_WARNING, "failed to bind cpu %d to thread %s: %s",
                index, name, strerror(errno));
        return;
    }
    t01_log(T01_NOTICE, "succeed to bind cpu %d to thread %s",
            index, name);
}

static void send_via_socket(uint32_t sip, uint32_t dip, uint16_t src_port, uint16_t dst_port,
                            const char *data, int len) {
    if (sendfd <= 0)
        return;

    struct pollfd pfds[1];
    pfds[0].fd = sendfd;
    pfds[0].events = POLLIN | POLLOUT;
    poll(pfds, 1, 0);
    if (pfds[0].revents & POLLIN) {
        char buffer[1024];
        int n = read(sendfd, buffer, 1024);
        if (n == 0) {
            t01_log(T01_WARNING, "Disconnect from remote socket");
            close(sendfd);
            sendfd = -1;
            return;
        }
    } else if (pfds[0].revents & POLLOUT) {
        struct attack_header header = INIT_HEADER(sip, dip, src_port, dst_port, len);
        int n;
        if ( ((n=anetWrite(sendfd, &header, sizeof(header))) < 0
              || (n=anetWrite(sendfd, data, len)) < 0) && tconfig.raw_socket == 2) {
            close(sendfd);
            sendfd = -1;
        }
    }
}

static void *attack_thread(void *args) {
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 1};
    int core = *((int *) args);
    enum t01_eth_mode eth_mode = tconfig.eth_mode;

    t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);

    if (core >= 0)
        setup_cpuaffinity(core, __FUNCTION__);
    pthread_setname_np(pthread_self(), __FUNCTION__);

    while (!shutdown_app) {
        struct attack_data *attack = NULL;
        myqueue_pop(attack_queue, (void**)&attack);
        if (attack == NULL) {
            nanosleep(&ts, NULL);
            continue;
        }

        struct ndpi_flow_info *flow = attack->flow;
        struct rule *rule = attack->rule;
        if (flow && is_ndpi_flow_info_used(flow) == 0) {
            zfree(attack);
            continue;
        }
        if (flow)
            process_hitslog(rule, flow, attack->smac, attack->dmac);
        else 
            rule->hits++;

        int len = attack->len;
        char *result = attack->buffer;
        if (len == 0) {
            zfree(attack);
            continue;
        }

        if (eth_mode & NETMAP_MODE) {
            if (out_nmr)
                nm_inject(out_nmr, result, len);
            else if (sendfd > 0) {
                if (tconfig.raw_socket == 1) {
                    anetWrite(sendfd, result, len);
                } else {
                    send_via_socket(flow->src_ip, flow->dst_ip, flow->src_port, flow->dst_port, result, len);
                }
            }
        } else if (eth_mode & LIBPCAP_MODE) {
            if (out_device)
                pcap_inject(out_device, result, len);
            else if (sendfd > 0) {
                if (tconfig.raw_socket == 1) {
                    anetWrite(sendfd, result, len);
                } else {
                    send_via_socket(flow->src_ip, flow->dst_ip, flow->src_port, flow->dst_port, result, len);
                }
            }
        } else if (eth_mode & PFRING_MODE) {
            if (out_ring)
                pfring_send(out_ring, result, len, 0);
            else if (sendfd > 0) {
                if (tconfig.raw_socket == 1) {
                    anetWrite(sendfd, result, len);
                } else {
                    send_via_socket(flow->src_ip, flow->dst_ip, flow->src_port, flow->dst_port, result, len);
                }
            }
        }

        if (flow && tconfig.verbose) {
            char l[48], u[48];
            char msg[4096];
            int offset = 0;

            if (tconfig.verbose & 2)
                t01_log(T01_NOTICE, "Completed packet sending : %x:%d <--> %x:%d",
                    flow->src_ip, flow->src_port,
                    flow->dst_ip, flow->dst_port);

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
        zfree(attack);
    }

    t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
    return NULL;
}

static void *mirror_thread(void *args) {
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 1};
    int index = *((int *) args);
    time_t last = time(NULL);
    struct ioengine_data *mirror_engine = &mirror_engines[index];
    myqueue mirror_queue = mirror_queues[index];

    if (index >= 0)
        setup_cpuaffinity(index, __FUNCTION__);

    t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);

    while (!shutdown_app) {
        struct filter_buffer *fb = NULL;
        myqueue_pop(mirror_queue, (void**)&fb);
        if (fb == NULL) {
            nanosleep(&ts, NULL);
            continue;
        }
        atomicIncr(total_out_mqueue, 1);

        if (store_raw_via_ioengine(mirror_engine, fb->buffer, fb->len,
                                   fb->hash_idx, fb->protocol, fb->ts) < 0) {
            time_t now = time(NULL);
            if (now - last >= 5) {
                t01_log(T01_WARNING,
                        "failed to write mirror ioengine, reconnect every 5 seconds");
                check_ioengine(mirror_engine);
                last = now;
            }
        }
        zfree(fb);
    }

    t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
    return NULL;
}

static void statistics_cb(evutil_socket_t fd, short event, void *arg) {
    struct ndpi_stats *stat = &workflow->stats;
    struct timeval curr_ts;
    uint64_t tot_usec, since_usec;
    uint64_t total_hits = 0;
    uint64_t curr_ip_packet_count = stat->ip_packet_count - ip_packet_count;
    uint64_t curr_total_wire_bytes =
            stat->total_wire_bytes - total_wire_bytes;
    uint64_t curr_total_ip_bytes = stat->total_ip_bytes - total_ip_bytes;
    uint64_t curr_tcp_count = stat->tcp_count - tcp_count;
    uint64_t curr_udp_count = stat->udp_count - udp_count;
    uint64_t curr_hits;
    uint64_t curr_pkts_ndpi = total_pkts_ndpi - last_pkts_ndpi;
    uint64_t curr_mirrored_in = total_in_mqueue - last_in_mqueue;
    uint64_t curr_mirrored_out = total_out_mqueue - last_out_mqueue;

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
    last_pkts_ndpi = total_pkts_ndpi;
    last_in_mqueue = total_in_mqueue;
    last_out_mqueue = total_out_mqueue;
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
    if (tconfig.eth_mode & NETMAP_MODE) {
        printf("\tNetmap recv/drop:     %llu / %llu\n", nmr->st.ps_recv, nmr->st.ps_drop);
    } else if (tconfig.eth_mode & LIBPCAP_MODE) {
        struct pcap_stat pstat;
        pcap_stats(device, &pstat);
        printf("\tLibpcap recv/drop:     %llu / %llu\n", pstat.ps_recv, pstat.ps_drop);
    } else if (tconfig.eth_mode & PFRING_MODE) {
        pfring_stat pfstat;
        pfring_stats(in_ring, &pfstat);
        printf("\tPFRING recv/drop:      %llu / %llu\n", pfstat.recv, pfstat.drop);
    }
    printf("\tIP bytes:              %-13llu (avg pkt size %u bytes)\n",
           curr_total_ip_bytes, stat->total_ip_bytes/(raw_packet_count == 0 ? 1 : raw_packet_count));
    printf("\tTCP Packets:           %-13lu\n", curr_tcp_count);
    printf("\tUDP Packets:           %-13lu\n", curr_udp_count);

    if (tot_usec > 0) {
        char buf[32], buf1[32];
        cur_pkts_per_second_in =
                curr_ip_packet_count * 1000000.0 / tot_usec;
        cur_bytes_per_second_in =
                curr_total_ip_bytes * 8 * 1000000.0 / tot_usec;
        pkts_ndpi_per_second = curr_pkts_ndpi * 1000000.0 / tot_usec;
        printf("\tTraffic duration:      %.3f sec (total %.3f sec)\n",
               tot_usec / 1000000.0, since_usec / 1000000.0);
        printf("\tTraffic throughput:    %s pps / %s/sec\n",
               format_packets(curr_ip_packet_count*1000000.0/tot_usec, buf),
               format_traffic(cur_bytes_per_second_in, 1, buf1));
        printf("\tnDPI throughput:       %s pps (total %s pkt)\n",
               format_packets(pkts_ndpi_per_second, buf),
               format_packets(total_pkts_ndpi, buf1));
        if (is_mirror) {
            uint64_t qin = curr_mirrored_in * 1000000.0 / tot_usec;
            uint64_t qout = curr_mirrored_out * 1000000.0 / tot_usec;
            printf("\tMirroring throughput:  in %s pps / out %s pps\n",
                   format_packets(qin, buf), format_packets(qout, buf1));
        }
        printf("\tIncoming throughput:   %s pps / %s/sec\n",
               format_packets(pkts_per_second_in, buf),
               format_traffic(bytes_per_second_in, 1, buf1));
        printf("\tOutcoming throughput:  %s pps / %s/sec\n",
               format_packets(pkts_per_second_out, buf),
               format_traffic(bytes_per_second_out, 1, buf1));
        if (is_mirror) {
            if (tconfig.verbose & 4) {
                int j;
                u_int64_t totalpkts = 0, totalbytes = 0;
                u_int64_t *counts = stat->port_counter;
                u_int64_t *bytes = stat->port_counter_bytes;
                u_int16_t ports[] = {21, 22, 23, 25, 53, 80, 110, 143, 443,
                                     465, 587, 993, 995, 1080, 1812, 1813,
                                     3306, 3389, 4000, 6379, 8000, 8080, 9200};
                char portss[20480];
                int offset = 0;

                for (j = 0; j < sizeof(ports) / sizeof(ports[0]); j++) {
                    u_int16_t p = ports[j];
                    offset += snprintf(portss + offset, sizeof(portss) - offset,
                                       "%d:%llu pkt(%llu bytes), ",
                                       p, counts[p], bytes[p]);
                }
                for (j = 0; j < 65536; j++) {
                    totalpkts += counts[j];
                    totalbytes += bytes[j];
                }
                snprintf(portss + offset, sizeof(portss) - offset,
                         "total:%llu pkt (%llu bytes)",
                         totalpkts, totalbytes);
                printf("\tPort distribution:     %s\n", portss);
            }

            uint64_t qin = curr_mirrored_in * 1000000.0 / tot_usec;
            uint64_t qout = curr_mirrored_out * 1000000.0 / tot_usec;
            printf("\tMirroring throughput:  in %s pps / out %s pps\n",
                   format_packets(qin, buf), format_packets(qout, buf1));
        }
    }

    curr_hits = total_hits - hits;
    printf("\tRules hits:            %-13lu (total %llu)\n",
           curr_hits, total_hits);
    hits = total_hits;
}

static void rulesaving_cb(evutil_socket_t fd, short event, void *arg) {
    time_t unix_time = time(NULL);

    static struct saveparam {
        time_t seconds;
        int changes;
    } saveparams[] = {{
                              300, 1},
                      {
                              60,  30},
                      {
                              5,   500},
                      {
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
                        (long) pid);
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
                        sp->changes, (int) sp->seconds);
                save_rules_background(tconfig.ruledb);
                break;
            }
        }
    }
}

static void slave_cb(evutil_socket_t fd, short event, void *arg) {
    slave_registry_master(tconfig.master_ip, tconfig.master_port,
                          tconfig.rule_port);
}

static void master_cb(evutil_socket_t fd, short event, void *arg) {
    master_check_slaves();
}

static void *hitslog_thread(void *args) {
    struct sockaddr_in addr[2];
    socklen_t addr_len[2] = {sizeof(addr[0]), sizeof(addr[1])};
    int fd[2];
    char err[ANET_ERR_LEN];
    char *udp_ip[2];
    int udp_port[2];
    size_t offset[2] = {0, 0};
    int log_len[2];
    int count = 0, i;
    int core = *((int *) args);

    t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);

    if (core >= 0)
        setup_cpuaffinity(core, __FUNCTION__);
    pthread_setname_np(pthread_self(), "hitslog_thread");
    if (tconfig.hit_ip[0] && tconfig.hit_port) {
        udp_ip[count] = tconfig.hit_ip;
        udp_port[count] = tconfig.hit_port;
        offset[count] = offsetof(struct log_rz, src_ip);
        log_len[count] = sizeof(struct log_rz) - offset[count];
        count++;
    }
    if (tconfig.master_ip[0] && tconfig.master_port) {
        udp_ip[count] = tconfig.master_ip;
        udp_port[count] = tconfig.master_port;
        offset[count] = 0;
        log_len[count] = sizeof(struct log_rz);
        count++;
    }
    for (i = 0; i < count; i++) {
        fd[i] = anetCreateUdpSocket(err, udp_ip[i], udp_port[i],
                                    (struct sockaddr *) &addr[i], addr_len[i]);
        if (fd[i] < 0) {
            t01_log(T01_WARNING, "Cannot create socket: %s", err);
            goto leave;
        }
    }

    while (!shutdown_app) {
        struct list_head *pos, *n;
        struct hits_log_rz *hlr;
        if (list_empty(&hitslog_list)) {
            usleep(1000);
            continue;
        }

        list_for_each_safe(pos, n, &hitslog_list) {
            hlr = list_entry(pos, struct hits_log_rz, list);
            pthread_spin_lock(&hitlog_lock);
            list_del(pos);
            pthread_spin_unlock(&hitlog_lock);

            for (i = 0; i < count; i++)
                anetUdpWrite(fd[i], (char *) &hlr->hit + offset[i], log_len[i],
                             (struct sockaddr *) &addr[i], addr_len[i]);
            zfree(hlr);
        }
    }

    for (i = 0; i < count; i++)
        close(fd[i]);

    leave:
    t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
    return NULL;
}

static void udp_server_can_read(int fd, short event, void *ptr) {
    struct sockaddr_in addr;
    socklen_t len;
    int nread;
    struct log_rz lr;

    if ((nread =
                 recvfrom(fd, &lr, sizeof(lr), 0, (struct sockaddr *) &addr,
                          &len)) <= 0)
        return;
    else if (nread != sizeof(lr))
        return;

    if (lr.local_ip == 0)
        lr.local_ip = addr.sin_addr.s_addr;

    add_log_rz(&lr);
}

static void *libevent_thread(void *args) {
    struct event ev0, ev1, ev2, ev3, ev4;
    struct timeval tv2, tv3, tv4;
    int core = *((int *) args);

    t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);

    if (core >= 0)
        setup_cpuaffinity(core, __FUNCTION__);
    pthread_setname_np(pthread_self(), __FUNCTION__);
    /* initialize libevent */
    base = event_base_new();

    /* start hit log udp server */
    if (udp_logfd > 0) {
        event_set(&ev0, udp_logfd, EV_READ | EV_PERSIST,
                  udp_server_can_read, NULL);
        event_base_set(base, &ev0);
        event_add(&ev0, NULL);
    }

    /* Create a new evhttp object to handle requests. */
    http = evhttp_new(base);
    if (!http) {
        t01_log(T01_WARNING, "couldn't create evhttp.");
        exit(1);
    }
    evhttp_set_gencb(http, http_server_request_cb, NULL);
    /* Now we tell the evhttp what port to listen on */
    handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", bind_port);
    if (!handle) {
        t01_log(T01_WARNING, "couldn't bind to port %d.", bind_port);
        exit(1);
    }

    /* Initalize timeout event */
    if (tconfig.work_mode & SLAVE_MODE) {
        event_assign(&ev2, base, -1, EV_PERSIST, statistics_cb,
                     (void *) &ev2);
        evutil_timerclear(&tv2);
        tv2.tv_sec = 5;
        event_add(&ev2, &tv2);
    }

    if (tconfig.work_mode & SLAVE_MODE || tconfig.work_mode & MASTER_MODE) {
        evutil_timerclear(&tv3);
        tv3.tv_usec = 1000;
        event_assign(&ev3, base, -1, EV_PERSIST, rulesaving_cb,
                     (void *) &ev3);
        event_add(&ev3, &tv3);
    }

    if (tconfig.work_mode & SLAVE_MODE) {
        evutil_timerclear(&tv4);
        tv4.tv_sec = 5;
        event_assign(&ev4, base, -1, EV_PERSIST, slave_cb,
                     (void *) &ev4);
        event_add(&ev4, &tv4);
    } else if (tconfig.work_mode & MASTER_MODE) {
        evutil_timerclear(&tv4);
        tv4.tv_sec = 5;
        event_assign(&ev4, base, -1, EV_PERSIST, master_cb,
                     (void *) &ev4);
        event_add(&ev4, &tv4);
    }

    event_base_dispatch(base);

    t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
    return NULL;
}

static void reject_tcp(const u_char *packet, struct attack_data *attack, struct rule *rule){
    struct ndpi_ethhdr *ethhdr = (struct ndpi_ethhdr *)packet;
    struct ndpi_iphdr *iph = (struct ndpi_iphdr *)(ethhdr + 1);
    struct tcphdr *tcppkt = (struct tcphdr *)(iph + 1);
    char *result = attack->buffer;
    int len = sizeof(attack->buffer);
    len = make_fin_packet(packet, result);
    if (len == 0) {
        t01_log(T01_WARNING, "Cannot create attack packet");
        zfree(attack);
        return;
    }
    attack->len = len;
    attack->rule = rule;
    attack->flow = NULL;
    memcpy(attack->smac, (uint8_t *) packet + 6, 6);
    memcpy(attack->dmac, (uint8_t *) packet, 6);
    if (myqueue_push(attack_queue, attack) < 0) {
        t01_log(T01_WARNING, "Cannot send attack packet from attack_queue");
        zfree(attack);
    } else {
        total_ip_bytes_out += len;
        ip_packet_count_out++;
    }
}

static inline int receive_packets(struct netmap_ring *ring,
                                  struct ndpi_workflow *workflow) {
    u_int cur, rx, n;
    struct nm_pkthdr hdr;
    int only_mirror = (is_mirror == 1 && is_attack == 0) ? 1: 0;
    cur = ring->cur;
    n = nm_ring_space(ring);

    for (rx = 0; rx < n; rx++) {
        struct netmap_slot *slot = &ring->slot[cur];
        char *data = NETMAP_BUF(ring, slot->buf_idx);
        hdr.ts = ring->ts;
        hdr.len = hdr.caplen = slot->len;
        cur = nm_ring_next(ring, cur);

        if(only_mirror) {
            mirror_match_filter(workflow, &hdr, data);
        } else {
            struct ndpi_iphdr *ippkt = (struct ndpi_iphdr *) &data[sizeof(struct ndpi_ethhdr)];
            int attack_flag = 0;
            if(ippkt->protocol == 6){
                struct rule *rule = match_rule_from_htable_tcp((u_char *)data);
                if(rule != NULL) {
                    struct attack_data *attack = zmalloc(sizeof(*attack));
                    attack_flag = 1;
                    if(attack){
                        reject_tcp(data, attack, rule);
                        continue;
                    } 
                } 
            } 

            if (attack_flag == 0)
                ndpi_workflow_process_packet(workflow, &hdr, (u_char *) data);
        }
    }

    ring->head = ring->cur = cur;
    return (rx);
}

static void *netmap_thread(void *args) {
    int i;
    struct pollfd pfd[2];
    int nfds = 1;
    struct netmap_ring *rxring = NULL;
    struct netmap_if *nifp = nmr->nifp;
    int core = *((int *) args);

    t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);

    pthread_setname_np(pthread_self(), __FUNCTION__);
    if (core >= 0)
        setup_cpuaffinity(core, __FUNCTION__);
    memset(pfd, 0, sizeof(pfd));
    pfd[0].fd = nmr->fd;
    pfd[0].events = POLLIN;
    if (out_nmr && out_nmr != nmr) {
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

void get_packet(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct nm_pkthdr hdr;
    int only_mirror = (is_mirror == 1 && is_attack == 0) ? 1: 0;

    hdr.ts = pkthdr->ts;
    hdr.caplen = pkthdr->caplen;
    hdr.len = pkthdr->len;

    if(only_mirror) {
        mirror_match_filter(workflow, &hdr, packet);
    } else { 
        int attack_flag = 0;
        struct iphdr *ippkt = (struct iphdr *) &packet[sizeof(struct ndpi_ethhdr)];
        if(ippkt->protocol == 6) {
            struct rule *rule = match_rule_from_htable_tcp((u_char *)packet);
            if(rule != NULL) {
                struct attack_data *attack = zmalloc(sizeof(*attack));
                if(attack)
                    reject_tcp(packet, attack, rule);
                attack_flag = 1;
            }
        }

        if (attack_flag == 0) {
            ndpi_workflow_process_packet(workflow, &hdr, packet);
            ndpi_workflow_clean_idle_flows(workflow, 0);
        }
    } 
}

static void *libpcap_thread(void *args) {
    int core = *((int *) args);
    int pcap_id = 0;

    t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);

    if (core >= 0)
        setup_cpuaffinity(core, __FUNCTION__);
    pthread_setname_np(pthread_self(), "libpcap_thread");

    pcap_loop(device, -1, get_packet, (u_char *) &pcap_id);

    t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
    return NULL;
}

static void pfring_processs_packet(const struct pfring_pkthdr *h, const u_char *p,
                                   const u_char *user_bytes) {
    struct nm_pkthdr hdr;
    int only_mirror = (is_mirror == 1 && is_attack == 0) ? 1: 0;

    hdr.ts = h->ts;
    hdr.caplen = h->caplen;
    hdr.len = h->len;

    if(only_mirror) {
        mirror_match_filter(workflow, &hdr, p);
    } else { 
        int attack_flag = 0;
        struct ndpi_iphdr *ippkt = (struct ndpi_iphdr *) &p[sizeof(struct ndpi_ethhdr)];
        if(ippkt->protocol == 6) {
            struct rule *rule = match_rule_from_htable_tcp((u_char *)p);
            if(rule != NULL) {
                struct attack_data *attack = zmalloc(sizeof(*attack));
                if(attack)
                    reject_tcp(p, attack, rule);
                attack_flag = 1;
            }
        }

        if (attack_flag == 0) {
            ndpi_workflow_process_packet(workflow, &hdr, p);
            ndpi_workflow_clean_idle_flows(workflow, 0);
        }
    } 
}


static void *pfring_thread(void *args) {
    int core = *((int *) args);

    t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);

    if (core >= 0)
        setup_cpuaffinity(core, __FUNCTION__);
    pthread_setname_np(pthread_self(), "pfring_thread");

    pfring_loop(in_ring, pfring_processs_packet, NULL, 0);

    t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
    return NULL;
}

static void *remote_check_thread(void *args) {
    char err[ANET_ERR_LEN];
    int core = *((int *) args);
    struct timespec ts = {.tv_sec = 0, .tv_nsec = 2*1000*1000};

    t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);
    if (core >= 0)
        setup_cpuaffinity(core, __FUNCTION__);
    pthread_setname_np(pthread_self(), __FUNCTION__);

    while (!shutdown_app) {
        if (sendfd > 0) {
            nanosleep(&ts, NULL);
            continue;
        }

        int fd = anetTcpConnect(err, tconfig.remote_ip, tconfig.remote_port);
        if (fd < 0) {
            nanosleep(&ts, NULL);
        } else {
            t01_log(T01_NOTICE, "Succeed to connect to remote socket %s:%d",
                    tconfig.remote_ip, tconfig.remote_port);
            sendfd = fd;
        }
    }

    t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
    return NULL;
}

static void main_thread() {
    int i, j = 0;
    int cores = get_cpu_cores();
    int max_threads = MAX_THREADS >= cores ? MAX_THREADS : cores;

    for (i = 0; i < max_threads; i++) {
        if (tconfig.cpu_thread > 0)
            affinity[i] = i;
        else
            affinity[i] = -1;
    }

    gettimeofday(&last_report_ts, NULL);

    if (is_mirror) {
        int i;
        for (i = 0; i < tconfig.engine_threads; i++) {
            if (pthread_create(&threads[nthreads++], NULL, mirror_thread,
                               &affinity[j++]) != 0) {
                t01_log(T01_WARNING, "Can't create mirror thread: %s",
                        strerror(errno));
                is_mirror = 0;
                nthreads--;
            }
        }
    }

    if (tconfig.work_mode & SLAVE_MODE) {
        if (tconfig.eth_mode & NETMAP_MODE &&
                pthread_create(&threads[nthreads++], NULL, netmap_thread,
                       &affinity[j++]) != 0) {
            t01_log(T01_WARNING, "Can't create netmap thread: %s",
                    strerror(errno));
            exit(1);
        } else if (tconfig.eth_mode & LIBPCAP_MODE &&
                pthread_create(&threads[nthreads++], NULL, libpcap_thread,
                       &affinity[j++]) != 0) {
            t01_log(T01_WARNING, "Can't create libpcap_get thread: %s",
                    strerror(errno));
            exit(1);
        } else if (tconfig.eth_mode & PFRING_MODE &&
                   pthread_create(&threads[nthreads++], NULL, pfring_thread,
                                  &affinity[j++]) != 0) {
            t01_log(T01_WARNING, "Can't create pfring_thread thread: %s",
                    strerror(errno));
            exit(1);
        }

        sleep(1);
    }

    if (tconfig.work_mode & ATTACK_MODE &&
        pthread_create(&threads[nthreads++], NULL, attack_thread,
                       &affinity[j++]) != 0) {
        t01_log(T01_WARNING, "Can't create attack thread: %s",
                strerror(errno));
        exit(1);
    }

    if ((tconfig.work_mode & ATTACK_MODE &&
         (tconfig.hit_ip[0] && tconfig.hit_port)) &&
        pthread_create(&threads[nthreads++], NULL, hitslog_thread,
                       &affinity[j++]) != 0) {
        t01_log(T01_WARNING, "Can't create hitslog thread: %s",
                strerror(errno));
        exit(1);
    }

    if (pthread_create(&threads[nthreads++], NULL, libevent_thread,
                       &affinity[j++]) != 0) {
        t01_log(T01_WARNING, "Can't create libevent thread: %s",
                strerror(errno));
        exit(1);
    }

    if ((tconfig.work_mode & ATTACK_MODE &&
         tconfig.remote_ip[0] && tconfig.remote_port) &&
        pthread_create(&threads[nthreads++], NULL, remote_check_thread,
                       &affinity[j++]) != 0) {
        t01_log(T01_WARNING, "Can't create remote_check thread: %s",
                strerror(errno));
        exit(1);
    }


    for (i = 0; i < nthreads; i++) {
        pthread_join(threads[i], NULL);
    }

    t01_log(T01_NOTICE, "See you next time :-)");
}

static void adjust_openfiles_limit() {
    rlim_t maxfiles = tconfig.max_clients + CONFIG_MIN_RESERVED_FDS;;
    struct rlimit limit;

    if (getrlimit(RLIMIT_NOFILE,&limit) == -1) {
        t01_log(T01_WARNING, "Unable to obtain the current NOFILE limit (%s), assuming 1024 and setting the max clients configuration accordingly.",
                strerror(errno));
    } else {
        rlim_t oldlimit = limit.rlim_cur;

        /* Set the max number of files if the current limit is not enough
         * for our needs. */
        if (oldlimit < maxfiles) {
            rlim_t bestlimit;
            int setrlimit_error = 0;

            /* Try to set the file limit to match 'maxfiles' or at least
             * to the higher value supported less than maxfiles. */
            bestlimit = maxfiles;
            while(bestlimit > oldlimit) {
                rlim_t decr_step = 16;

                limit.rlim_cur = bestlimit;
                limit.rlim_max = bestlimit;
                if (setrlimit(RLIMIT_NOFILE,&limit) != -1) break;
                setrlimit_error = errno;

                /* We failed to set file limit to 'bestlimit'. Try with a
                 * smaller limit decrementing by a few FDs per iteration. */
                if (bestlimit < decr_step) break;
                bestlimit -= decr_step;
            }

            /* Assume that the limit we get initially is still valid if
             * our last try was even lower. */
            if (bestlimit < oldlimit) bestlimit = oldlimit;


            if (bestlimit < maxfiles) {
                unsigned int old_maxclients = tconfig.max_clients;
                tconfig.max_clients = bestlimit-CONFIG_MIN_RESERVED_FDS;
                /* maxclients is unsigned so may overflow: in order
                 * to check if maxclients is now logically less than 1
                 * we test indirectly via bestlimit. */
                if (bestlimit <= CONFIG_MIN_RESERVED_FDS) {
                    t01_log(T01_WARNING,"Your current 'ulimit -n' "
                                    "of %llu is not enough for the server to start. "
                                    "Please increase your open file limit to at least "
                                    "%llu. Exiting.",
                            (unsigned long long) oldlimit,
                            (unsigned long long) maxfiles);
                    return;
                }
                t01_log(T01_WARNING,"You requested maxclients of %d "
                                "requiring at least %llu max file descriptors.",
                        old_maxclients,
                        (unsigned long long) maxfiles);
                t01_log(T01_WARNING,"Server can't set maximum open files "
                                "to %llu because of OS error: %s.",
                        (unsigned long long) maxfiles, strerror(setrlimit_error));
                t01_log(T01_WARNING,"Current maximum open files is %llu. "
                                "maxclients has been reduced to %d to compensate for "
                                "low ulimit. "
                                "If you need higher maxclients increase 'ulimit -n'.",
                        (unsigned long long) bestlimit, tconfig.max_clients);
            } else {
                t01_log(T01_NOTICE, "Increased maximum number of open files to %llu (it was originally set to %llu).",
                        (unsigned long long) maxfiles,
                        (unsigned long long) oldlimit);
            }
        }
    }
}

static void init_system() {
    int i;

    if (tconfig.daemon_mode) {
        daemonize();
        create_pidfile();
    }

    adjust_openfiles_limit();

    t01_log(T01_NOTICE, "Using malloc version %s", ZMALLOC_LIB);
    t01_log(T01_NOTICE, "Using libevent version %s", event_get_version());
    t01_log(T01_NOTICE, "Using nDPI version %s", ndpi_revision());

    attack_queue = myqueue_create();
    if (!attack_queue) {
        t01_log(T01_WARNING, "failed to initialize attack queue");
        exit(0);
    }
    for (i = 0; i < tconfig.engine_threads; i++) {
        mirror_queues[i] = myqueue_create();
        if (!mirror_queues[i]) {
            t01_log(T01_WARNING, "failed to initialize mirror queue");
            exit(0);
        }
    }

    if (tconfig.daemon_mode) {
        init_log(tconfig.verbose, tconfig.logfile);
    }
    lastsave = upstart = time(NULL);
    gettimeofday(&upstart_tv, NULL);
    is_attack = tconfig.work_mode & ATTACK_MODE;
    is_mirror = tconfig.work_mode & MIRROR_MODE;
}

static void init_netmap() {
    struct nmreq req;
    char interface[64];
    unsigned char mac_address[6];
    char buf[32];
    int rc;

    rc = get_interface_mac(tconfig.ifname, mac_address);
    t01_log(T01_NOTICE, "Capturing from %s [mac: %s][speed: %uMb/s]",
            tconfig.ifname, rc == 0 ? etheraddr_string(mac_address, buf) : "unknown",
            ethtool_get_interface_speed(tconfig.ifname));

    manage_interface_promisc_mode(tconfig.ifname, 1);
    t01_log(T01_NOTICE,
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
    } else if (tconfig.raw_socket == 1) {
        sendfd = create_l2_raw_socket(tconfig.ofname);
    } else if (tconfig.raw_socket == 2) {
        char err[ANET_ERR_LEN];
        sendfd = anetTcpConnect(err, tconfig.remote_ip, tconfig.remote_port);
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

static void init_libpcap() {
    if((device = pcap_open_live(tconfig.ifname, MAX_PCAP_DATA, PCAP_PROMISC,
                                PCAP_TIMEOUT, errBuf)) == NULL) {
        t01_log(T01_WARNING, "Could not open device %s: %s, try to read it as pcap file",
                tconfig.ifname, errBuf);
        /* trying to open a pcap file */
        if((device = pcap_open_offline(tconfig.ifname, errBuf)) == NULL) {
            t01_log(T01_WARNING, "Could not open pcap file %s: %s", tconfig.ifname, errBuf);
            exit(-1);
        } else {
            t01_log(T01_NOTICE, "Reading packets from pcap file %s...", tconfig.ifname);
        }

    } else {
        t01_log(T01_NOTICE, "Capturing live traffic from device %s...", tconfig.ifname);
    }

    if (tconfig.ofname[0] == 0 || strcmp(tconfig.ifname, tconfig.ofname) == 0) {
        out_device = device;
    } else if (tconfig.raw_socket == 1) {
        sendfd = create_l2_raw_socket(tconfig.ofname);
    } else if (tconfig.raw_socket == 2) {
        char err[ANET_ERR_LEN];
        sendfd = anetTcpConnect(err, tconfig.remote_ip, tconfig.remote_port);
    } else {
        out_device = pcap_open_live(tconfig.ofname, MAX_PCAP_DATA, PCAP_PROMISC, PCAP_TIMEOUT, errBuf);
        if (!out_device) {
            t01_log(T01_WARNING, "error out_device pcap_open_live(): %s", errBuf);
            exit(1);
        }
    }

    t01_log(T01_NOTICE, "Using %s", pcap_lib_version());

    unsigned char mac_address[6];
    char buf[32];
    int rc = get_interface_mac(tconfig.ifname, mac_address);
    t01_log(T01_NOTICE, "Capturing from %s [mac: %s][speed: %uMb/s]",
            tconfig.ifname, rc == 0 ? etheraddr_string(mac_address, buf) : "unknown",
            ethtool_get_interface_speed(tconfig.ifname));

    if (tconfig.bpf != NULL && tconfig.bpf[0] != 0) {
        struct bpf_program filter;
        pcap_compile(device, &filter, tconfig.bpf, 0, 0);
        pcap_setfilter(device, &filter);
    }

    workflow = setup_detection();
}

static void init_pfring() {
    in_ring = pfring_open(tconfig.ifname, MAX_PKT_LEN, PF_RING_PROMISC);
    if (!in_ring) {
        t01_log(T01_WARNING, "Failed to open pfring device %s [%s]", tconfig.ifname, strerror(errno));
        exit(1);
    }
    if (tconfig.ofname[0] == 0 || strcmp(tconfig.ifname, tconfig.ofname) == 0) {
        out_ring = in_ring;
    } else if (tconfig.raw_socket == 1) {
        sendfd = create_l2_raw_socket(tconfig.ofname);
    } else if (tconfig.raw_socket == 2) {
        char err[ANET_ERR_LEN];
        sendfd = anetTcpConnect(err, tconfig.remote_ip, tconfig.remote_port);
    } else {
        out_ring = pfring_open(tconfig.ofname, MAX_PKT_LEN, PF_RING_PROMISC);
        if (!out_device) {
            t01_log(T01_WARNING, "Failed to open pfring device %s [%s]", tconfig.ifname, strerror(errno));
            exit(1);
        }
    }

    u_int32_t version;
    pfring_set_application_name(in_ring, "t01-slave");
    pfring_version(in_ring, &version);
    t01_log(T01_NOTICE, "Using PF_RING v%d.%d.%d", (version & 0xFFFF0000) >> 16,
           (version & 0x0000FF00) >> 8, version & 0x000000FF);

    if(pfring_enable_ring(in_ring) != 0) {
        t01_log(T01_WARNING, "Unable to enable ring :-(");
        pfring_close(in_ring);
        exit(1);
    }

    int ifindex = -1;
    unsigned char mac_address[6];
    char buf[32];
    int rc = pfring_get_bound_device_address(in_ring, mac_address);
    pfring_get_bound_device_ifindex(in_ring, &ifindex);
    t01_log(T01_NOTICE, "Capturing from %s [mac: %s][speed: %uMb/s]",
            tconfig.ifname, rc == 0 ? etheraddr_string(mac_address, buf) : "unknown",
            pfring_get_interface_speed(in_ring));

    if (tconfig.bpf != NULL && tconfig.bpf[0] != 0) {
        pfring_set_bpf_filter(in_ring, tconfig.bpf);
    }

    workflow = setup_detection();
}

static void init_engine() {
    if (tconfig.filter[0]) {
        char *temp = zstrdup(tconfig.filter), *p, *last = NULL;
        p = strtok_r(temp, ",", &last);
        n_filters = 0;
        while (p != NULL) {
            char protocol[64] = {0}, port[10] = {
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

    if (tconfig.work_mode & MIRROR_MODE &&
            tconfig.engine[0] && tconfig.mirror_engine_opt[0]) {
        int i;
        if (tconfig.engine_threads > MAX_ENGINE_THREADS)
            tconfig.engine_threads = MAX_ENGINE_THREADS;
        for (i = 0; i < tconfig.engine_threads; i++) {
            if (load_ioengine(&mirror_engines[i], tconfig.engine) < 0) {
                t01_log(T01_WARNING, "Unable to load mirror engine %s",
                        tconfig.engine);
            }

            if (init_ioengine(&mirror_engines[i], tconfig.mirror_engine_opt) < 0) {
                t01_log(T01_WARNING, "Unable to init mirror engine %s",
                        tconfig.engine);
                is_mirror = tconfig.engine_reconnect > 0;
            } else {
                is_mirror = 1;
            }
        }
    }
}

static void init_rulemgmt() {
    char err[ANET_ERR_LEN];

    init_rules(0);

    if (tconfig.ruledb[0]) {
        int rule_num = load_rules(tconfig.ruledb);
        if (rule_num > 0) {
            t01_log(T01_NOTICE, "Load %d rules from file %s",
                    rule_num, tconfig.ruledb);
        } else {
            rule_num = 0;
        }
    }

    if (tconfig.work_mode & SLAVE_MODE) {
        bind_ip = tconfig.rule_ip;
        bind_port = tconfig.rule_port;
    } else {
        bind_ip = tconfig.master_ip;
        bind_port = tconfig.master_port;
    }

    /* Open the UDP listening socke. */
    if (bind_port != 0) {
        if (tconfig.work_mode & MASTER_MODE) {
            udp_logfd = anetUdpServer(err, bind_port, bind_ip);
            if (udp_logfd == ANET_ERR) {
                t01_log(T01_WARNING,
                        "Could not create server udp listening socket %s:%d: %s",
                        bind_ip[0] ? bind_ip : "*", bind_port, err);
                exit(1);
            }
            t01_log(T01_NOTICE, "Succeed to bind udp %s:%d",
                    bind_ip, bind_port);
            anetNonBlock(NULL, udp_logfd);
        }
    }

    pthread_spin_init(&hitlog_lock, 0);
}

void close_listening_sockets() {
    if (udp_logfd != -1)
        close(udp_logfd);
}

static void exit_netmap() {
    if (out_nmr && out_nmr != nmr)
        nm_close(out_nmr);
    if (sendfd > 0)
        close(sendfd);
    nm_close(nmr);
}

static void exit_rulemgmt() {
    destroy_rules();
    close_listening_sockets();
}

static void exit_libpcap() {
    pcap_close(device);
    if (out_device && out_device != device) {
        pcap_close(out_device);
    }
}

static void exit_pfring() {
    pfring_close(in_ring);
    if (out_ring && out_ring != in_ring) {
        pfring_close(out_ring);
    }
}

int main(int argc, char **argv) {
    parse_options(argc, argv);

    init_system();
    init_engine();

    if (tconfig.work_mode & SLAVE_MODE) {
        if (tconfig.eth_mode & NETMAP_MODE)
            init_netmap();
        else if (tconfig.eth_mode & LIBPCAP_MODE)
            init_libpcap();
        else if (tconfig.eth_mode & PFRING_MODE)
            init_pfring();
    }
    init_rulemgmt();

    signal(SIGINT, signal_hander);
    signal(SIGTERM, signal_hander);
    if (tconfig.restart_if_crash) {
        struct sigaction act;
        sigemptyset(&act.sa_mask);
        act.sa_flags = SA_NODEFER | SA_RESETHAND | SA_SIGINFO;
        act.sa_sigaction = segv_handler;
        sigaction(SIGSEGV, &act, NULL);
        sigaction(SIGBUS, &act, NULL);
        sigaction(SIGFPE, &act, NULL);
        sigaction(SIGILL, &act, NULL);
    }
    main_thread();

    if (tconfig.work_mode & SLAVE_MODE) {
        if (tconfig.eth_mode & NETMAP_MODE)
            exit_netmap();
        else if (tconfig.eth_mode & LIBPCAP_MODE)
            exit_libpcap();
        else if (tconfig.eth_mode & PFRING_MODE)
            exit_pfring();
    }
    exit_rulemgmt();

    return 0;
}

/*
 * ndpi_util.h
 *
 * Copyright (C) 2011-16 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/**
 * This module contains routines to help setup a simple nDPI program.
 *
 * If you concern about performance or have to integrate nDPI in your
 * application, you could need to reimplement them yourself.
 *
 * WARNING: this API is unstable! Use it at your own risk!
 */

#ifndef __NDPI_UTIL_H__
#define __NDPI_UTIL_H__

#define MAX_NUM_READER_THREADS     16
#define IDLE_SCAN_PERIOD          200 /* msec (use TICK_RESOLUTION = 1000) */
#define MAX_IDLE_TIME           30000
#define IDLE_SCAN_BUDGET        65536
#define NUM_ROOTS                1023
#define MAX_NDPI_FLOWS      200000000
#define TICK_RESOLUTION          1000

#define NDPI_FLOW_MAGIC    0xbeafdead

#define MAX_VLAN_COUNT              4

#define NETMAP_WITH_LIBS 1
#include <net/netmap_user.h>

#ifdef __cplusplus
extern "C" {
#endif

// flow tracking
typedef struct ndpi_flow_info {
    u_int32_t magic;
    u_int32_t lower_ip;
    u_int32_t upper_ip;
    u_int16_t lower_port;
    u_int16_t upper_port;
    u_int32_t src_ip;
    u_int32_t dst_ip;
    u_int16_t src_ipid;
    u_int16_t dst_ipid;
    u_int16_t src_port;
    u_int16_t dst_port;
    u_int8_t detection_completed, protocol;
    u_int16_t vlan_ids[MAX_VLAN_COUNT];
    u_int8_t ip_version;
    u_int8_t payload_offset;
    u_int8_t src_ttl;
    u_int8_t dst_ttl;
    u_int16_t pktlen;
    u_int64_t last_seen;
    u_int64_t bytes;
    u_int32_t packets;
    u_int8_t total_vlan;

    struct ndpi_flow_struct *ndpi_flow;

    // result only, not used for flow identification
    ndpi_protocol detected_protocol;

    char host_server_name[192];

    struct {
        char client_certificate[48], server_certificate[48];
    } ssl;

    void *src_id, *dst_id;
} ndpi_flow_info_t;

typedef struct ndpi_stats {
    u_int32_t guessed_flow_protocols;
    u_int64_t raw_packet_count;
    u_int64_t ip_packet_count;
    u_int64_t total_wire_bytes, total_ip_bytes, total_discarded_bytes;
    u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
    u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
    u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
    u_int32_t ndpi_flow_count;
    u_int64_t tcp_count, udp_count;
    u_int64_t mpls_count, pppoe_count, vlan_count, fragmented_count;
} ndpi_stats_t;

typedef struct ndpi_workflow_prefs {
    u_int8_t decode_tunnels;
    u_int8_t quiet_mode;
    u_int32_t num_roots;
    u_int32_t max_ndpi_flows;
} ndpi_workflow_prefs_t;

struct ndpi_workflow;

/** workflow, flow, user data */
typedef void (*ndpi_workflow_callback_ptr)(struct ndpi_workflow *, struct ndpi_flow_info *, void *, void *);

typedef void (*data_clone_callback_ptr)(void *, uint32_t, uint8_t, uint64_t);

typedef int (*data_filter_callback_ptr)(struct ndpi_flow_info *, void *);

typedef struct ndpi_workflow {
    u_int64_t last_time;

    struct ndpi_workflow_prefs prefs;
    struct ndpi_stats stats;

    u_int64_t last_idle_scan_time;
    u_int32_t idle_scan_idx;
    u_int32_t num_idle_flows;
    struct ndpi_flow_info *idle_flows[IDLE_SCAN_BUDGET];

    data_clone_callback_ptr __data_clone_callback;
    data_filter_callback_ptr __filter_callback;
    ndpi_workflow_callback_ptr __flow_detected_callback;
    void *__flow_detected_udata;
    void *__packet_data;
    struct nm_pkthdr *__packet_header;

    /* allocated by prefs */
    void **ndpi_flows_root;
    struct ndpi_detection_module_struct *ndpi_struct;
} ndpi_workflow_t;

/* TODO: remove wrappers parameters and use ndpi global, when their initialization will be fixed... */
struct ndpi_workflow *ndpi_workflow_init(const struct ndpi_workflow_prefs *prefs);

void ndpi_workflow_free(struct ndpi_workflow *workflow);

/** Free flow_info ndpi support structures but not the flow_info itself
 *
 *  TODO remove! Half freeing things is bad!
 */
void ndpi_free_flow_info_half(struct ndpi_flow_info *flow);

/** Process a @packet and update the @workflow.  */
void ndpi_workflow_process_packet(struct ndpi_workflow *workflow, struct nm_pkthdr *header, const u_char *packet);

/* Idle flows cleanup periodly */
void ndpi_workflow_clean_idle_flows(struct ndpi_workflow *workflow, int mandatory);

/* Whether struct ndpi_flow_info used? */
int is_ndpi_flow_info_used(struct ndpi_flow_info *flow);

/* flow callbacks: ndpi_flow_info will be freed right after */
static inline void ndpi_workflow_set_flow_detected_callback(struct ndpi_workflow *workflow,
                                                            ndpi_workflow_callback_ptr callback,
                                                            void *udata) {
    workflow->__flow_detected_callback = callback;
    workflow->__flow_detected_udata = udata;
}

/* flow callbacks: ndpi_flow_info will be freed right after */
static inline void ndpi_set_mirror_data_callback(struct ndpi_workflow *workflow,
                                                 data_clone_callback_ptr callback1,
                                                 data_filter_callback_ptr callback2) {
    workflow->__data_clone_callback = callback1;
    workflow->__filter_callback = callback2;
}


int ndpi_workflow_node_cmp(const void *a, const void *b);

#ifdef __cplusplus
}
#endif

#endif
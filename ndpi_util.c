/*
 * ndpi_util.c
 *
 * Copyright (C) 2011-16 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
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

#include <stdlib.h>

#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
#else
#include <unistd.h>
#include <netinet/in.h>
#endif

#include "ndpi_main.h"
#include "ndpi_util.h"
#include "zmalloc.h"
#include "t01.h"
#include "logger.h"

#ifndef ETH_P_IP
#define ETH_P_IP               0x0800 	/* IPv4 */
#endif

#ifndef ETH_P_IPv6
#define ETH_P_IPV6	       0x86dd	/* IPv6 */
#endif

#define SLARP                  0x8035   /* Cisco Slarp */
#define CISCO_D_PROTO          0x2000	/* Cisco Discovery Protocol */

#define VLAN                   0x8100
#define MPLS_UNI               0x8847
#define MPLS_MULTI             0x8848
#define PPPoE                  0x8864
#define SNAP                   0xaa

/* mask for FCF */
#define	WIFI_DATA                        0x2    /* 0000 0010 */
#define FCF_TYPE(fc)     (((fc) >> 2) & 0x3)    /* 0000 0011 = 0x3 */
#define FCF_SUBTYPE(fc)  (((fc) >> 4) & 0xF)    /* 0000 1111 = 0xF */
#define FCF_TO_DS(fc)        ((fc) & 0x0100)
#define FCF_FROM_DS(fc)      ((fc) & 0x0200)

/* mask for Bad FCF presence */
#define BAD_FCS                         0x50    /* 0101 0000 */

#define GTP_U_V1_PORT                   2152
#define TZSP_PORT                      37008

#define DLT_NULL	0	/* BSD loopback encapsulation */
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define DLT_EN3MB	2	/* Experimental Ethernet (3Mb) */
#define DLT_AX25	3	/* Amateur Radio AX.25 */
#define DLT_PRONET	4	/* Proteon ProNET Token Ring */
#define DLT_CHAOS	5	/* Chaos */
#define DLT_IEEE802	6	/* 802.5 Token Ring */
#define DLT_ARCNET	7	/* ARCNET, with BSD-style header */
#define DLT_SLIP	8	/* Serial Line IP */
#define DLT_PPP		9	/* Point-to-point Protocol */
#define DLT_FDDI	10	/* FDDI */

#define SIZEOF_ID_STRUCT (sizeof(struct ndpi_id_struct))
#define SIZEOF_FLOW_STRUCT (sizeof(struct ndpi_flow_struct))


/* ***************************************************** */

void ndpi_free_flow_info_half(struct ndpi_flow_info *flow) {
  if(flow->ndpi_flow) { ndpi_free_flow(flow->ndpi_flow); flow->ndpi_flow = NULL; }
  if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL; }
  if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL; }

}

/* ***************************************************** */

static const u_int8_t nDPI_traceLevel = 0;

/* ***************************************************** */

/**
 * @brief malloc wrapper function
 */
static void *malloc_wrapper(size_t size) {
  return zmalloc(size);
}

/* ***************************************************** */

/**
 * @brief free wrapper function
 */
static void free_wrapper(void *freeable) {
  zfree(freeable);
}

/* ***************************************************** */

struct ndpi_workflow * ndpi_workflow_init(const struct ndpi_workflow_prefs * prefs) {
  
  set_ndpi_malloc(malloc_wrapper), set_ndpi_free(free_wrapper);
  /* TODO: just needed here to init ndpi malloc wrapper */
  struct ndpi_detection_module_struct * module = ndpi_init_detection_module();
  
  struct ndpi_workflow * workflow = ndpi_calloc(1, sizeof(struct ndpi_workflow));

  workflow->prefs = *prefs;
  workflow->ndpi_struct = module;

  if(workflow->ndpi_struct == NULL) {
    NDPI_LOG(0, NULL, NDPI_LOG_ERROR, "global structure initialization failed\n");
    exit(-1);
  }

  workflow->ndpi_flows_root = ndpi_calloc(workflow->prefs.num_roots, sizeof(void *));
  return workflow;
}

/* ***************************************************** */

int is_ndpi_flow_info_used(struct ndpi_flow_info * flow) {
  return flow && flow->magic == NDPI_FLOW_MAGIC;
}

/* ***************************************************** */

static void ndpi_flow_info_freer(void *node) {
  struct ndpi_flow_info *flow = (struct ndpi_flow_info*)node;

  ndpi_free_flow_info_half(flow);
  flow->magic = 0;
  ndpi_free(flow);
}

/* ***************************************************** */

void ndpi_workflow_free(struct ndpi_workflow * workflow) {
  int i;

  for(i=0; i<workflow->prefs.num_roots; i++)
    ndpi_tdestroy(workflow->ndpi_flows_root[i], ndpi_flow_info_freer);

  ndpi_exit_detection_module(workflow->ndpi_struct);
  zfree(workflow->ndpi_flows_root);
  zfree(workflow);
}

/* ***************************************************** */

int ndpi_workflow_node_cmp(const void *a, const void *b) {
  struct ndpi_flow_info *fa = (struct ndpi_flow_info*)a;
  struct ndpi_flow_info *fb = (struct ndpi_flow_info*)b;

  if(fa->vlan_ids[0]   < fb->vlan_ids[0]  )   return(-1); else { if(fa->vlan_ids[0]   > fb->vlan_ids[0]    ) return(1); }
  if(fa->lower_ip   < fb->lower_ip  ) return(-1); else { if(fa->lower_ip   > fb->lower_ip  ) return(1); }
  if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
  if(fa->upper_ip   < fb->upper_ip  ) return(-1); else { if(fa->upper_ip   > fb->upper_ip  ) return(1); }
  if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
  if(fa->protocol   < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }

  return(0);
}


/* ***************************************************** */

/**
 * @brief Idle Scan Walker
 */
static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {

  struct ndpi_flow_info *flow = *(struct ndpi_flow_info **) node;
  struct ndpi_workflow * workflow = (struct ndpi_workflow *)user_data;

  if(workflow->num_idle_flows == IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
    return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if(flow->last_seen + MAX_IDLE_TIME < workflow->last_time) {

      ndpi_free_flow_info_half(flow);
      workflow->stats.ndpi_flow_count--;

      /* adding to a queue (we can't delete it from the tree inline ) */
      workflow->idle_flows[workflow->num_idle_flows++] = flow;
    }
  }
}

/* ***************************************************** */

void ndpi_workflow_clean_idle_flows(struct ndpi_workflow * workflow, int mandatory) {

    int ntries = 0;
    uint64_t total_flows = 0;
    int factor = mandatory ? 1 : 20;
    int scan_num = workflow->prefs.num_roots / factor;

    if(mandatory || workflow->last_idle_scan_time + IDLE_SCAN_PERIOD < workflow->last_time) {
 check:
      /* scan for idle flows */
      ndpi_twalk(workflow->ndpi_flows_root[workflow->idle_scan_idx], node_idle_scan_walker, workflow);
      total_flows += workflow->num_idle_flows;
      
      /* remove idle flows (unfortunately we cannot do this inline) */
      while (workflow->num_idle_flows > 0) {

	/* search and delete the idle flow from the "ndpi_flow_root" - here flows are the node of a b-tree */
	ndpi_tdelete(workflow->idle_flows[--workflow->num_idle_flows],
        &workflow->ndpi_flows_root[workflow->idle_scan_idx],
        ndpi_workflow_node_cmp);

	/* free the memory associated to idle flow in "idle_flows" - (see struct reader thread)*/
	ndpi_free_flow_info_half(workflow->idle_flows[workflow->num_idle_flows]);
	ndpi_free(workflow->idle_flows[workflow->num_idle_flows]);
      }

      if(++workflow->idle_scan_idx == workflow->prefs.num_roots) workflow->idle_scan_idx = 0;
      workflow->last_idle_scan_time = workflow->last_time;

      if(mandatory && ++ntries < scan_num && total_flows < IDLE_SCAN_BUDGET) goto check;
    }
  }

/* ***************************************************** */

static struct ndpi_flow_info *get_ndpi_flow_info(struct ndpi_workflow * workflow,
						 const u_int8_t version,
						 u_int16_t* vlan_ids,
						 u_int8_t total_vlan,
                         const struct ndpi_iphdr *iph,
						 const struct ndpi_ipv6hdr *iph6,
						 u_int16_t ip_offset,
						 u_int16_t ipsize,
						 u_int16_t l4_packet_len,
						 struct ndpi_tcphdr **tcph,
						 struct ndpi_udphdr **udph,
						 u_int16_t *sport, u_int16_t *dport,
						 struct ndpi_id_struct **src,
						 struct ndpi_id_struct **dst,
						 u_int8_t *proto,
						 u_int8_t **payload,
						 u_int16_t *payload_len,
						 u_int8_t *src_to_dst_direction) {
  u_int32_t idx, l4_offset;
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int16_t id;
  struct ndpi_flow_info flow;
  void *ret;
  u_int8_t *l3, *l4;
  u_int8_t flag;
  u_int8_t ttl;

  /*
    Note: to keep things simple (ndpiReader is just a demo app)
    we handle IPv6 a-la-IPv4.
  */
  if(version == 4) {
    if(ipsize < 20)
      return NULL;

    if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
       || (iph->frag_off & htons(0x1FFF)) != 0)
      return NULL;

    l4_offset = iph->ihl * 4;
    l3 = (u_int8_t*)iph;
  } else {
    l4_offset = sizeof(struct ndpi_ipv6hdr);
    l3 = (u_int8_t*)iph6;
  }

  if(iph->saddr < iph->daddr) {
    lower_ip = iph->saddr;
    upper_ip = iph->daddr;
    flag = 0;
  } else {
    lower_ip = iph->daddr;
    upper_ip = iph->saddr;
    flag = 1;
  }
  id = ntohs(iph->id);
  ttl = iph->ttl;

  *proto = iph->protocol;
  l4 = ((u_int8_t *) l3 + l4_offset);

  if(iph->protocol == 6 && l4_packet_len >= 20) {
    u_int tcp_len;

    workflow->stats.tcp_count++;

    // tcp
    *tcph = (struct ndpi_tcphdr *)l4;
    *sport = ntohs((*tcph)->source), *dport = ntohs((*tcph)->dest);

    if(iph->saddr < iph->daddr) {
      lower_port = (*tcph)->source, upper_port = (*tcph)->dest;
      *src_to_dst_direction = 1;
    } else {
      lower_port = (*tcph)->dest;
      upper_port = (*tcph)->source;

      *src_to_dst_direction = 0;
      if(iph->saddr == iph->daddr) {
	if(lower_port > upper_port) {
	  u_int16_t p = lower_port;

	  lower_port = upper_port;
	  upper_port = p;
	}
      }
    }

    tcp_len = ndpi_min(4*(*tcph)->doff, l4_packet_len);
    *payload = &l4[tcp_len];
    *payload_len = ndpi_max(0, l4_packet_len-4*(*tcph)->doff);
  } else if(iph->protocol == 17 && l4_packet_len >= 8) {
    // udp
    workflow->stats.udp_count++;

    *udph = (struct ndpi_udphdr *)l4;
    *sport = ntohs((*udph)->source), *dport = ntohs((*udph)->dest);
    *payload = &l4[sizeof(struct ndpi_udphdr)];
    *payload_len = ndpi_max(0, l4_packet_len-sizeof(struct ndpi_udphdr));

    if(iph->saddr < iph->daddr) {
      lower_port = (*udph)->source, upper_port = (*udph)->dest;
      *src_to_dst_direction = 1;
    } else {
      lower_port = (*udph)->dest, upper_port = (*udph)->source;

      *src_to_dst_direction = 0;

      if(iph->saddr == iph->daddr) {
	if(lower_port > upper_port) {
	  u_int16_t p = lower_port;

	  lower_port = upper_port;
	  upper_port = p;
	}
      }
    }

    *sport = ntohs(lower_port), *dport = ntohs(upper_port);
  } else {
    // non tcp/udp protocols
    lower_port = 0;
    upper_port = 0;
  }

  flow.protocol = iph->protocol;
  memcpy(flow.vlan_ids, vlan_ids, sizeof(flow.vlan_ids));
  flow.total_vlan = total_vlan;
  flow.lower_ip = lower_ip, flow.upper_ip = upper_ip;
  flow.lower_port = lower_port, flow.upper_port = upper_port;

  /*
  if(workflow->__filter_callback && workflow->__data_clone_callback) {
    if(workflow->__filter_callback(&flow))
      workflow->__data_clone_callback(workflow->__flow_packet_data, workflow->__flow_packet_len);
  }*/

  if(0)
    NDPI_LOG(0, workflow.ndpi_struct, NDPI_LOG_DEBUG, "[NDPI] [%u][%u:%u <-> %u:%u]\n",
	     iph->protocol, lower_ip, ntohs(lower_port), upper_ip, ntohs(upper_port));

  idx = (vlan_ids[0] + lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % workflow->prefs.num_roots;
  ret = ndpi_tfind(&flow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp);

  if(ret == NULL) {
    if(workflow->stats.ndpi_flow_count == workflow->prefs.max_ndpi_flows)
      ndpi_workflow_clean_idle_flows(workflow, 1);
   
    if(workflow->stats.ndpi_flow_count == workflow->prefs.max_ndpi_flows) {
      NDPI_LOG(0, workflow.ndpi_struct, NDPI_LOG_ERROR, "maximum flow count (%u) has been exceeded\n", workflow->prefs.max_ndpi_flows);
      return NULL;
    } else {
      struct ndpi_flow_info *newflow = (struct ndpi_flow_info*)zmalloc(sizeof(struct ndpi_flow_info));

      if(newflow == NULL) {
	NDPI_LOG(0, workflow.ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(1): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      memset(newflow, 0, sizeof(struct ndpi_flow_info));
      newflow->magic = NDPI_FLOW_MAGIC;
      newflow->protocol = iph->protocol;
      memcpy(newflow->vlan_ids, vlan_ids, sizeof(newflow->vlan_ids));
      newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
      newflow->lower_port = lower_port, newflow->upper_port = upper_port;
      newflow->ip_version = version;
      newflow->src_ipid = id; 
      newflow->src_ttl = ttl;
      newflow->total_vlan = total_vlan;
      newflow->hash_idx = idx;
      
      if(flag == 0){ newflow->src_ip = lower_ip; newflow->dst_ip = upper_ip; newflow->src_port = ntohs(lower_port); newflow->dst_port = ntohs(upper_port); }
      else{ newflow->src_ip = upper_ip; newflow->dst_ip = lower_ip; newflow->src_port = ntohs(upper_port); newflow->dst_port = ntohs(lower_port); }

      if((newflow->ndpi_flow = ndpi_malloc(SIZEOF_FLOW_STRUCT)) == NULL) {
	NDPI_LOG(0, workflow.ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(2): not enough memory\n", __FUNCTION__);
	zfree(newflow);
	return(NULL);
      } else
	memset(newflow->ndpi_flow, 0, SIZEOF_FLOW_STRUCT);

      if((newflow->src_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL) {
	NDPI_LOG(0, workflow.ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(3): not enough memory\n", __FUNCTION__);
	zfree(newflow);
	return(NULL);
      } else
	memset(newflow->src_id, 0, SIZEOF_ID_STRUCT);

      if((newflow->dst_id = ndpi_malloc(SIZEOF_ID_STRUCT)) == NULL) {
	NDPI_LOG(0, workflow.ndpi_struct, NDPI_LOG_ERROR, "[NDPI] %s(4): not enough memory\n", __FUNCTION__);
	zfree(newflow);
	return(NULL);
      } else
	memset(newflow->dst_id, 0, SIZEOF_ID_STRUCT);

      ndpi_tsearch(newflow, &workflow->ndpi_flows_root[idx], ndpi_workflow_node_cmp); /* Add */
      workflow->stats.ndpi_flow_count++;

      *src = newflow->src_id, *dst = newflow->dst_id;

      data_filter_callback_ptr callback1 = workflow->__filter_callback;

      if(callback1 && callback1(newflow, workflow->__packet_data)
          && workflow->__data_clone_callback) {
          workflow->__data_clone_callback(workflow->__packet_data, 
                                          workflow->__packet_header->len,
                                          newflow->hash_idx,
                                          newflow->protocol, workflow->last_time);
      }

      return newflow;
    }
  } else {
    struct ndpi_flow_info *flow = *(struct ndpi_flow_info**)ret;

    if(flow->lower_ip == lower_ip && flow->upper_ip == upper_ip
       && flow->lower_port == lower_port && flow->upper_port == upper_port)
      *src = flow->src_id, *dst = flow->dst_id;
    else
      *src = flow->dst_id, *dst = flow->src_id;

    data_filter_callback_ptr callback1 = workflow->__filter_callback;
    if(callback1 && callback1(flow, workflow->__packet_data) &&
        workflow->__data_clone_callback) {
        workflow->__data_clone_callback(workflow->__packet_data, 
                                        workflow->__packet_header->len,
                                        flow->hash_idx,
                                        flow->protocol, workflow->last_time);
    }

    if(flag == 0) flow->src_ipid = id, flow->src_ttl = ttl;
    else          flow->dst_ipid = id, flow->dst_ttl = ttl;

    return flow;
  }
}

/* ****************************************************** */

static struct ndpi_flow_info *get_ndpi_flow_info6(struct ndpi_workflow * workflow,
						  u_int16_t *vlan_ids,
						  u_int8_t total_vlan,
						  const struct ndpi_ipv6hdr *iph6,
						  u_int16_t ip_offset,
						  struct ndpi_tcphdr **tcph,
						  struct ndpi_udphdr **udph,
						  u_int16_t *sport, u_int16_t *dport,
						  struct ndpi_id_struct **src,
						  struct ndpi_id_struct **dst,
						  u_int8_t *proto,
						  u_int8_t **payload,
						  u_int16_t *payload_len,
						  u_int8_t *src_to_dst_direction) {
  struct ndpi_iphdr iph;

  memset(&iph, 0, sizeof(iph));
  iph.version = 4;
  iph.saddr = iph6->ip6_src.u6_addr.u6_addr32[2] + iph6->ip6_src.u6_addr.u6_addr32[3];
  iph.daddr = iph6->ip6_dst.u6_addr.u6_addr32[2] + iph6->ip6_dst.u6_addr.u6_addr32[3];
  iph.protocol = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

  if(iph.protocol == 0x3C /* IPv6 destination option */) {
    u_int8_t *options = (u_int8_t*)iph6 + sizeof(const struct ndpi_ipv6hdr);

    iph.protocol = options[0];
  }

  return(get_ndpi_flow_info(workflow, 6, vlan_ids, total_vlan, &iph, iph6, ip_offset,
			    sizeof(struct ndpi_ipv6hdr),
			    ntohs(iph6->ip6_ctlun.ip6_un1.ip6_un1_plen),
			    tcph, udph, sport, dport,
			    src, dst, proto, payload, payload_len, src_to_dst_direction));
}

/* ****************************************************** */

// ipsize = header->len - ip_offset ; rawsize = header->len
static unsigned int packet_processing(struct ndpi_workflow * workflow,
				      const u_int64_t time,
				      u_int16_t* vlan_ids,
				      u_int8_t total_vlan,
				      const struct ndpi_iphdr *iph,
				      struct ndpi_ipv6hdr *iph6,
				      u_int16_t ip_offset,
				      u_int16_t ipsize, u_int16_t rawsize) {
  struct ndpi_id_struct *src, *dst;
  struct ndpi_flow_info *flow;
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int8_t proto;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int16_t sport, dport, payload_len;
  u_int8_t *payload;
  u_int8_t src_to_dst_direction= 1;

  if(iph)
    flow = get_ndpi_flow_info(workflow, 4, vlan_ids, total_vlan, iph, NULL,
			      ip_offset, ipsize,
			      ntohs(iph->tot_len) - (iph->ihl * 4),
			      &tcph, &udph, &sport, &dport,
			      &src, &dst, &proto,
			      &payload, &payload_len, &src_to_dst_direction);
  else
    flow = get_ndpi_flow_info6(workflow, vlan_ids, total_vlan, iph6, ip_offset,
			       &tcph, &udph, &sport, &dport,
			       &src, &dst, &proto,
			       &payload, &payload_len, &src_to_dst_direction);

  if(flow != NULL) {
    struct ndpi_stats* stats = &workflow->stats;
    stats->ip_packet_count++;
    stats->total_wire_bytes += rawsize + 24 /* CRC etc */, stats->total_ip_bytes += rawsize;
    stats->port_counter[dport]++;
    stats->port_counter_bytes[dport] += rawsize;
    if (tconfig.verbose && stats->ip_packet_count % tconfig.sampling == 0) {
        flow->log_flag = 1;
        t01_log(T01_NOTICE, "Before nDPI: %x:%d <--> %x:%d", flow->src_ip, flow->src_port,
                flow->dst_ip, flow->dst_port);
    }
    ndpi_flow = flow->ndpi_flow;
    flow->packets++, flow->bytes += rawsize;
    flow->last_seen = time;
    flow->payload_offset = payload-(u_int8_t *)workflow->__packet_data;
    flow->pktlen = workflow->__packet_header->len;
  } else {
    return(0);
  }

  /* Protocol already detected */
  if(flow->detection_completed)  return(0);

  flow->detected_protocol = ndpi_detection_process_packet(workflow->ndpi_struct, ndpi_flow,
							  iph ? (uint8_t *)iph : (uint8_t *)iph6,
							  ipsize, time, src, dst);

  if((flow->detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN)
     || ((proto == IPPROTO_UDP) && (flow->packets > 1))
     || ((proto == IPPROTO_TCP) && (flow->packets >= 4))
     || ((proto == IPPROTO_ICMP) && (flow->packets >= 2))) {
    /* New protocol detected or give up */
    flow->detection_completed = 1;

    if((flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) && (ndpi_flow->num_stun_udp_pkts > 0))
      ndpi_set_detected_protocol(workflow->ndpi_struct, ndpi_flow, NDPI_PROTOCOL_STUN, NDPI_PROTOCOL_UNKNOWN);

    snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);

    if((proto == IPPROTO_TCP) && (flow->detected_protocol.protocol != NDPI_PROTOCOL_DNS)) {
      snprintf(flow->ssl.client_certificate, sizeof(flow->ssl.client_certificate), "%s", flow->ndpi_flow->protos.ssl.client_certificate);
      snprintf(flow->ssl.server_certificate, sizeof(flow->ssl.server_certificate), "%s", flow->ndpi_flow->protos.ssl.server_certificate);
    }

    if(flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) {
      flow->detected_protocol = ndpi_detection_giveup(workflow->ndpi_struct, flow->ndpi_flow);
      if(flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) {
	 flow->detection_completed = 0;
	 return 0;
      } else {
	if (workflow->__flow_detected_callback != NULL)
	  workflow->__flow_detected_callback(workflow, flow, workflow->__packet_header,  workflow->__packet_data);
      }
    } else {
      if (workflow->__flow_detected_callback != NULL)
        workflow->__flow_detected_callback(workflow, flow, workflow->__packet_header,  workflow->__packet_data);
    }

    ndpi_free_flow_info_half(flow);
  }

  return 0;
}

/* ****************************************************** */
void ndpi_workflow_process_packet (struct ndpi_workflow * workflow, struct nm_pkthdr *header, const u_char *packet) {
  /*
   * Declare pointers to packet headers
   */

  /* --- Ethernet header --- */
  const struct ndpi_ethhdr *ethernet;
  /* --- Ethernet II header --- */
  const struct ndpi_ethhdr *ethernet_2;
  /* --- LLC header --- */
  const struct ndpi_llc_header *llc;

  /* --- Cisco HDLC header --- */
  const struct ndpi_chdlc *chdlc;
  /* --- SLARP frame --- */
  struct ndpi_slarp *slarp;
  /* --- CDP --- */
  struct ndpi_cdp *cdp;

  /* --- Radio Tap header --- */
  const struct ndpi_radiotap_header *radiotap;
  /* --- Wifi header --- */
  const struct ndpi_wifi_header *wifi;

  /* --- MPLS header --- */
  struct ndpi_mpls_header *mpls;

  /** --- IP header --- **/
  struct ndpi_iphdr *iph;
  /** --- IPv6 header --- **/
  struct ndpi_ipv6hdr *iph6;

  /* lengths and offsets */
  u_int16_t eth_offset = 0;
  u_int16_t radio_len;
  u_int16_t fc;
  u_int16_t type;
  int wifi_len = 0;
  int llc_off;
  int pyld_eth_len = 0;
  int check;
  u_int64_t time;
  u_int16_t ip_offset, ip_len, ip6_offset;
  u_int16_t frag_off = 0, vlan_id = 0;
  u_int8_t proto = 0;
  u_int8_t total_vlan = 0;
  u_int16_t vlan_ids[MAX_VLAN_COUNT] = {0};
  u_int32_t label;

  /* counters */
  u_int8_t vlan_packet = 0;

  /* Increment raw packet counter */
  workflow->stats.raw_packet_count++;
  workflow->__packet_header = header;
  workflow->__packet_data = packet;

  /* setting time */
  time = ((uint64_t) header->ts.tv_sec) * TICK_RESOLUTION + header->ts.tv_usec / (1000000 / TICK_RESOLUTION);

  /* safety check */
  if(workflow->last_time > time) {
    /* printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", ndpi_thread_info[thread_id].last_time - time); */
    time = workflow->last_time;
  }
  /* update last time value */
  workflow->last_time = time;

  /*** check Data Link type ***/
  const int datalink_type = DLT_EN10MB;
 datalink_check:
  /* IEEE 802.3 Ethernet - 1 */
  ethernet = (struct ndpi_ethhdr *) &packet[eth_offset];
  ip_offset = sizeof(struct ndpi_ethhdr) + eth_offset;
  check = ntohs(ethernet->h_proto);

  if(check <= 1500)
    pyld_eth_len = check;
  else if (check >= 1536)
    type = check;

  if(pyld_eth_len != 0) {
      /* check for LLC layer with SNAP extension */
      if(packet[ip_offset] == SNAP) {
	llc = (struct ndpi_llc_header *)(&packet[ip_offset]);
	type = llc->snap.proto_ID;
	ip_offset += + 8;
      }
    }

  /* check ether type */
  switch(type) {
    case VLAN:
vlan_check:
      vlan_id = ((packet[ip_offset] << 8) + packet[ip_offset+1]) & 0xFFF;
      type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
      ip_offset += 4;
      vlan_packet = 1;
      if (total_vlan < MAX_VLAN_COUNT)
          vlan_ids[total_vlan++] = vlan_id;
      if (type == VLAN) goto vlan_check;
      break;
    case MPLS_UNI:
    case MPLS_MULTI:
      mpls = (struct ndpi_mpls_header *) &packet[ip_offset];
      label = ntohl(mpls->label);
      /* label = ntohl(*((u_int32_t*)&packet[ip_offset])); */
      workflow->stats.mpls_count++;
      type = ETH_P_IP, ip_offset += 4;

      while((label & 0x100) != 0x100) {
        ip_offset += 4;
        label = ntohl(mpls->label);
      }
      break;
    case PPPoE:
      workflow->stats.pppoe_count++;
      type = ETH_P_IP;
      ip_offset += 8;
      break;
    default:
      break;
  }

  workflow->stats.vlan_count += vlan_packet;

 iph_check:
  /* Check and set IP header size and total packet length */
  iph = (struct ndpi_iphdr *) &packet[ip_offset];

  /* just work on Ethernet packets that contain IP */
  if(type == ETH_P_IP && header->caplen >= ip_offset) {
    frag_off = ntohs(iph->frag_off);

    proto = iph->protocol;
    if(header->caplen < header->len) {
      static u_int8_t cap_warning_used = 0;

      if(cap_warning_used == 0) {
	if(!workflow->prefs.quiet_mode)
	  NDPI_LOG(0, workflow.ndpi_struct, NDPI_LOG_DEBUG, "\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
	cap_warning_used = 1;
      }
    }
  }

  if(iph->version == 4) {
    ip_len = ((u_short)iph->ihl * 4);
    iph6 = NULL;

    if(iph->protocol == 41) {
      ip_offset += ip_len;
      goto iph_check;
    }

    if((frag_off & 0x3FFF) != 0) {
      static u_int8_t ipv4_frags_warning_used = 0;
      workflow->stats.fragmented_count++;

      if(ipv4_frags_warning_used == 0) {
	if(!workflow->prefs.quiet_mode)
	  NDPI_LOG(0, workflow.ndpi_struct, NDPI_LOG_DEBUG, "\n\nWARNING: IPv4 fragments are not handled by this demo (nDPI supports them)\n");
	ipv4_frags_warning_used = 1;
      }

      workflow->stats.total_discarded_bytes +=  header->len;
      return;
    }
  } else if(iph->version == 6) {
    iph6 = (struct ndpi_ipv6hdr *)&packet[ip_offset];
    proto = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    ip_len = sizeof(struct ndpi_ipv6hdr);

    if(proto == 0x3C /* IPv6 destination option */) {

      u_int8_t *options = (u_int8_t*)&packet[ip_offset+ip_len];
      proto = options[0];
      ip_len += 8 * (options[1] + 1);
    }
    iph = NULL;

  } else {
    static u_int8_t ipv4_warning_used = 0;

  v4_warning:
    if(ipv4_warning_used == 0) {
      if(!workflow->prefs.quiet_mode)
        NDPI_LOG(0, workflow.ndpi_struct, NDPI_LOG_DEBUG, "\n\nWARNING: only IPv4/IPv6 packets are supported in this demo (nDPI supports both IPv4 and IPv6), all other packets will be discarded\n\n");
      ipv4_warning_used = 1;
    }
    workflow->stats.total_discarded_bytes +=  header->len;
    return;
  }

  if(workflow->prefs.decode_tunnels && (proto == IPPROTO_UDP)) {
    struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[ip_offset+ip_len];
    u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

    if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
      /* Check if it's GTPv1 */
      u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
      u_int8_t flags = packet[offset];
      u_int8_t message_type = packet[offset+1];

      if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) &&
	 (message_type == 0xFF /* T-PDU */)) {

	ip_offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr)+8; /* GTPv1 header len */
	if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
	if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
	if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

	iph = (struct ndpi_iphdr *) &packet[ip_offset];

	if(iph->version != 4) {
	  // printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)workflow->stats.raw_packet_count);
	  goto v4_warning;
	}
      }
    } else if((sport == TZSP_PORT) || (dport == TZSP_PORT)) {
      /* https://en.wikipedia.org/wiki/TZSP */
      u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
      u_int8_t version = packet[offset];
      u_int8_t type    = packet[offset+1];
      u_int16_t encapsulates = ntohs(*((u_int16_t*)&packet[offset+2]));

      if((version == 1) && (type == 0) && (encapsulates == 1)) {
	u_int8_t stop = 0;

	offset += 4;

	while((!stop) && (offset < header->caplen)) {
	  u_int8_t tag_type = packet[offset];
	  u_int8_t tag_len;

	  switch(tag_type) {
	  case 0: /* PADDING Tag */
	    tag_len = 1;
	    break;
	  case 1: /* END Tag */
	    tag_len = 1, stop = 1;
	    break;
	  default:
	    tag_len = packet[offset+1];
	    break;
	  }

	  offset += tag_len;

	  if(offset >= header->caplen)
          return; /* Invalid packet */
	  else {
	    eth_offset = offset;
	    goto datalink_check;
	  }
	}
      }
    }
  }

  /* process the packet */
  packet_processing(workflow, time, vlan_ids, total_vlan, iph, iph6,
		    ip_offset, header->len - ip_offset, header->len);
}

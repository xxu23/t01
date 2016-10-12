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
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rule.h"
#include "cJSON.h"
#include "ndpi_api.h"
#include "ndpi_util.h"
#include "ndpi_protocol_ids.h"
#include "logger.h"
#include "zmalloc.h"


LIST_HEAD(rule_list);

static uint32_t max_id;

static inline uint8_t get_action(const char* action)
{
  if (strcmp(action, "reject") == 0)
    return T01_ACTION_REJECT;
  else if(strcmp(action, "redirect") == 0)
    return T01_ACTION_REDIRECT;
  else if(strcmp(action, "confuse") == 0)
    return T01_ACTION_CONFUSE;
  return 0;
}

static inline uint8_t get_protocol(const char* protocol, uint8_t* master, NDPI_PROTOCOL_BITMASK* mask)
{
  int prot = 0;
  if(strcasecmp(protocol, "http") == 0){
    *master = NDPI_PROTOCOL_HTTP;
    prot = IPPROTO_TCP;
  } else if (strcasecmp(protocol, "https") == 0){
    *master = NDPI_PROTOCOL_SSL;
    prot = IPPROTO_TCP;
  } else if (strcasecmp(protocol, "dns") == 0){
    *master = NDPI_PROTOCOL_DNS;
    prot = IPPROTO_UDP;
  } else if (strcasecmp(protocol, "ssh") == 0){
    *master = NDPI_PROTOCOL_SSH;
    prot = IPPROTO_TCP;
  } else if (strcasecmp(protocol, "icmp") == 0){
    *master = NDPI_PROTOCOL_IP_ICMP;
    prot = IPPROTO_ICMP;
  } else if (strcasecmp(protocol, "icmpv6") == 0){
    *master = NDPI_PROTOCOL_IP_ICMPV6;
    prot = IPPROTO_ICMPV6;
  } else if (strcasecmp(protocol, "ipsec") == 0){
    *master = NDPI_PROTOCOL_IP_IPSEC;
    prot = IPPROTO_IP;
  } else if (strcasecmp(protocol, "pptp") == 0){
    *master = NDPI_PROTOCOL_PPTP;
    prot = IPPROTO_TCP;
  } else if (strcasecmp(protocol, "socks") == 0){
    *master = NDPI_PROTOCOL_SOCKS;
    prot = IPPROTO_UDP;
  } else if (strcasecmp(protocol, "dhcp") == 0){
    *master = NDPI_PROTOCOL_DHCP;
    prot = IPPROTO_UDP;
  } else if (strcasecmp(protocol, "tcp") == 0){
    *master = 0;
    prot = IPPROTO_TCP;
  } else if (strcasecmp(protocol, "udp") == 0){
    *master = 0;
    prot = IPPROTO_UDP;
  } 
  if(mask && *master)
    NDPI_BITMASK_ADD(*mask, *master);
  return prot;
}

static void strrpl(char* pDstOut, const char* pSrcIn, const char* pSrcRpl, const char* pDstRpl)
{ 
  const char* pi = pSrcIn; 
  char* po = pDstOut; 
  int nSrcRplLen = strlen(pSrcRpl); 
  int nDstRplLen = strlen(pDstRpl); 
  char *p = NULL; 
  int nLen = 0; 

  do {
    p = strstr(pi, pSrcRpl); 
    if(p != NULL) { 
      nLen = p - pi; 
      memcpy(po, pi, nLen);
      memcpy(po + nLen, pDstRpl, nDstRplLen); 
    } else { 
      strcpy(po, pi); 
      break;
    } 

    pi = p + nSrcRplLen; 
    po = po + nLen + nDstRplLen;
  } while (p != NULL); 
}

static inline get_ip(const char* ip, u_int32_t* start, u_int32_t* end)
{
  if(strchr(ip, '*')){
    char ip1[16], ip2[16];
    strrpl(ip1, ip, "*", "1");
    strrpl(ip2, ip, "*", "255");
    *start = inet_addr (ip1);
    *end = inet_addr (ip2);
    return 2;
  } else {
    *start = *end = inet_addr (ip);
    return 1;
  }
}

void transform_one_rule(struct rule* rule, NDPI_PROTOCOL_BITMASK* mask)
{
  if(rule->human_saddr[0])
    get_ip(rule->human_saddr, &rule->saddr0, &rule->saddr1);

  if(rule->human_daddr[0])
    get_ip(rule->human_daddr, &rule->daddr0, &rule->daddr1);      

  if(rule->human_protocol[0])
    rule->protocol = get_protocol(rule->human_protocol, &(rule->master_protocol), mask);
 
  if(rule->human_action[0])
    rule->action = get_action(rule->human_action);
}

#define get_string_from_json(item, json, key, value) 	\
  item = cJSON_GetObjectItem(json, key); 			\
  if(item){ 							\
    strncpy(value, item->valuestring, sizeof(value));	\
  }									\

#define get_int_from_json(item, json, key, value) 	\
  item = cJSON_GetObjectItem(json, key); 		\
  if(item){ 							\
    value = item->valueint;                             \
  }									\

#define get_string_from_arrayjson(item, json, j, value) 	\
  item = cJSON_GetArrayItem(json, j);				\
  if(item) {								\
    strncpy(value[j], item->valuestring, sizeof(value[j]));	\
  }										\

static void parse_one_rule(cJSON* json, struct rule* rule)
{
  cJSON *item, *parent;

  get_string_from_json(item, json, "protocol", rule->human_protocol);
  get_string_from_json(item, json, "saddr", rule->human_saddr);
  get_string_from_json(item, json, "daddr", rule->human_daddr);
  get_int_from_json(item, json, "sport", rule->sport);
  get_int_from_json(item, json, "dport", rule->dport);
  get_int_from_json(item, json, "id", rule->id);
  if(rule->id == 0) rule->id = ++max_id;
  else if(rule->id > max_id) max_id = rule->id;

  parent = cJSON_GetObjectItem(json, "condition");
  if(parent){
    get_string_from_json(item, parent, "host", rule->condition.host);
  }
  
  get_string_from_json(item, json, "action", rule->human_action);
 
  parent = cJSON_GetObjectItem(json, "params");
  if(parent){
    int m = cJSON_GetArraySize(parent);
    if(m <= 4){
      int j;
      for (j = 0; j < m; j++)
        { get_string_from_arrayjson(item, parent, j, rule->action_params); }
    }
  }
}

int load_rules_from_file(const char* filename, struct list_head* head, void* ndpi_mask)
{
  FILE *f;
  long size;
  char *data;
  NDPI_PROTOCOL_BITMASK* mask = (NDPI_PROTOCOL_BITMASK*)ndpi_mask;

  f = fopen(filename,"rb");
  if(!f){
    t01Log(T01_WARNING, "Cannot open json file %s: %s", filename, strerror(errno));
    return -1;
  }
  fseek(f, 0, SEEK_END);
  size = ftell(f);
  fseek(f, 0, SEEK_SET);
	
  data = (char*)malloc(size+1);
  if(!data){
    t01Log(T01_WARNING, "Out of memory!");
    return -2;
  }
  fread(data, 1, size, f);
  data[size]='\0';
  fclose(f);
  
  cJSON * json = cJSON_Parse(data);
  if(!json){
    t01Log(T01_WARNING, "Cannot parse json: %s", cJSON_GetErrorPtr());
    free(data);
    return -3;
  }
  
  char* msg = NULL;
  int ret = 0;
  int n = cJSON_GetArraySize(json);
  if(n == 0)
    goto out;
  
  int i;
  for(i = 0;  i < n; i++){
    cJSON* item = cJSON_GetArrayItem(json, i);
    if(!item){
      t01Log(T01_WARNING, "Cannot parse json: %s", cJSON_GetErrorPtr());
      continue;
     }

    struct rule* rule = malloc(sizeof(*rule));
    if(!rule) {
      msg = "Out of memory";
      ret = -2;
      goto out;
     }
    bzero(rule,  sizeof(*rule));
    
    parse_one_rule(item, rule);
    transform_one_rule(rule, mask);
    rule->used = 1;
    list_add_tail(&rule->list, head);
  }
  ret = n;
   
out:
  free(data);
  cJSON_Delete(json);
  if(ret < 0)
    t01Log(T01_WARNING, "Cannot parse json: %s", msg);
  return ret;
}

void destroy_rules(struct list_head *head)
{
  if(!head || list_empty(head)) return;
  
  struct list_head *pos, *n;
  struct rule *rule;
  int i;
  list_for_each_safe(pos, n, head) {
    list_del(pos);
    rule = list_entry(pos, struct rule, list);
    free(rule);
  }
}

int get_rule_by_id(uint32_t id, void* out, int len)
{
  struct list_head *pos;
  list_for_each(pos, &rule_list) {
    struct rule* rule = list_entry(pos, struct rule, list);
    if(rule->id == id && rule->used == 1){
      len = (char*)&(rule->protocol) - (char*)rule;
      memcpy(out, rule, len);
      return len;
    }
  }

  return -1; 
}

int update_rule(void* in, int in_len, void* out, int len)
{
  struct list_head *pos;
  struct rule* new_rule = (struct rule*)in;
  list_for_each(pos, &rule_list) {
    struct rule* rule = list_entry(pos, struct rule, list);
    if(rule->id == new_rule->id && rule->used == 1){
      int i;
      if(new_rule->human_protocol[0])
        strncpy(rule->human_protocol, new_rule->human_protocol, sizeof(rule->human_protocol));
      if(new_rule->human_saddr[0])
        strncpy(rule->human_saddr, new_rule->human_saddr, sizeof(rule->human_saddr));
      if(new_rule->human_daddr[0])
        strncpy(rule->human_daddr, new_rule->human_daddr, sizeof(rule->human_daddr));
      if(new_rule->human_action[0])
        strncpy(rule->human_action, new_rule->human_action, sizeof(rule->human_action));
      if(((char*)&new_rule->condition)[0])
        memcpy(&rule->condition, &new_rule->condition, sizeof(rule->condition));
      for(i = 0; i < 4; i++)
        if(new_rule->action_params[i][0])
          strncpy(rule->action_params[i], new_rule->action_params[i], sizeof(rule->action_params[i]));
      if(new_rule->sport)
        rule->sport = new_rule->sport;
      if(new_rule->dport)
        rule->dport = new_rule->dport;

      transform_one_rule(rule, NULL);
      
      return 0;
    }
  }
  return -1;
}

int delete_rule_by_id(uint32_t id, void* out, int len)
{
  struct list_head *pos, *n;
  struct rule *rule;
  list_for_each_safe(pos, n, &rule_list) {
    rule = list_entry(pos, struct rule, list);
    if(rule->id == id) {
      rule->used = 0;
      return 0;
    }
  }

  return -1;
}

int add_rule(void* in, int in_len, void* out, int out_len)
{
  struct rule *src_rule = (struct rule *)in;
  struct rule* new_rule = NULL;
  struct list_head *pos;
  int offset;
  
  list_for_each(pos, &rule_list) {
    struct rule* rule = list_entry(pos, struct rule, list);
    if(rule->used == 0) {
      new_rule = rule;
      break;
    }
  }

  if(!new_rule) {
    new_rule = malloc(sizeof(*new_rule));
    if(!new_rule) {
      strncpy(out, "Out of memory", out_len);
      return -1;
     }
    bzero(new_rule,  sizeof(*new_rule));
    list_add_tail(&new_rule->list, &rule_list);
  }
  
  in_len = (char*)&new_rule->protocol - new_rule->human_protocol;
  offset = new_rule->human_protocol - (char*)new_rule;
  memcpy(((char*)new_rule)+offset, ((char*)src_rule)+offset, in_len);
  transform_one_rule(new_rule, NULL);
  new_rule->used = 1;
  new_rule->id = ++max_id;
  return new_rule->id;
}


struct rule* match_rule_from_packet(struct list_head *head, void* flow_, void* packet)
{
  struct ndpi_flow_info* flow = (struct ndpi_flow_info *)flow_;
  struct list_head* pos;
  list_for_each(pos, head) {
    struct rule* rule = list_entry(pos, struct rule, list);
    if(rule->used == 0) 
        continue;

    if(flow->protocol == NDPI_PROTOCOL_UNKNOWN)
      continue;

    if(rule->protocol != flow->protocol) 
      continue;
    
    if(rule->master_protocol){
      uint8_t master_protocol = flow->detected_protocol.master_protocol;
      if(master_protocol == 0) master_protocol = flow->detected_protocol.protocol;
      if(master_protocol != rule->master_protocol)
	continue; 
    }

    if(rule->dport || rule->sport || rule->daddr0 || rule->saddr0){
      if(rule->dport && rule->dport != flow->dst_port) continue;
      if(rule->daddr0 && (flow->dst_ip < rule->daddr0 || flow->dst_ip > rule->daddr1)) continue;      
      if(rule->sport && rule->sport != flow->src_port) continue;
      if(rule->saddr0 && (flow->src_ip < rule->saddr0 || flow->src_ip > rule->saddr1)) continue;
    }
    
    char* host = flow->host_server_name;
    if(host[0] == 0 || flow->ssl.client_certificate[0] != 0 || flow->ssl.server_certificate[0] != 0)
      host = flow->ssl.client_certificate[0] == 0 ? flow->ssl.server_certificate : flow->ssl.client_certificate;
    if(rule->condition.host[0] && strcasecmp(rule->condition.host,  host) != 0)
      continue;
    
    return rule;
  }
  
  return NULL;
}

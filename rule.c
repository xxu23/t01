/*
 * Copyright 2016 <copyright holder> <email>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
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
#include "zmalloc.h"

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
  if(*master)
    NDPI_BITMASK_ADD(*mask, *master);
  return prot;
}

void parse_one_rule(cJSON* json, struct rule* rule, NDPI_PROTOCOL_BITMASK* mask)
{
  cJSON* item = cJSON_GetObjectItem(json, "smac");
  if(item){
    uint8_t* mac = rule->shost;
    sscanf(item->valuestring, "%02x-%02x-%02x-%02x-%02x-%02x", mac, mac+1, mac+2, mac+3, mac+4, mac+5); 
  }
  
  item = cJSON_GetObjectItem(json, "dmac");
  if(item){
    uint8_t* mac = rule->dhost;
    sscanf(item->valuestring, "%02x-%02x-%02x-%02x-%02x-%02x", mac, mac+1, mac+2, mac+3, mac+4, mac+5); 
  }

  item = cJSON_GetObjectItem(json, "saddr");
  if(item){
    rule->saddr = inet_addr (item->valuestring);
  }
  
  item = cJSON_GetObjectItem(json, "daddr");
  if(item){
    rule->daddr = inet_addr (item->valuestring);      
  }
  
  item = cJSON_GetObjectItem(json, "sport");
  if(item){
      rule->sport = item->valueint; 
  }

  item = cJSON_GetObjectItem(json, "dport");
  if(item){
      rule->dport = item->valueint; 
  }

  item = cJSON_GetObjectItem(json, "protocol");
  if(item){
    rule->protocol = get_protocol(item->valuestring, &(rule->master_protocol), mask);
  }
  
  item = cJSON_GetObjectItem(json, "condition");
  if(item){
    cJSON* subitem = cJSON_GetObjectItem(item, "host");
    if(subitem) strcpy(rule->condition.host, subitem->valuestring);
    
    subitem = cJSON_GetObjectItem(item, "ua");
    if(subitem) strcpy(rule->condition.ua, subitem->valuestring);
  }
  
  item = cJSON_GetObjectItem(json, "action");
  if(item){
    rule->action = get_action(item->valuestring);
  }

  item = cJSON_GetObjectItem(json, "params");
  if(item){
    int m = cJSON_GetArraySize(item);
    if(m <= 9){
      int j;
      for (j = 0; j < m; j++){
	cJSON* param = cJSON_GetArrayItem(item, j);
	if(param) rule->action_params[j] = strdup(param->valuestring);
      }
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
    printf("Cannot open json file %s: %s\n", filename, strerror(errno));
    return -1;
  }
  fseek(f, 0, SEEK_END);
  size = ftell(f);
  fseek(f, 0, SEEK_SET);
	
  data = (char*)malloc(size+1);
  if(!data){
    printf("Out of memory!");
    return -2;
  }
  fread(data, 1, size, f);
  data[size]='\0';
  fclose(f);
  
  cJSON * json = cJSON_Parse(data);
  if(!json){
    printf("failed to parse json file %s: %s\n", filename, cJSON_GetErrorPtr());
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
      printf("failed to get %d json object: %s\n", i+1, cJSON_GetErrorPtr());
      continue;
     }

    struct rule* rule = malloc(sizeof(*rule));
    if(!rule) {
      msg = "Out of memory";
      ret = -2;
      goto out;
     }
    bzero(rule,  sizeof(*rule));
    
    parse_one_rule(item, rule, mask);
    rule->used = 1;
    list_add(&rule->list, head);
  }
  ret = n;
   
out:
  free(data);
  cJSON_Delete(json);
  if(ret < 0)
    printf("failed to parse json file %s: %s\n", filename, msg);
  return ret;
}

void destroy_rules(struct list_head *head)
{
  if(!head || list_empty(head)) return;
  
  struct list_head *pos, *n;
  struct rule *rule;
  list_for_each_safe(pos, n, head) {
    list_del(pos);
    rule = list_entry(pos, struct rule, list);
    free(rule);
  }
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
    
    if(rule->dport || rule->sport || rule->daddr || rule->saddr){
      uint32_t lower_ip, upper_ip;
      u_int16_t lower_port, upper_port;
      if(rule->saddr < rule->daddr) {
	lower_ip = rule->saddr;
	upper_ip = rule->daddr;
	lower_port = htons(rule->sport);
	upper_port = htons(rule->dport);
      } else {
	lower_ip = rule->daddr;
	upper_ip = rule->saddr;
	lower_port = htons(rule->dport);
	upper_port = htons(rule->sport);
      }
      
      if(lower_ip && flow->lower_ip != lower_ip && flow->upper_ip != lower_ip) continue;
      if(upper_ip && flow->upper_ip != upper_ip && flow->lower_ip != upper_ip) continue;      
      if(lower_port && flow->lower_port != lower_port && flow->upper_port != lower_port) continue;
      if(upper_port && flow->upper_port != upper_port && flow->lower_port != upper_port) continue;
    }
    
    //TODO add mac match
    //if(rule->smac[0] && memcmp(rule->smac)
    char* host = flow->host_server_name;
    if(host[0] == 0 || flow->ssl.client_certificate[0] != 0 || flow->ssl.server_certificate[0] != 0)
      host = flow->ssl.client_certificate[0] == 0 ? flow->ssl.server_certificate : flow->ssl.client_certificate;
    if(rule->condition.host[0] && strcasecmp(rule->condition.host,  host) != 0)
      continue;
    //TODO add user-agent match
    
    return rule;
  }
  
  return NULL;
}

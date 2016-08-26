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

static inline uint8_t get_protocol(const char* protocol, uint8_t* master)
{
  if(strcasecmp(protocol, "http") == 0){
    *master = NDPI_PROTOCOL_HTTP;
    return IPPROTO_TCP;
  } else if (strcasecmp(protocol, "https") == 0){
    *master = NDPI_PROTOCOL_SSL;
    return IPPROTO_TCP;
  } else if (strcasecmp(protocol, "dns") == 0){
    *master = NDPI_PROTOCOL_DNS;
    return IPPROTO_UDP;
  } else if (strcasecmp(protocol, "ssh") == 0){
    *master = NDPI_PROTOCOL_SSH;
    return IPPROTO_TCP;
  } else if (strcasecmp(protocol, "icmp") == 0){
    *master = NDPI_PROTOCOL_IP_ICMP;
    return IPPROTO_ICMP;
  } else if (strcasecmp(protocol, "icmpv6") == 0){
    *master = NDPI_PROTOCOL_IP_ICMPV6;
    return IPPROTO_ICMPV6;
  } else if (strcasecmp(protocol, "ipsec") == 0){
    *master = NDPI_PROTOCOL_IP_IPSEC;
    return IPPROTO_IP;
  } else if (strcasecmp(protocol, "pptp") == 0){
    *master = NDPI_PROTOCOL_PPTP;
    return IPPROTO_TCP;
  } else if (strcasecmp(protocol, "socks") == 0){
    *master = NDPI_PROTOCOL_SOCKS;
    return IPPROTO_UDP;
  } else if (strcasecmp(protocol, "dhcp") == 0){
    *master = NDPI_PROTOCOL_DHCP;
    return IPPROTO_UDP;
  } else if (strcasecmp(protocol, "tcp") == 0){
    *master = 0;
    return IPPROTO_TCP;
  } else if (strcasecmp(protocol, "udp") == 0){
    *master = 0;
    return IPPROTO_UDP;
  } 
  return 0;
}

void parse_one_rule(cJSON* json, struct rule* rule)
{
  cJSON* item = cJSON_GetObjectItem(json, "smac");
  if(item){
    uint8_t* mac = rule->shost;
    sscanf(item->valuestring, "%x-%x-%x-%x-%x-%x ", mac, mac+1, mac+2, mac+3, mac+4, mac+5); 
  }
  
  item = cJSON_GetObjectItem(json, "dmac");
  if(item){
    uint8_t* mac = rule->dhost;
    sscanf(item->valuestring, "%x-%x-%x-%x-%x-%x ", mac, mac+1, mac+2, mac+3, mac+4, mac+5); 
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
    rule->protocol = get_protocol(item->valuestring, &(rule->master_protocol));
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

int load_rules_from_file(const char* filename, struct rule** rule)
{
  FILE *f;
  long size;
  char *data;

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
  *rule = (struct rule*)malloc(n * sizeof(struct rule));
  if(*rule == NULL){
    msg = "Out of memory";
    ret = -2;
    goto out;
  }
  bzero(*rule,  n * sizeof(struct rule));
  
  int i;
  for(i = 0;  i < n; i++){
    cJSON* item = cJSON_GetArrayItem(json, i);
    if(!item){
      printf("failed to get %d json object: %s\n", i+1, cJSON_GetErrorPtr());
      continue;
    }
    
    parse_one_rule(item, &((*rule)[i]));
  }
  ret = n;
   
out:
  free(data);
  cJSON_Delete(json);
  if(ret < 0)
    printf("failed to parse json file %s: %s\n", filename, msg);
  return ret;
}

void destroy_rules(struct rule** rule,  int n)
{
  if(n == 0 || !rule) return;
  for(n = n-1; n >= 0; n--){
    int j;
    for(j = 0; j < 10; j++){
      if((*rule)[n].action_params[j] == NULL)
	break;
      free((*rule)[n].action_params[j]);
    }
  }
  free(*rule);
  *rule = NULL;
}

int match_rule_from_packet(struct rule* rule, int n, void* flow_, void* packet)
{
  struct ndpi_flow_info* flow = (struct ndpi_flow_info *)flow_;
  int i;
  for(i = 0; i < n; i++){
    if(flow->protocol == NDPI_PROTOCOL_UNKNOWN)
      continue;

    //printf("%d %d\n", rule[i].protocol, flow->protocol); 
    if(rule[i].protocol != flow->protocol) 
      continue;
    
    if(rule[i].master_protocol){
      uint8_t master_protocol = flow->detected_protocol.master_protocol;
      if(master_protocol == 0) master_protocol = flow->detected_protocol.protocol;
      if(master_protocol != rule[i].master_protocol)
	continue; 
    }
    
    if(rule[i].dport || rule[i].sport || rule[i].daddr || rule[i].saddr){
      uint32_t lower_ip, upper_ip;
      u_int16_t lower_port, upper_port;
      if(rule[i].saddr < rule[i].daddr) {
	lower_ip = rule[i].saddr;
	upper_ip = rule[i].daddr;
	lower_port = htons(rule[i].sport);
	upper_port = htons(rule[i].dport);
      } else {
	lower_ip = rule[i].daddr;
	upper_ip = rule[i].saddr;
	lower_port = htons(rule[i].dport);
	upper_port = htons(rule[i].sport);
      }
      if(lower_ip && flow->lower_ip != lower_ip && flow->upper_ip != lower_ip) continue;
      if(upper_ip && flow->upper_ip != upper_ip && flow->lower_ip != upper_ip) continue;      
      if(lower_port && flow->lower_port != lower_port && flow->upper_port != lower_port) continue;
      if(upper_port && flow->upper_port != upper_port && flow->lower_port != upper_port) continue;
    }
    
    //TODO add mac match
    //if(rule[i].smac[0] && memcmp(rule[i].smac)
      
    if(rule[i].condition.host[0] && strcasecmp(rule[i].condition.host, flow->host_server_name) != 0)
      continue;
    //TODO add user-agent match
    
    return i;
  }
  
  return -1;
}

#ifdef TEST
int main(int argc, char* argv[])
{
  struct rule* rule;
  int n = load_rules_from_file(argv[1], &rule);
  int i;
  
  for(i = 0; i < n; i++){
    printf("%x %x %x %x %d %d\n", rule[i].shost, rule[i].dhost, rule[i].saddr, rule[i].daddr, rule[i].sport, rule[i].dport);
    printf("%d %d\t action=%d\n", rule[i].protocol, rule[i].master_protocol, rule[i].action);
    printf("%s %s\n", rule[i].condition.host, rule[i].condition.ua);
    int j = 0;
    while(rule[i].action_params[j]){
      printf("params %d: %s\n", j, rule[i].action_params[j]);
      j ++;
    }
  }
  
  destroy_rules(&rule, n);
}
#endif
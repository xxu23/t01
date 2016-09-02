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

/* inclusion guard */
#ifndef __RULE_H__
#define __RULE_H__

struct match_payload{
  char host[256];
  char ua[64];
};

struct rule
{
  u_int8_t  shost[6];
  u_int8_t  dhost[6];
  u_int32_t saddr;
  u_int32_t daddr;
  u_int16_t sport;
  u_int16_t dport;
  u_int8_t protocol;
  u_int8_t master_protocol;
  struct match_payload condition;
  u_int8_t action;
  char *action_params[10];
};

#define T01_ACTION_REDIRECT 		1
#define T01_ACTION_REJECT		2
#define T01_ACTION_CONFUSE		3

int load_rules_from_file(const char* filename, struct rule** rule, void* ndpi_mask);

void destroy_rules(struct rule** rule,  int n);

int match_rule_from_packet(struct rule* rule, int n, void* flow, void* packet);

#endif /* __RULE_H__ */

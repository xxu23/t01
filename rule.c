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
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>
#include <regex.h>
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "t01.h"
#include "rule.h"
#include "crc64.h"
#include "cJSON.h"
#include "ndpi_api.h"
#include "ndpi_util.h"
#include "ndpi_protocol_ids.h"
#include "logger.h"
#include "zmalloc.h"
#include "util.h"

#define HT_DEFAULT_SIZE 128

#define T01_TDB_VERSION 2
#define T01_TDB_MINI_VERSION 1

#define T01_TDB_TYPE_RULE 1
#define T01_TDB_TYPE_HIT  2
#define T01_TDB_TYPE_VERSION  254
#define T01_TDB_TYPE_EOF  255

#define MAX_HITS_PER_RULE 16*1024*4

static uint32_t max_id;
static uint8_t tdbver;
static ZLIST_HEAD(rule_list);

uint64_t version = 0;

typedef struct hash_entry {
    uint32_t key;
    struct rule *value;
    struct hash_entry *next;
} hash_entry;

typedef struct hash_table {
    unsigned int key_count;
    unsigned int array_size;
    unsigned int array_size2;
    hash_entry **array;
} hash_table;

static hash_table ht;
static hash_table ht_tcp;

static inline uint8_t get_action(const char *action) {
    if (strcmp(action, "reject") == 0)
        return T01_ACTION_REJECT;
    else if (strcmp(action, "redirect") == 0)
        return T01_ACTION_REDIRECT;
    else if (strcmp(action, "confuse") == 0)
        return T01_ACTION_CONFUSE;
    else if (strcmp(action, "mirror") == 0)
        return T01_ACTION_MIRROR;
    return 0;
}

static inline uint8_t get_match(const char *match) {
    if (strcmp(match, "match") == 0)
        return T01_MATCH_MATCH;
    else if (strcmp(match, "regex") == 0)
        return T01_MATCH_REGEX;
    else if (strcmp(match, "startswith") == 0)
        return T01_MATCH_STARTSWITH;
    else if (strcmp(match, "endswith") == 0)
        return T01_MATCH_ENDSWITH;
    return 0;
}

static inline uint8_t get_which(const char *which) {
    if (strcmp(which, "url") == 0)
        return T01_WHICH_URL;
    else if (strcmp(which, "host") == 0)
        return T01_WHICH_HOST;
    return 0;
}

static inline int match_payload(int match, const char *payload,
                                const char *dst, const char *self) {
    if (match == T01_MATCH_MATCH) {
        return strcmp(payload, dst) == 0
               && strcmp(self, dst) != 0;
    } else if (match == T01_MATCH_STARTSWITH) {
        return startswith(dst, payload) == 0
               && strcmp(self, dst) != 0;
    } else if (match == T01_MATCH_ENDSWITH) {
        return endswith(dst, payload) == 0
               && strcmp(self, dst) != 0;
    } else if (match == T01_MATCH_REGEX) {
        regmatch_t pm[1];
        regex_t reg;
        int st;

        st = regcomp(&reg, payload,
                     REG_EXTENDED | REG_NOSUB | REG_ICASE);
        if (st != 0)
            return -1;
        st = regexec(&reg, dst, 1, pm, 0);
        regfree(&reg);
        return st != REG_NOMATCH && strcasecmp(self, dst) != 0;
    }
    return 0;
}

static inline uint8_t get_protocol(const char *protocol, uint8_t *master) {
    int prot = 0;
    if (strcasecmp(protocol, "http") == 0) {
        *master = NDPI_PROTOCOL_HTTP;
        prot = IPPROTO_TCP;
    } else if (strcasecmp(protocol, "https") == 0) {
        *master = NDPI_PROTOCOL_SSL;
        prot = IPPROTO_TCP;
    } else if (strcasecmp(protocol, "dns") == 0) {
        *master = NDPI_PROTOCOL_DNS;
        prot = IPPROTO_UDP;
    } else if (strcasecmp(protocol, "ssh") == 0) {
        *master = NDPI_PROTOCOL_SSH;
        prot = IPPROTO_TCP;
    } else if (strcasecmp(protocol, "icmp") == 0) {
        *master = NDPI_PROTOCOL_IP_ICMP;
        prot = IPPROTO_ICMP;
    } else if (strcasecmp(protocol, "icmpv6") == 0) {
        *master = NDPI_PROTOCOL_IP_ICMPV6;
        prot = IPPROTO_ICMPV6;
    } else if (strcasecmp(protocol, "ipsec") == 0) {
        *master = NDPI_PROTOCOL_IP_IPSEC;
        prot = IPPROTO_IP;
    } else if (strcasecmp(protocol, "pptp") == 0) {
        *master = NDPI_PROTOCOL_PPTP;
        prot = IPPROTO_TCP;
    } else if (strcasecmp(protocol, "socks") == 0) {
        *master = NDPI_PROTOCOL_SOCKS;
        prot = IPPROTO_UDP;
    } else if (strcasecmp(protocol, "dhcp") == 0) {
        *master = NDPI_PROTOCOL_DHCP;
        prot = IPPROTO_UDP;
    } else if (strcasecmp(protocol, "tcp") == 0) {
        *master = 0;
        prot = IPPROTO_TCP;
    } else if (strcasecmp(protocol, "udp") == 0) {
        *master = 0;
        prot = IPPROTO_UDP;
    }
    return prot;
}

//初始化哈希
int init_rules(int hsize) {
    if (hsize <= 0) {
        hsize = HT_DEFAULT_SIZE;
    }
 
    ht.array_size = hsize;
    ht.array_size2 = hsize - 1;
    ht.array = tcalloc(hsize, sizeof(hash_entry *));
    ht.key_count = 0;
   
    ht_tcp.array_size = hsize;
    ht_tcp.array_size2 = hsize - 1;
    ht_tcp.array = tcalloc(hsize, sizeof(hash_entry *));
    ht_tcp.key_count = 0;
}

//哈希散列方法函数
static inline unsigned int ht_index(uint32_t saddr0) {
    return saddr0 == 0 ? 0 : (saddr0 % ht.array_size2 + 1);
}

//向哈希表中插入数据
static hash_entry *he_create(uint32_t key, struct rule *value) {
    hash_entry *entry = zmalloc(sizeof(*entry));
    if (entry == NULL) {
        return NULL;
    }

    entry->key = key;
    entry->value = value;
    entry->next = NULL;
    return entry;
}

static void ht_insert_he(hash_entry *entry, hash_table *table) {
    hash_entry *tmp;
    unsigned int index;
    
    entry->next = NULL;
    index = ht_index(entry->key);
    tmp = table->array[index];

    // the first, no collision
    if (tmp == NULL) {
        table->array[index] = entry;
        table->key_count++;
        return;
    } 
    // not the first, and have slave value
    while (tmp->next != NULL) {
        tmp = tmp->next;
    }
    // else tack the new entry onto the end of the chain
    tmp->next = entry;
    table->key_count++;
}

static void ht_insert(uint32_t key, struct rule *value) {
    hash_entry *entry = he_create(key, value);
    if (entry) {
        if (entry->value->protocol == 6 && entry->value->action == T01_ACTION_REJECT){
            ht_insert_he(entry, &ht_tcp);
        } else 
            ht_insert_he(entry, &ht);
    }
}

static void ht_remove(uint32_t key, uint32_t id) {
    unsigned int index = ht_index(key);
    hash_entry *entry = ht.array[index];
    hash_entry *entry2 = ht_tcp.array[index];
    hash_entry *prev = NULL;
    hash_entry *prev2 = NULL;
    while (entry != NULL) {
        if (entry->value->id == id) {
            //the first rule
            if (prev == NULL)
                ht.array[index] = entry->next;
            else
                prev->next = entry->next;

            ht.key_count--;
            zfree(entry);
            return;
        } else {
            prev = entry;
            entry = entry->next;
        }
    }

    while (entry2 != NULL) {
        if (entry2->value->id == id) {
            //the first rule
            if (prev2 == NULL)
                ht_tcp.array[index] = entry2->next;
            else
                prev2->next = entry2->next;

            ht_tcp.key_count--;
            zfree(entry2);
            return;
        } else {
            prev2 = entry2;
            entry2 = entry2->next;
        }
    }
}

static void strrpl(char *pDstOut, const char *pSrcIn, const char *pSrcRpl,
                   const char *pDstRpl) {
    const char *pi = pSrcIn;
    char *po = pDstOut;
    int nSrcRplLen = strlen(pSrcRpl);
    int nDstRplLen = strlen(pDstRpl);
    char *p = NULL;
    int nLen = 0;

    do {
        p = strstr(pi, pSrcRpl);
        if (p != NULL) {
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

static inline get_ip(const char *ip, u_int32_t *start, u_int32_t *end) {
    if (strchr(ip, '*')) {
        char ip1[16], ip2[16];
        strrpl(ip1, ip, "*", "1");
        strrpl(ip2, ip, "*", "255");
        *start = inet_addr(ip1);
        *end = inet_addr(ip2);
        return 2;
    } else {
        *start = *end = inet_addr(ip);
        return 1;
    }
}

static int tdb_write_raw(FILE *fp, void *p, size_t len) {
    len = fwrite(p, 1, len, fp);
    if (len < 0)
        return -1;
    return len;
}

static int tdb_load_raw(FILE *fp, void *p, size_t len) {
    if (fread(p, 1, len, fp) < len)
        return -1;
    return len;
}

static int tdb_save_type(FILE *fp, unsigned char type) {
    return tdb_write_raw(fp, &type, 1);
}

static int tdb_save_rule(FILE *fp, struct rule *r) {
    return tdb_write_raw(fp, r, (char *) &r->list - (char *) r);
}

static int tdb_save_hit(FILE *fp, struct hit_record *h) {
    return tdb_write_raw(fp, h, (char *) &h->list - (char *) h);
}

static int tdb_load_type(FILE *fp) {
    unsigned char type;
    if (fread(&type, 1, 1, fp) <= 0)
        return -1;
    return type;
}

static int tdb_load_rule(FILE *fp, struct rule *r) {
    size_t len = (char *) &r->list - (char *) r;
    if (fread(r, 1, len, fp) < len)
        return -1;
    return len;
}

static int tdb_load_hit(FILE *fp, struct hit_record *h) {
    size_t len;
    if (tdbver == 1)
        len = (char *) &h->localip - (char *) h;
    else
        len = (char *) &h->list - (char *) h;
    if (fread(h, 1, len, fp) < len)
        return -1;
    return len;
}

int transform_one_rule(struct rule *rule) {
    if (rule->human_saddr[0])
        get_ip(rule->human_saddr, &rule->saddr0, &rule->saddr1);

    if (rule->human_daddr[0])
        get_ip(rule->human_daddr, &rule->daddr0, &rule->daddr1);

    if (rule->human_protocol[0])
        rule->protocol =
                get_protocol(rule->human_protocol, &(rule->master_protocol));

    if (rule->human_action[0]
        && (rule->action = get_action(rule->human_action)) == 0) {
        t01_log(T01_WARNING, "Not support action %s",
                rule->human_action);
        return -1;
    }

    if (rule->human_match[0]
        && (rule->match = get_match(rule->human_match)) == 0) {
        t01_log(T01_WARNING, "Not support match %s", rule->human_match);
        return -1;
    }

    if (rule->human_which[0]
        && (rule->which = get_which(rule->human_which)) == 0) {
        t01_log(T01_WARNING, "Not support which %s", rule->human_which);
        return -1;
    }

    return 0;
}

#define get_string_from_json(item, json, key, value)    \
  item = cJSON_GetObjectItem(json, key);            \
  if(item){                            \
    strncpy(value, item->valuestring, sizeof(value)-1);    \
  }                                    \

#define get_int_from_json(item, json, key, value)    \
  item = cJSON_GetObjectItem(json, key);            \
  if(item){                            \
    value = item->valueint;                             \
  }                                    \

#define get_string_from_arrayjson(item, json, j, value)    \
  item = cJSON_GetArrayItem(json, j);                \
  if(item) {                                \
    strncpy(value, item->valuestring, sizeof(value)-1);    \
  }                                        \


static void parse_one_rule(cJSON *json, struct rule *rule) {
    cJSON *item, *parent;

    get_string_from_json(item, json, "protocol", rule->human_protocol);
    get_string_from_json(item, json, "saddr", rule->human_saddr);
    get_string_from_json(item, json, "daddr", rule->human_daddr);
    get_string_from_json(item, json, "description", rule->description);
    get_int_from_json(item, json, "sport", rule->sport);
    get_int_from_json(item, json, "dport", rule->dport);
    get_int_from_json(item, json, "id", rule->id);
    get_int_from_json(item, json, "version", rule->version);
    get_int_from_json(item, json, "type", rule->type);
    get_int_from_json(item, json, "disabled", rule->disabled);

    parent = cJSON_GetObjectItem(json, "condition");
    if (parent) {
        get_string_from_json(item, parent, "match", rule->human_match);
        get_string_from_json(item, parent, "which", rule->human_which);
        get_string_from_json(item, parent, "payload", rule->payload);
    }

    get_string_from_json(item, json, "action", rule->human_action);

    parent = cJSON_GetObjectItem(json, "params");
    if (parent) {
        get_string_from_arrayjson(item, parent, 0,
                                  rule->action_params);
    }
}

static int load_rules_from_json(const char *data, struct list_head *head) {
    cJSON *json = cJSON_Parse(data);
    if (!json) {
        t01_log(T01_WARNING, "Cannot parse json %s: %s",
                data, cJSON_GetErrorPtr());
        return -3;
    }

    char *msg = NULL;
    int ret = 0;
    int n = cJSON_GetArraySize(json);
    if (n == 0)
        goto out;

    int i;
    for (i = 0; i < n; i++) {
        cJSON *item = cJSON_GetArrayItem(json, i);
        if (!item) {
            t01_log(T01_WARNING, "Cannot parse json: %s",
                    cJSON_GetErrorPtr());
            continue;
        }

        struct rule *rule = zmalloc(sizeof(*rule));
        if (!rule) {
            msg = "Out of memory";
            ret = -2;
            goto out;
        }
        bzero(rule, sizeof(*rule));
        INIT_LIST_HEAD(&rule->hit_head);

        parse_one_rule(item, rule);
        if (transform_one_rule(rule) < 0) {
            zfree(rule);
            continue;
        }
        rule->used = 1;
        list_add_tail(&rule->list, head);
        if (rule->id == 0)
            rule->id = ++max_id;
        else if (rule->id > max_id)
            max_id = rule->id;
    }
    ret = n;

    out:
    cJSON_Delete(json);
    if (ret < 0)
        t01_log(T01_WARNING, "Cannot parse json: %s", msg);
    return ret;
}

int load_rules(const char *filename) {
    uint32_t dbid;
    int type, i = 0;
    char buf[8];
    FILE *fp;
    struct rule *curr_rule;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        t01_log(T01_WARNING,
                "Cannot read rule %s: %s.", filename, strerror(errno));
        return 0;
    }

    if (tdb_load_raw(fp, buf, 8) == 0)
        goto eoferr;

    if (memcmp(buf, "T01", 3) != 0 && memcmp(buf, "[", 1) != 0) {
        fclose(fp);
        t01_log(T01_WARNING,
                "Wrong signature trying to load DB from file");
        return -1;
    }

    if (memcmp(buf, "[", 1) == 0) {
        long size;
        char *data;
        int ret;

        fseek(fp, 0, SEEK_END);
        size = ftell(fp) + 8;
        fseek(fp, 0, SEEK_SET);
        data = (char *) zmalloc(size + 1);
        if (!data) {
            t01_log(T01_WARNING, "Out of memory!");
            goto eoferr;
        }
        fread(data, 1, size, fp);
        data[size] = '\0';
        fclose(fp);

        ret = load_rules_from_json(data, &rule_list);
        zfree(data);
        return ret;
    }

    tdbver = atoi(buf + 3);
    if (tdbver < T01_TDB_MINI_VERSION) {
        fclose(fp);
        t01_log(T01_WARNING, "Can't handle TDB format early than version %d",
                tdbver);
        return -1;
    }

    while (1) {
        if ((type = tdb_load_type(fp)) == -1)
            break;

        if (type == T01_TDB_TYPE_RULE) {
            struct rule *r = zmalloc(sizeof(*r));
            if (!r)
                goto eoferr;
            bzero(r, sizeof(*r));
            INIT_LIST_HEAD(&r->hit_head);
            if (tdb_load_rule(fp, r) == -1)
                goto eoferr;

            //Avoid load rules have the same rule_id
            if (get_rule(r->id, NULL, NULL) == 0) {
                zfree(r);
                continue;
            }

            list_add_tail(&r->list, &rule_list);
            curr_rule = r;
            r->saved_hits = 0;
            i++;
            if (r->id > max_id)
                max_id = r->id;
            if (r->version > version)
                version = r->version;
            ht_insert(r->saddr0, r);
        } else if (type == T01_TDB_TYPE_HIT) {
            struct hit_record *h = zmalloc(sizeof(*h));
            if (!h)
                goto eoferr;
            bzero(h, sizeof(*h));
            if (tdb_load_hit(fp, h) == -1)
                goto eoferr;
            if (h->rule_id != curr_rule->id || curr_rule->saved_hits == MAX_HITS_PER_RULE) {
                zfree(h);
                continue;
            }
            list_add_tail(&h->list, &curr_rule->hit_head);
            curr_rule->saved_hits++;
        } else if (type == T01_TDB_TYPE_VERSION) {
            tdb_load_raw(fp, &version, sizeof(version));
            break;
        } else if (type == T01_TDB_TYPE_EOF) {
            break;
        }
    }

    fclose(fp);
    return i;

    eoferr:            /* unexpected end of file is handled here with a fatal exit */
    t01_log(T01_WARNING,
            "Short read or OOM loading DB. Unrecoverable error, aborting now.");
    exit(1);
    return -1;
}

int add_log_rz(struct log_rz *lr) {
    struct rule *r = NULL;
    struct hit_record *h;
    struct list_head *pos;

    list_for_each(pos, &rule_list) {
        struct rule *rule = list_entry(pos, struct rule, list);
        if (rule->id == lr->rule_id) {
            r = rule;
            break;
        }
    }
    if (!r)
        return -1;

    return add_hit_record(r, lr->time, lr->src_ip, lr->dst_ip, lr->src_port,
                          lr->dst_port, lr->smac, lr->dmac, lr->local_ip,
                          lr->proto, lr->pktlen);
}

int add_hit_record(struct rule *r, uint64_t time, uint32_t saddr,
                   uint32_t daddr, uint16_t sport, uint16_t dport,
                   uint8_t smac[], uint8_t dmac[], uint32_t localip,
                   uint8_t proto, uint16_t pktlen) {
    struct hit_record *h = NULL;

    if (r->saved_hits == MAX_HITS_PER_RULE) {
        struct list_head *tail = r->hit_head.prev;
        h = list_entry(tail, struct hit_record, list);
        r->saved_hits--;
        list_del(tail);
    } else {
        h = zmalloc(sizeof(*h));
    }
    if (!h)
        return -1;
    bzero(h, sizeof(*h));

    list_add_tail(&h->list, &r->hit_head);

    r->hits++;
    r->saved_hits++;
    dirty++;

    h->rule_id = r->id;
    h->time = time;
    h->saddr = saddr;
    h->daddr = daddr;
    h->sport = sport;
    h->dport = dport;
    h->localip = localip;
    h->pktlen = pktlen;
    h->proto = proto;
    memcpy(h->smac, smac, 6);
    memcpy(h->dmac, dmac, 6);
    h->id = r->hits;

    return 0;
}

void destroy_rules() {
    if (list_empty(&rule_list))
        return;

    struct list_head *pos, *n, *pos2, *n2, *hhead;
    struct rule *rule;
    struct hit_record *hit;

    list_for_each_safe(pos, n, &rule_list) {
        list_del(pos);
        rule = list_entry(pos, struct rule, list);
        hhead = &rule->hit_head;
        if (list_empty(hhead) == 0)
            list_for_each_safe(pos2, n2, hhead) {
                list_del(pos2);
                hit = list_entry(pos2, struct hit_record, list);
                zfree(hit);
            }
        zfree(rule);
    }
}

int save_rules(const char *filename) {
    char tmpfile[256];
    FILE *fp;
    char magic[8];
    struct list_head *pos;
    struct rule *rule;

    snprintf(tmpfile, 256, "temp-%d.tdb", (int) getpid());
    fp = fopen(tmpfile, "w");
    if (!fp) {
        t01_log(T01_WARNING, "Failed opening .tdb for saving: %s",
                strerror(errno));
        return -1;
    }

    snprintf(magic, sizeof(magic), "T01%04d", T01_TDB_VERSION);
    if (tdb_write_raw(fp, magic, 8) == -1)
        goto werr;

    list_for_each(pos, &rule_list) {
        struct list_head *pos2;
        struct hit_record *hit;
        rule = list_entry(pos, struct rule, list);
        if (rule->used == 0)
            continue;

        if (tdb_save_type(fp, T01_TDB_TYPE_RULE) < 0)
            goto werr;
        if (tdb_save_rule(fp, rule) < 0)
            goto werr;

        list_for_each(pos2, &rule->hit_head) {
            hit = list_entry(pos2, struct hit_record, list);
            if (tdb_save_type(fp, T01_TDB_TYPE_HIT) < 0)
                goto werr;
            if (tdb_save_hit(fp, hit) < 0)
                goto werr;
        }
    }
    if (tdb_save_type(fp, T01_TDB_TYPE_VERSION) < 0)
        goto werr;
    if (tdb_write_raw(fp, &version, sizeof(version)) < 0)
        goto werr;

    if (tdb_save_type(fp, T01_TDB_TYPE_EOF) < 0)
        goto werr;

    /* Make sure data will not remain on the OS's output buffers */
    if (fflush(fp) == EOF)
        goto werr;
    if (fsync(fileno(fp)) == -1)
        goto werr;
    if (fclose(fp) == EOF)
        goto werr;

    /* Use RENAME to make sure the DB file is changed atomically only
     * if the generate DB file is ok. */
    if (rename(tmpfile, filename) == -1) {
        t01_log(T01_WARNING,
                "Error moving temp DB file on the final destination: %s",
                strerror(errno));
        unlink(tmpfile);
        return -1;
    }

    t01_log(T01_NOTICE, "DB saved on disk");
    dirty = 0;
    lastsave = time(NULL);
    lastbgsave_status = 0;
    return 0;

    werr:
    t01_log(T01_WARNING, "Write error saving DB on disk: %s",
            strerror(errno));
    fclose(fp);
    unlink(tmpfile);
    return -1;
}

int save_rules_background(const char *filename) {
    pid_t childpid;
    long long start;

    if (tdb_child_pid != -1)
        return -1;

    dirty_before_bgsave = dirty;

    if ((childpid = fork()) == 0) {
        int retval;
        /* Child */
        close_listening_sockets();
        retval = save_rules(filename);
        _exit((retval == 0) ? 0 : 1);
    } else {
        /* Parent */
        if (childpid == -1) {
            lastbgsave_status = -1;
            t01_log(T01_WARNING,
                    "Can't save in background: fork: %s",
                    strerror(errno));
            return -1;
        }
        t01_log(T01_NOTICE, "Background saving started by pid %d",
                childpid);
        //server.rdb_save_time_start = time(NULL);
        tdb_child_pid = childpid;
        return 0;
    }
    return 0;        /* unreached */
}

static void tdb_remove_tempfile(pid_t childpid) {
    char tmpfile[256];
    snprintf(tmpfile, 256, "temp-%d.tdb", (int) childpid);
    unlink(tmpfile);
}

void background_save_done_handler(int exitcode, int bysignal) {
    if (!bysignal && exitcode == 0) {
        t01_log(T01_NOTICE,
                "Background saving terminated with success");
        dirty = dirty - dirty_before_bgsave;
        lastsave = time(NULL);
        lastbgsave_status = 0;
    } else if (!bysignal && exitcode != 0) {
        t01_log(T01_WARNING, "Background saving error");
        lastbgsave_status = -1;
    } else {
        t01_log(T01_WARNING,
                "Background saving terminated by signal %d", bysignal);
        tdb_remove_tempfile(tdb_child_pid);
        if (bysignal != SIGUSR1)
            lastbgsave_status = -1;
    }

    tdb_child_pid = -1;
}

void release_buffer(char **out) {
    if (*out)
        zfree(*out);
}

static cJSON *rule2cjson(struct rule *rule) {
    cJSON *root = cJSON_CreateObject(), *array;
    cJSON *condition = cJSON_CreateObject();
    int n = 0, i;
    const char *strings[1] = {rule->action_params};

    cJSON_AddNumberToObject(root, "id", rule->id);
    cJSON_AddNumberToObject(root, "disabled", rule->disabled);
    cJSON_AddNumberToObject(root, "type", rule->type);
    cJSON_AddNumberToObject(root, "version", rule->version);
    if (rule->human_protocol[0])
        cJSON_AddStringToObject(root, "protocol", rule->human_protocol);
    if (rule->description[0])
        cJSON_AddStringToObject(root, "description", rule->description);
    if (rule->human_saddr[0])
        cJSON_AddStringToObject(root, "saddr", rule->human_saddr);
    if (rule->human_daddr[0])
        cJSON_AddStringToObject(root, "daddr", rule->human_daddr);
    if (rule->human_action[0])
        cJSON_AddStringToObject(root, "action", rule->human_action);

    if (rule->payload[0])
        cJSON_AddStringToObject(condition, "payload", rule->payload);
    if (rule->human_match[0])
        cJSON_AddStringToObject(condition, "match", rule->human_match);
    if (rule->human_which[0])
        cJSON_AddStringToObject(condition, "which", rule->human_which);
    cJSON_AddItemToObject(root, "condition", condition);

    if (rule->sport)
        cJSON_AddNumberToObject(root, "sport", rule->sport);
    if (rule->dport)
        cJSON_AddNumberToObject(root, "dport", rule->dport);

    if (rule->action_params[0])
        n = 1;
    if (n > 0) {
        array = cJSON_CreateStringArray(strings, n);
        cJSON_AddItemToObject(root, "params", array);
    }

    cJSON_AddNumberToObject(root, "total_hits", rule->hits);
    cJSON_AddNumberToObject(root, "saved_hits", rule->saved_hits);

    return root;
}

static char *cjson2string(cJSON *root) {
    char *render, *result;

    render = cJSON_PrintUnformatted(root);
    result = zmalloc(strlen(render) + 1);
    strcpy(result, render);
    cJSON_Delete(root);
    cJSON_FreePrint(render);

    return result;

}

static char *rule2jsonstr(struct rule *rule) {
    cJSON *root = rule2cjson(rule);
    return cjson2string(root);
}

int get_ruleids(int type, uint8_t match, uint8_t disabled, uint8_t action,
                const char *kw, int offset, int limit,
                char **out, size_t *out_len, int json) {
    uint32_t *ids;
    struct list_head *pos;
    int n = 0, i = 0, j = 0;
    if (type < 0)
        type = 0;
    list_for_each(pos, &rule_list) {
        struct rule *rule = list_entry(pos, struct rule, list);
        if (rule->used == 0 || (type && rule->type != type))
            continue;
        if (kw && kw[0] &&
            (strstr(rule->payload, kw) == NULL
             && strstr(rule->action_params, kw) == NULL
             && strstr(rule->human_saddr, kw) == NULL
             && strstr(rule->human_daddr, kw) == NULL
             && strstr(rule->description, kw) == NULL))
            continue;
        if (match && rule->match != match)
            continue;
        if (action && rule->action != action)
            continue;
        if (disabled != 0xff && rule->disabled != disabled)
            continue;
        if (limit == 0) {
            n++;
        } else if (j++ >= offset && n < limit) {
            n++;
        }
    }

    if (n == 0) {
        cJSON *array = cJSON_CreateIntArray(NULL, n);
        *out = cjson2string(array);
        *out_len = strlen(*out);
        return 0;
    }

    ids = (uint32_t *) zmalloc(sizeof(uint32_t) * n);
    bzero(ids, sizeof(uint32_t) * n);
    j = 0;
    if (!ids)
        return -1;
    list_for_each(pos, &rule_list) {
        struct rule *rule = list_entry(pos, struct rule, list);
        if (rule->used == 0 || (type && rule->type != type))
            continue;
        if (kw && kw[0] &&
            (strstr(rule->payload, kw) == NULL
             && strstr(rule->action_params, kw) == NULL
             && strstr(rule->human_saddr, kw) == NULL
             && strstr(rule->human_daddr, kw) == NULL
             && strstr(rule->description, kw) == NULL))
            continue;
        if (match && rule->match != match)
            continue;
        if (action && rule->action != action)
            continue;
        if (disabled != 0xff && rule->disabled != disabled)
            continue;
        if (limit == 0) {
            ids[i++] = rule->id;
        } else if (j++ >= offset && i < limit) {
            ids[i++] = rule->id;
        }
    }
    if (!json) {
        *out = (char *) ids;
        *out_len = sizeof(uint32_t) * n;
        return 0;
    }

    cJSON *array = cJSON_CreateIntArray((int *) ids, n);
    *out = cjson2string(array);
    *out_len = strlen(*out);

    return 0;
}

int get_rule(uint32_t id, char **out, size_t *out_len) {
    struct list_head *pos;
    struct rule *rule = NULL;
    list_for_each(pos, &rule_list) {
        struct rule *rule2 = list_entry(pos, struct rule, list);
        if (rule2->id == id && rule2->used == 1) {
            rule = rule2;
            break;
        }
    }

    if (!rule)
        return -1;

    if (out) *out = rule2jsonstr(rule);
    if (out_len && out) *out_len = strlen(*out);

    return 0;
}

int get_summary(int type, char **out, size_t *out_len) {
    struct list_head *pos;
    int nrules = 0, nenabled = 0, nhits = 0;
    cJSON *root = cJSON_CreateObject();
    if (type < 0)
        type = 0;

    list_for_each(pos, &rule_list) {
        struct rule *rule = list_entry(pos, struct rule, list);
        if (rule->used == 0 || (type && rule->type != type))
            continue;
        nrules++;
        if (rule->disabled == 0)
            nenabled++;
        nhits += rule->hits;
    }

    cJSON_AddNumberToObject(root, "total_rules", nrules);
    cJSON_AddNumberToObject(root, "enabled_rules", nenabled);
    cJSON_AddNumberToObject(root, "hits", nhits);

    *out = cjson2string(root);
    *out_len = strlen(*out);
    return 0;
}

int disable_rule(uint32_t id) {
    struct list_head *pos;
    struct rule *rule = NULL;
    list_for_each(pos, &rule_list) {
        struct rule *rule2 = list_entry(pos, struct rule, list);
        if (rule2->id == id && rule2->used == 1) {
            rule = rule2;
            break;
        }
    }

    if (!rule)
        return -1;

    if (rule->disabled == 0) {
        rule->disabled = 1;
        dirty += HITS_THRESHOLD_PER_SECOND;
    }

    return 0;
}

int enable_rule(uint32_t id) {
    struct list_head *pos;
    struct rule *rule = NULL;
    list_for_each(pos, &rule_list) {
        struct rule *rule2 = list_entry(pos, struct rule, list);
        if (rule2->id == id && rule2->used == 1) {
            rule = rule2;
            break;
        }
    }

    if (!rule)
        return -1;

    if (rule->disabled) {
        rule->disabled = 0;
        dirty += HITS_THRESHOLD_PER_SECOND;
    }

    return 0;
}

int get_rules(uint32_t *ids, size_t len, char **out, size_t *out_len) {
    int i;
    struct list_head *pos;
    cJSON *root = cJSON_CreateArray();

    list_for_each(pos, &rule_list) {
        struct rule *rule = list_entry(pos, struct rule, list);
        if (rule->used == 0)
            continue;
        for (i = 0; i < len; i++) {
            if (rule->id == ids[i]) {
                cJSON_AddItemToArray(root, rule2cjson(rule));
                break;
            }
        }
    }

    *out = cjson2string(root);
    *out_len = strlen(*out);

    return 0;
}

static cJSON *hit2cjson(struct hit_record *hit) {
    cJSON *root = cJSON_CreateObject();
    int n = 0, i;
    char ip[48];

    cJSON_AddNumberToObject(root, "id", hit->id);
    cJSON_AddNumberToObject(root, "rule_id", hit->rule_id);
    cJSON_AddNumberToObject(root, "time", hit->time);
    cJSON_AddNumberToObject(root, "pktlen", hit->pktlen);
    if (hit->sport)
        cJSON_AddNumberToObject(root, "sport", hit->sport);
    if (hit->dport)
        cJSON_AddNumberToObject(root, "dport", hit->dport);

    if (hit->saddr) {
        inet_ntop(AF_INET, &hit->saddr, ip, sizeof(ip));
        cJSON_AddStringToObject(root, "saddr", ip);
    }

    if (hit->daddr) {
        inet_ntop(AF_INET, &hit->daddr, ip, sizeof(ip));
        cJSON_AddStringToObject(root, "daddr", ip);
    }

    if (hit->localip) {
        inet_ntop(AF_INET, &hit->localip, ip, sizeof(ip));
        cJSON_AddStringToObject(root, "localip", ip);
    }

    {
        strcpy(ip, ipproto_name(hit->proto));
        cJSON_AddStringToObject(root, "proto", ip);
    }

    sprintf(ip, "%02x-%02x-%02x-%02x-%02x-%02x",
            hit->smac[0], hit->smac[1], hit->smac[2],
            hit->smac[3], hit->smac[4], hit->smac[5]);
    cJSON_AddStringToObject(root, "smac", ip);

    sprintf(ip, "%02x-%02x-%02x-%02x-%02x-%02x",
            hit->dmac[0], hit->dmac[1], hit->dmac[2],
            hit->dmac[3], hit->dmac[4], hit->dmac[5]);
    cJSON_AddStringToObject(root, "dmac", ip);

    return root;
}

int get_hits(uint32_t rule_id, int offset, int limit, char **out,
             size_t *out_len) {
    struct list_head *pos;
    struct rule *rule = NULL;
    struct hit_record *hit;
    cJSON *root = cJSON_CreateArray();
    int i = 0;

    list_for_each(pos, &rule_list) {
        struct rule *rule2 = list_entry(pos, struct rule, list);
        if (rule2->id == rule_id && rule2->used == 1) {
            rule = rule2;
            break;
        }
    }

    if (!rule)
        return -1;

    list_for_each(pos, &rule->hit_head) {
        if (i++ < offset)
            continue;
        hit = list_entry(pos, struct hit_record, list);
        cJSON_AddItemToArray(root, hit2cjson(hit));
        if (--limit == 0)
            break;
    }

    *out = cjson2string(root);
    *out_len = strlen(*out);

    return 0;
}

int update_rule(uint32_t id, const char *body, int body_len) {
    struct list_head *pos;
    struct rule new_rule;
    cJSON *root = cJSON_Parse(body);
    if (!root) {
        t01_log(T01_WARNING, "Cannot parse json: %s",
                cJSON_GetErrorPtr());
        return -1;
    }
    bzero(&new_rule, sizeof(new_rule));
    parse_one_rule(root, &new_rule);
    new_rule.id = id;
    new_rule.used = 1;
    cJSON_Delete(root);
    if (transform_one_rule(&new_rule) < 0)
        return -1;

    list_for_each(pos, &rule_list) {
        struct rule *rule = list_entry(pos, struct rule, list);
        if (rule->id == id && rule->used == 1) {
            new_rule.hits = rule->hits;
            new_rule.saved_hits = rule->saved_hits;
            if (new_rule.version == 0)
                new_rule.version = ++version;
            else if (new_rule.version > version)
                version = new_rule.version;
            ht_remove(rule->saddr0, rule->id);
            memcpy(rule, &new_rule, offsetof(struct rule, list));
            ht_insert(rule->saddr0, rule);
            t01_log(T01_NOTICE, "Update rule %d version %lld",
                    new_rule.id, new_rule.version);
            dirty += HITS_THRESHOLD_PER_SECOND;
            return 0;
        }
    }
    return -1;
}

int delete_rule(uint32_t id) {
    struct list_head *pos, *n;
    struct rule *rule;
    struct hit_record *hit;
    list_for_each_safe(pos, n, &rule_list) {
        rule = list_entry(pos, struct rule, list);
        if (rule->id == id && rule->used == 1) {
            struct list_head *pos2, *n2, *hhead;
            hhead = &rule->hit_head;
            rule->used = 0;
            rule->disabled = 0;
            ht_remove(rule->saddr0, rule->id);
            if (list_empty(hhead) == 0)
                list_for_each_safe(pos2, n2, hhead) {
                    list_del(pos2);
                    hit = list_entry(pos2, struct hit_record, list);
                    zfree(hit);
                }
            bzero(rule, offsetof(struct rule, list));
            dirty += HITS_THRESHOLD_PER_SECOND;
            return 0;
        }
    }

    return -1;
}

int create_rule(const char *body, int body_len, char **out, size_t *out_len) {
    int offset;
    struct rule src_rule, *new_rule = NULL;
    struct list_head *pos;
    cJSON *root;
    uint32_t rule_id = 0;

    root = cJSON_Parse(body);
    if (!root) {
        t01_log(T01_WARNING, "Cannot parse json: %s",
                cJSON_GetErrorPtr());
        return -1;
    }
    bzero(&src_rule, sizeof(src_rule));
    parse_one_rule(root, &src_rule);
    cJSON_Delete(root);
    if (transform_one_rule(&src_rule) < 0)
        return -1;

    /* Find a recycled rule */
    list_for_each(pos, &rule_list) {
        struct rule *rule = list_entry(pos, struct rule, list);
        if (rule->used == 0) {
            new_rule = rule;
            break;
        }
    }

    /* Not found, malloc a rule */
    if (!new_rule) {
        new_rule = zmalloc(sizeof(*new_rule));
        if (!new_rule) {
            return -1;
        }
        bzero(new_rule, sizeof(*new_rule));
        INIT_LIST_HEAD(&new_rule->hit_head);
        list_add_tail(&new_rule->list, &rule_list);
    }

    memcpy(new_rule, &src_rule, offsetof(struct rule, list));
    new_rule->used = 1;
    new_rule->disabled = 0;
    if (new_rule->version == 0)
        new_rule->version = ++version;
    else if (new_rule->version > version)
        version = new_rule->version;
    rule_id = src_rule.id;
    list_for_each(pos, &rule_list) {
        struct rule *rule = list_entry(pos, struct rule, list);
        if (rule_id == rule->id) {
            rule_id = ++max_id;
            break;
        }
    }
    new_rule->id = rule_id ? rule_id : ++max_id;
    t01_log(T01_NOTICE, "Create rule %d version %lld",
            new_rule->id, new_rule->version);
    dirty += HITS_THRESHOLD_PER_SECOND;

    ht_insert(new_rule->saddr0, new_rule);
    get_rule(new_rule->id, out, out_len);

    return 0;
}

int sync_rules(const char *body, int body_len) {
    char *msg = NULL;
    struct rule *rules = NULL;
    int ret = 0;
    int nrules, i;
    cJSON *json;
    struct list_head *pos, *n;
    struct rule *rule;
    struct hit_record *hit;

    /* Step 1: parse json rules */
    if (!(json = cJSON_Parse(body))) {
        t01_log(T01_WARNING, "Cannot parse json: %s",
                cJSON_GetErrorPtr());
        return -3;
    }
    nrules = cJSON_GetArraySize(json);
    if (nrules == 0)
        goto step1;
    rules = zmalloc(nrules * sizeof(struct rule));
    if (!rules) {
        msg = "Out of memory";
        ret = -2;
        goto step1;
    }
    for (i = 0; i < nrules; i++) {
        cJSON *item = cJSON_GetArrayItem(json, i);
        struct rule *rule = rules + i;
        if (!item) {
            t01_log(T01_WARNING, "Cannot parse %d item: %s",
                    i, cJSON_GetErrorPtr());
            continue;
        }

        bzero(rule, sizeof(struct rule));
        parse_one_rule(item, rule);
        if (transform_one_rule(rule) < 0)
            continue;
        rule->used = 1;
    }
    step1:
    cJSON_Delete(json);
    if (ret < 0) {
        t01_log(T01_WARNING, "Cannot sync rules: %s", msg);
        return ret;
    }

    /* Step 2: Walk through original slave rules and check whether it matches
     * with master rules. If not match delete original slave rule. */
    list_for_each_safe(pos, n, &rule_list) {
        rule = list_entry(pos, struct rule, list);
        if (rule->used == 0) continue;
        for (i = 0; i < nrules; i++) {
            if (rule->id == rules[i].id)
                break;
        }

        if (i == nrules) {
            /* doesn't match, destroy match and hits */
            struct list_head *pos2, *n2, *hhead;
            t01_log(T01_NOTICE, "Sync rules: remove rule %d", rule->id);
            hhead = &rule->hit_head;
            rule->used = 0;
            if (list_empty(hhead) == 0) {
                list_for_each_safe(pos2, n2, hhead) {
                    list_del(pos2);
                    hit = list_entry(pos2, struct hit_record, list);
                    zfree(hit);
                }
            }
            bzero(rule, offsetof(struct rule, list));
            dirty += HITS_THRESHOLD_PER_SECOND;
        } else {
            /* id match, check rule's content further */
            if (memcmp(rule, &rules[i], offsetof(struct rule, protocol)) != 0 || rule->disabled != rules[i].disabled) {
                struct list_head *pos2, *n2, *hhead;
                t01_log(T01_NOTICE, "Sync rules: update rule %d version %lld",
                        rules[i].id, rules[i].version);
                // Remove entry from hashtable
                ht_remove(rule->saddr0, rule->id);
                memcpy(rule, &rules[i], offsetof(struct rule, protocol));
                rule->disabled = rules[i].disabled;
                hhead = &rule->hit_head;
                if (list_empty(hhead) == 0) {
                    list_for_each_safe(pos2, n2, hhead) {
                        list_del(pos2);
                        hit = list_entry(pos2, struct hit_record, list);
                        zfree(hit);
                    }
                    rule->hits = rule->saved_hits = 0;
                }
                if (rule->version > version)
                    version = rule->version;
                dirty += HITS_THRESHOLD_PER_SECOND;
                // Insert entry
                ht_insert(rule->saddr0, rule);
            }
            rules[i].used = 2;
        }
    }

    /* Step 3: Walk through post-processed master rules and insert into original slave rule. */
    for (i = 0; i < nrules; i++) {
        struct rule *new_rule = NULL;

        if (rules[i].used == 2) continue;

        /* Find a recycled rule or malloc new rule */
        list_for_each(pos, &rule_list) {
            struct rule *rule2 = list_entry(pos, struct rule, list);
            if (rule2->used == 0) {
                new_rule = rule2;
                break;
            }
        }
        if (!new_rule) {
            t01_log(T01_NOTICE, "Sync rules: add rule %d version %lld",
                    rules[i].id, rules[i].version);
            new_rule = zmalloc(sizeof(*new_rule));
            if (!new_rule) {
                return -1;
            }
            bzero(new_rule, sizeof(*new_rule));
            INIT_LIST_HEAD(&new_rule->hit_head);
            list_add_tail(&new_rule->list, &rule_list);
        }

        memcpy(new_rule, &rules[i], offsetof(struct rule, list));
        new_rule->used = 1;
        ht_insert(new_rule->saddr0, new_rule);
        dirty += HITS_THRESHOLD_PER_SECOND;
        if (new_rule->id > max_id)
            max_id = new_rule->id;
        if (new_rule->version > version)
            version = new_rule->version;
        transform_one_rule(new_rule);
    }

    step2:
    zfree(rules);

    return ret;
}

struct rule *match_rule_before_mirrored(struct ndpi_flow_info *flow) {
    struct list_head *pos;
    list_for_each(pos, &rule_list) {
        struct rule *rule = list_entry(pos, struct rule, list);
        if (rule->used == 0 || rule->action != T01_ACTION_MIRROR)
            continue;

        if (rule->dport || rule->sport || rule->daddr0 || rule->saddr0) {
            if (rule->dport && rule->dport != flow->dst_port)
                continue;
            if (rule->daddr0
                && (flow->dst_ip < rule->daddr0
                    || flow->dst_ip > rule->daddr1))
                continue;
            if (rule->sport && rule->sport != flow->src_port)
                continue;
            if (rule->saddr0
                && (flow->src_ip < rule->saddr0
                    || flow->src_ip > rule->saddr1))
                continue;
        }

        return rule;
    }

    return NULL;
}

struct rule *match_rule_from_hashtable(struct ndpi_flow_info *flow, int index) {
    hash_table *table = &ht;
    hash_entry *tmp = table->array[index];

    while (tmp != NULL && tmp->value != NULL) {
        struct rule *rule = tmp->value;

        if (rule->used == 0 ||
            rule->disabled ||
            flow->protocol == NDPI_PROTOCOL_UNKNOWN ||
            flow->protocol != rule->protocol) {
            tmp = tmp->next;
            continue;
        }

        if (rule->master_protocol) {
            uint8_t master_protocol =
                    flow->detected_protocol.master_protocol;
            //if (master_protocol == 0)
            master_protocol = master_protocol == 0 ?
                              flow->detected_protocol.protocol :
                              master_protocol;
            if (master_protocol != rule->master_protocol) {
                tmp = tmp->next;
                continue;
            }
        }

        if (rule->saddr0 && (flow->src_ip < rule->saddr0
                             || flow->src_ip > rule->saddr1)) {
            tmp = tmp->next;
            continue;
        }

        if (rule->dport && rule->dport != flow->dst_port) {
            tmp = tmp->next;
            continue;
        }

        if (rule->sport && rule->sport != flow->src_port) {
            tmp = tmp->next;
            continue;
        }

        if (rule->daddr0 && (flow->dst_ip < rule->daddr0
                             || flow->dst_ip > rule->daddr1)) {
            tmp = tmp->next;
            continue;
        }

        if (rule->payload[0]) {
            uint8_t which = rule->which;
            uint8_t match = rule->match;
            if (which == T01_WHICH_HOST) {
                char *host = flow->host_server_name;
                if (!host[0] || match_payload(match, rule->payload, host,
                                              rule->action_params) != 1) {
                    tmp = tmp->next;
                    continue;
                }
            } else if (which == T01_WHICH_URL) {
                char *url = flow->ndpi_flow->http.url;
                if (!url || (url[0] &&
                             match_payload(match, rule->payload, url,
                                           rule->action_params) != 1)) {
                    tmp = tmp->next;
                    continue;
                }
            }
        }
        return rule;
    }

    return NULL;
}

struct rule *match_rule_from_tcp(struct iphdr *ippkt, struct tcphdr *tcppkt, int index){
    hash_table *table = &ht_tcp;
    hash_entry *tmp = table->array[index];
    
    while (tmp != NULL && tmp->value != NULL) {
        struct rule *rule = tmp->value;

        if (rule->used == 0 ||
            rule->disabled ||
            ippkt->protocol != rule->protocol) {
            tmp = tmp->next;
            continue;
        }

        if (rule->saddr0 && (ippkt->saddr < rule->saddr0
                             || ippkt->saddr > rule->saddr1)) {
            tmp = tmp->next;
            continue;
        }

        if (rule->dport && rule->dport != ntohs(tcppkt->dest)) {
            tmp = tmp->next;
            continue;
        }

        if (rule->sport && rule->sport != ntohs(tcppkt->source)) {
            tmp = tmp->next;
            continue;
        }

        if (rule->daddr0 && (ippkt->daddr < rule->daddr0
                             || ippkt->daddr > rule->daddr1)) {
            tmp = tmp->next;
            continue;
        }
        
        return rule;
    }

    return NULL;
}

struct rule *match_rule_from_htable_tcp(const u_char *data){
    struct ether_header *ethhdr = (struct ether_header *)data;
    struct iphdr *ippkt = (struct iphdr *)(ethhdr + 1);
    struct tcphdr *tcppkt = (struct tcphdr *)(ippkt + 1);

    int index = ht_index(ippkt->saddr);
    struct rule *rule = NULL;

    rule = match_rule_from_tcp(ippkt, tcppkt, 0);
    if(rule != NULL){
        return rule;
    }
    
    rule = match_rule_from_tcp(ippkt, tcppkt, index);
    return rule;
}

struct rule *match_rule_from_htable_after_detected(struct ndpi_flow_info *flow) {
    int index = ht_index(flow->src_ip);
    struct rule *rule = NULL;

    rule = match_rule_from_hashtable(flow, 0);
    if (rule != NULL) {
        return rule;
    }

    rule = match_rule_from_hashtable(flow, index);
    return rule;
}

struct rule *match_rule_after_detected(struct ndpi_flow_info *flow) {
    struct list_head *pos;
    list_for_each(pos, &rule_list) {
        struct rule *rule = list_entry(pos, struct rule, list);

        if (rule->used == 0 ||
            rule->disabled ||
            flow->protocol == NDPI_PROTOCOL_UNKNOWN ||
            flow->protocol != rule->protocol)
            continue;

        if (rule->master_protocol) {
            uint8_t master_protocol =
                    flow->detected_protocol.master_protocol;
            //if (master_protocol == 0)
            master_protocol = master_protocol == 0 ?
                              flow->detected_protocol.protocol :
                              master_protocol;
            if (master_protocol != rule->master_protocol)
                continue;
        }

        if (rule->saddr0 && (flow->src_ip < rule->saddr0
                             || flow->src_ip > rule->saddr1))
            continue;
        if (rule->dport && rule->dport != flow->dst_port)
            continue;
        if (rule->sport && rule->sport != flow->src_port)
            continue;
        if (rule->daddr0 && (flow->dst_ip < rule->daddr0
                             || flow->dst_ip > rule->daddr1))
            continue;

        if (rule->payload[0]) {
            uint8_t which = rule->which;
            uint8_t match = rule->match;
            if (which == T01_WHICH_HOST) {
                char *host = flow->host_server_name;
                if (!host[0] || match_payload(match, rule->payload, host,
                                              rule->action_params) != 1)
                    continue;
            } else if (which == T01_WHICH_URL) {
                char *url = flow->ndpi_flow->http.url;
                if (!url || (url[0] &&
                             match_payload(match, rule->payload, url,
                                           rule->action_params) != 1))
                    continue;
            }
        }

        return rule;
    }

    return NULL;
}

static int rule_cmp(const void *a, const void *b) {
    struct rule *ra = (struct rule *) a;
    struct rule *rb = (struct rule *) b;
    return ra->id - rb->id;
}

uint64_t calc_crc64_rules() {
    uint64_t cksum = 0;
    struct list_head *pos;
    int len, total = 0, i;
    struct rule *rules = NULL;

    /* Calculate how many valid rules*/
    list_for_each(pos, &rule_list) {
        struct rule *rule = list_entry(pos, struct rule, list);
        if (rule->used == 0)
            continue;
        total++;
        rules = zrealloc(rules, total * sizeof(struct rule));
        memcpy(&rules[total - 1], rule, sizeof(struct rule));
    }

    /* Sort rules according to id */
    qsort(rules, total, sizeof(struct rule), rule_cmp);

    /* Calulcate crc */
    for (i = 0; i < total; i++) {
        struct rule *rule = rules + i;
        len = (char *) &rule->protocol - (char *) rule;
        cksum = crc64(cksum, (unsigned char *) rule, len);
        cksum = crc64_2(cksum, rule->disabled);
    }

    zfree(rules);

    return cksum;
}

uint64_t calc_totalhits() {
    struct list_head *pos;
    uint64_t total_hits = 0;

    list_for_each(pos, &rule_list) {
        struct rule *rule = list_entry(pos, struct rule, list);
        if (rule->used == 0)
            continue;
        total_hits += rule->hits;
    }
    return total_hits;
}

void calc_rules(uint64_t *total, uint64_t *enabled) {
    struct list_head *pos;
    uint64_t n1 = 0, n2 = 0;

    list_for_each(pos, &rule_list) {
        struct rule *rule = list_entry(pos, struct rule, list);
        if (rule->used == 0)
            continue;
        if (rule->disabled == 0)
            n2++;
        n1++;
    }
    *total = n1;
    *enabled = n2;
}
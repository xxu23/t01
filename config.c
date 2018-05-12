/*
 * Copyright (c) 2016-18, YAO Wei <njustyw at gmail dot com>
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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "cJSON.h"

#include "t01.h"
#include "util.h"
#include "logger.h"
#include "zmalloc.h"
#include "config.h"

#define copy_string_from_json(item, json, key, value)   \
    item = cJSON_GetObjectItem(json, key);              \
    if(item){                                           \
        value = zstrdup(item->valuestring);             \
    }

#define get_string_from_json(item, json, key, value)    \
    item = cJSON_GetObjectItem(json, key);              \
    if(item){                                           \
        strncpy(value, item->valuestring, sizeof(value)-1); \
    }

#define get_int_from_json(item, json, key, value)       \
    item = cJSON_GetObjectItem(json, key);              \
    if(item){                                           \
        value = item->valueint;                         \
    }

void load_config(const char *filename) {
    FILE *fp;
    long size;
    char *data;
    cJSON *json, *item;
    char wm[64], sm[64] = {0}, ethm[64];

    /* Read content from file */
    fp = fopen(filename, "r");
    if (fp == NULL) {
        t01_log(T01_WARNING,
                "Cannot read config %s: %s, aborting now", filename, strerror(errno));
        exit(1);
    }
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    data = (char *) zmalloc(size + 1);
    if (!data) {
        t01_log(T01_WARNING, "Out of memory!");
        exit(1);
    }
    fread(data, 1, size, fp);
    data[size] = '\0';
    fclose(fp);

    json = cJSON_Parse(data);
    if (!json) {
        t01_log(T01_WARNING, "Cannot parse json: %s", cJSON_GetErrorPtr());
        exit(1);
    }
    zfree(data);

    get_string_from_json(item, json, "ifname", tconfig.ifname);
    get_string_from_json(item, json, "ofname", tconfig.ofname);
    get_string_from_json(item, json, "mfname", tconfig.mfname);
    get_string_from_json(item, json, "ruledb", tconfig.ruledb);
    get_string_from_json(item, json, "logfile", tconfig.logfile);
    get_string_from_json(item, json, "filter", tconfig.filter);
    get_string_from_json(item, json, "engine", tconfig.engine);
    get_string_from_json(item, json, "mirror_engine", tconfig.mirror_engine_opt);
    get_int_from_json(item, json, "engine_reconnect", tconfig.engine_reconnect);
    get_int_from_json(item, json, "engine_threads", tconfig.engine_threads);
    get_int_from_json(item, json, "restart_if_crash", tconfig.restart_if_crash);
    get_int_from_json(item, json, "daemon", tconfig.daemon_mode);
    get_string_from_json(item, json, "master_ip", tconfig.master_ip);
    get_int_from_json(item, json, "master_port", tconfig.master_port);
    get_string_from_json(item, json, "rule_ip", tconfig.rule_ip);
    get_int_from_json(item, json, "rule_port", tconfig.rule_port);
    get_string_from_json(item, json, "hit_ip", tconfig.hit_ip);
    get_int_from_json(item, json, "hit_port", tconfig.hit_port);
    get_string_from_json(item, json, "remote_ip", tconfig.remote_ip);
    get_int_from_json(item, json, "remote_port", tconfig.remote_port);
    get_int_from_json(item, json, "verbose", tconfig.verbose);
    get_int_from_json(item, json, "id", tconfig.id);
    get_int_from_json(item, json, "cpu_thread", tconfig.cpu_thread);
    get_string_from_json(item, json, "work_mode", wm);
    get_string_from_json(item, json, "eth_mode", ethm);
    get_string_from_json(item, json, "send_mode", sm);
    get_string_from_json(item, json, "this_mac", tconfig.this_mac_addr);
    get_string_from_json(item, json, "next_mac", tconfig.next_mac_addr);
    get_string_from_json(item, json, "detected_protocol", tconfig.detected_protocol);
    copy_string_from_json(item, json, "bpf", tconfig.bpf);

    if (strcasecmp(wm, "slave") == 0)
        tconfig.work_mode = SLAVE_MODE;
    else if (strcasecmp(wm, "attack") == 0)
        tconfig.work_mode = ATTACK_MODE;
    else if (strcasecmp(wm, "mirror") == 0)
        tconfig.work_mode = MIRROR_MODE;
    else if (strcasecmp(wm, "master") == 0)
        tconfig.work_mode = MASTER_MODE;
    else
        tconfig.work_mode = SLAVE_MODE;

    if (strcasecmp(ethm, "netmap") == 0)
        tconfig.eth_mode = NETMAP_MODE;
    else if (strcasecmp(ethm, "libpcap") == 0)
        tconfig.eth_mode = LIBPCAP_MODE;
    else if (strcasecmp(ethm, "pfring") == 0)
        tconfig.eth_mode = PFRING_MODE;
    else
        tconfig.eth_mode = LIBPCAP_MODE;

    if (sm[0] == 0 || strcasecmp(sm, "netmap") == 0)
        tconfig.raw_socket = 0;
    else if (strcasecmp(sm, "socket") == 0)
        tconfig.raw_socket = 1;
    cJSON_Delete(json);
}


static void usage() {
    const char *cmd = "t01";
    fprintf(stderr,
            "Usage: %s [options]\n"
                    "\nOptions:\n"
                    "\t-c filename               configuration file\n"
                    "\t-i interface              interface that captures incoming traffic\n"
                    "\t-o interface              interface that sends outcoming traffic (default same as incoming interface)\n"
                    "\t-r ruledb                 rule db file that saving rule and hit record\n"
                    "\t-b ip                     ip address binded for rule management\n"
                    "\t-p port                   port listening for rule management (default 9899)\n"
                    "\t-C cpu_thread             which core do you want to bind to receiveing thread\n"
                    "\t-S | -M                   slave or master mode for rule management\n"
                    "\t-d                        run in daemon mode or not\n"
                    "\t-j ip:port                master address for rule management cluster (eg 192.168.1.2:9898)\n"
                    "\t-H ip:port                udp server address for rule hits\n"
                    "\t-F filter                 filter strategy for mirroring netflow (eg 80/tcp,53/udp)\n"
                    "\t-e engine                 backend/mirror engine to store network flow data\n"
                    "\t-m mirror_eigine          arguments attached to mirror engine\n"
                    "\t-B backup_eigine          arguments attached to backup engine\n"
                    "\t-v verbosity              logger levels (0:debug, 1:verbose, 2:notice, 3:warning)\n"
                    "\t-l log_file               logger into file or screen\n"
                    "", cmd);

    exit(0);
}

static int mac_str_to_n(const char *addr, unsigned char mac0[6]) {
    unsigned int mac[6];
    int i;
    if (sscanf(addr, "%2x:%2x:%2x:%2x:%2x:%2x",
               mac, mac + 1, mac + 2, mac + 3, mac + 4, mac + 5) != 6)
        return -1;

    for (i = 0; i < 6; i++)
        mac0[i] = mac[i];
    return 0;
}

void parse_options(int argc, char **argv) {
    int opt;
    char master_address[64] = {0};
    char hit_address[64] = {0};
    char config_file[256];

    while ((opt = getopt(argc, argv,
                         "SMdhc:i:o:r:e:b:p:C:m:v:l:F:j:H:")) != EOF) {
        switch (opt) {
            case 'S':
                tconfig.work_mode |= SLAVE_MODE;
                break;

            case 'M':
                tconfig.work_mode |= MASTER_MODE;
                break;

            case 'd':
                tconfig.daemon_mode = 1;
                break;

            case 'i':
                strncpy(tconfig.ifname, optarg, sizeof(tconfig.ifname));
                break;

            case 'o':
                strncpy(tconfig.ofname, optarg, sizeof(tconfig.ofname));
                break;

            case 'j':
                strncpy(master_address, optarg, sizeof(master_address));
                break;

            case 'H':
                strncpy(hit_address, optarg, sizeof(hit_address));
                break;

            case 'p':
                tconfig.rule_port = atoi(optarg);
                break;

            case 'C':
                tconfig.cpu_thread = atoi(optarg);
                break;

            case 'b':
                strncpy(tconfig.rule_ip, optarg,
                        sizeof(tconfig.rule_ip));
                break;

            case 'r':
                strncpy(tconfig.ruledb, optarg, sizeof(tconfig.ruledb));
                break;

            case 'c':
                strncpy(config_file, optarg, sizeof(config_file));
                break;

            case 'v':
                tconfig.verbose = atoi(optarg);
                break;

            case 'l':
                strncpy(tconfig.logfile, optarg,
                        sizeof(tconfig.logfile));
                break;

            case 'F':
                strncpy(tconfig.filter, optarg, sizeof(tconfig.filter));
                break;

            case 'e':
                strcpy(tconfig.engine, optarg);
                break;

            case 'm':
                strcpy(tconfig.mirror_engine_opt, optarg);
                break;

            case 'h':
                usage();
                break;

            default:
                usage();
                break;
        }
    }

    int core = get_cpu_cores();

    if (config_file[0])
        load_config(config_file);

    if (tconfig.cpu_thread > 0) {
        if (tconfig.cpu_thread > core)
            tconfig.cpu_thread = 1;
    }

    if (tconfig.engine_threads == 0)
        tconfig.engine_threads = 1;

    // check parameters
    if (master_address[0]) {
        parseipandport(master_address, tconfig.master_ip,
                       sizeof(tconfig.master_ip), &tconfig.master_port);
    }
    if (hit_address[0]) {
        parseipandport(hit_address, tconfig.hit_ip,
                       sizeof(tconfig.hit_ip), &tconfig.hit_port);
    }
    if (tconfig.this_mac_addr[0]) {
        char *addr = tconfig.this_mac_addr;
        if (mac_str_to_n(addr, tconfig.this_mac) != 0) {
            fprintf(stderr, "%s is not a valid mac address\n", addr);
            exit(-1);
        }
    }
    if (tconfig.next_mac_addr[0]) {
        char *addr = tconfig.next_mac_addr;
        if (mac_str_to_n(addr, tconfig.next_mac) != 0) {
            fprintf(stderr, "%s is not a valid mac address\n", addr);
            exit(-1);
        }
    }
    if (tconfig.work_mode & SLAVE_MODE && tconfig.work_mode & MASTER_MODE) {
        fprintf(stderr, "Both master and slave mode is not support\n");
        usage();
    }
    if ((tconfig.work_mode & SLAVE_MODE || tconfig.work_mode & MASTER_MODE)
        && tconfig.master_ip[0] == 0) {
        fprintf(stderr,
                "Master address should be specified in master/slave mode\n");
        usage();
    }

    if (tconfig.work_mode & SLAVE_MODE && tconfig.ifname[0] == 0
        && tconfig.ruledb[0] == 0) {
        fprintf(stderr,
                "Incoming interface should be specified in slave mode\n");
        usage();
    }
    if (tconfig.ruledb[0] == 0)
        strcpy(tconfig.ruledb, DEFAULT_RULEDB);
    if (tconfig.rule_port == 0)
        tconfig.rule_port = DEFAULT_RULE_PORT;

    if (tconfig.remote_ip[0] != 0 && tconfig.remote_port != 0) {
        tconfig.raw_socket = 2;
    }

    tconfig.max_clients = CONFIG_DEFAULT_MAX_CLIENTS;

    {
        argv_ = malloc(sizeof(char *) * (argc + 1));
        argv_[argc] = NULL;
        while (argc > 0) {
            argv_[argc - 1] = strdup(argv[argc - 1]);
            argc--;
        }
    }
}
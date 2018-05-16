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
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <assert.h>

#include "ioengine.h"
#include "ndpi_api.h"
#include "zmalloc.h"
#include "logger.h"
#include "util.h"

static ZLIST_HEAD(engine_list);

static const int MAX_FLUSH_ITEM = 1000;

void unregister_ioengine(struct ioengine_ops *ops) {
    t01_log(T01_DEBUG, "ioengine %s unregistered", ops->name);
    list_del(&ops->list);
}

void register_ioengine(struct ioengine_ops *ops) {
    t01_log(T01_DEBUG, "ioengine %s registered", ops->name);
    list_add_tail(&ops->list, &engine_list);
}

void close_ioengine(struct ioengine_data *td) {
    t01_log(T01_DEBUG, "close ioengine %s", td->io_ops->name);
    if (td->io_ops->disconnect) {
        td->io_ops->disconnect(td);
        td->private_data = NULL;
        zfree(td->total_param);
        zfree(td->host);
        td->total_param = NULL;
        td->host = NULL;
        td->flag = 0;
    }
}

static uint64_t t01_clock() {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec * 1000LLU + tv.tv_usec / 1000;
}

int init_ioengine(struct ioengine_data *td, const char *args) {
    t01_log(T01_NOTICE, "init ioengine %s with opt %s", td->io_ops->name,
            args);

    td->total_param = zstrdup(args);
    td->io_ops->init(td, args);
    td->stat_ts = td->ts = t01_clock();

    if (td->io_ops->connect) {
        int ret = td->io_ops->connect(td);
        td->flag = ret == 0;
        return ret;
    }
    return -1;
}

int check_ioengine(struct ioengine_data *td) {
    int (*ping)(struct ioengine_data *) = td->io_ops->ping;
    int flag = td->flag;

    if (flag == 0 || (ping && ping(td) != 0)) {
        if (flag && td->io_ops->disconnect)
            td->io_ops->disconnect(td);

        if (td->io_ops->connect) {
            int ret = td->io_ops->connect(td);
            td->flag = ret == 0;
            return ret;
        }
    }
    return 0;
}

typedef int (*write_engine)(struct ioengine_data *, const char *, int, uint32_t, int);

int store_raw_via_ioengine(struct ioengine_data *td, const char *data,
                           int len, uint32_t hash_idx, uint8_t protocol, uint64_t ts) {
    write_engine write = td->io_ops->write;
    int ret;
    int flush = 0;
    uint64_t now = t01_clock();
    if (++td->count >= MAX_FLUSH_ITEM || now - td->ts >= 200) {
        flush = td->count;
        td->count = 0;
        td->ts = now;
    }
    td->stat_count++;
    td->stat_bytes += len;

    if (!write || td->flag == 0)
        return -1;
    ret = write(td, data, len, hash_idx, flush);
    td->flag = ret > 0;
    int interval = now - td->stat_ts;
    if (interval >= 5000) {
        char buf1[64], buf2[64];
        t01_log(T01_NOTICE, "ioengine producing %s pps/s, %s/s",
                format_packets(td->stat_count*1000.0f/interval, buf1),
                format_traffic((float)td->stat_bytes*8000.0f/interval, 1, buf2));
        td->stat_count = 0;
        td->stat_bytes = 0;
        td->stat_ts = now;
    }
    return ret;
}

static struct ioengine_ops *find_ioengine(const char *name) {
    struct ioengine_ops *ops;
    struct list_head *entry;

    list_for_each(entry, &engine_list) {
        ops = list_entry(entry, struct ioengine_ops, list);
        if (!strcmp(name, ops->name))
            return ops;
    }

    return NULL;
}

int load_ioengine(struct ioengine_data *data, const char *name) {
    struct ioengine_ops *ops;
    char engine[64];

    t01_log(T01_NOTICE, "load ioengine %s into %p", name, data);

    engine[sizeof(engine) - 1] = '\0';
    strncpy(engine, name, sizeof(engine) - 1);

    ops = find_ioengine(engine);
    if (!ops) {
        t01_log(T01_WARNING, "engine %s not loadable", name);
        return -1;
    }

    data->io_ops = ops;
    return 0;
}

int fio_show_ioengine_help(const char *engine) {
    struct list_head *entry;
    struct ioengine_ops *io_ops;
    struct ioengine_data id;
    int ret = 1;

    if (!engine || !*engine) {
        printf("Available IO engines:\n");
        list_for_each(entry, &engine_list) {
            io_ops = list_entry(entry, struct ioengine_ops, list);
            printf("\t%s\n", io_ops->name);
        }
        return 0;
    }

    if (load_ioengine(&id, engine) < 0) {
        printf("IO engine %s not found\n", engine);
        return 1;
    } else {
        io_ops = id.io_ops;
    }

    if (io_ops->show_help)
        ret = io_ops->show_help();
    else
        printf("IO engine %s has no options\n", io_ops->name);

    return ret;
}

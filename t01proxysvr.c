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
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <sys/poll.h>

#include "logger.h"
#include "zmalloc.h"
#include "util.h"
#include "anet.h"
#include "ioengine.h"
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

#pragma pack(1)
struct proxy_header {
    char magic[8];
    uint32_t id;
    int self_len;
    int data_len;
};
#pragma pack()

#define MAGIC "\x7aT\x85@\xaf$\xd0$"
#define HEADER_LEN sizeof(struct proxy_header)

struct my_param {
    int step;
    struct proxy_header hdr;
    int hdr_offset;
    int data_len;
    int offset;
    char buf[1600];
    int count;
};

static int shutdown_app = 0;
static int port = 9777;
static char *logfile;
static char *engine;
static char *engine_opt;
static int daemon_mode = 0;
static struct ioengine_data mirror_engine;
static time_t last = 0;


static void usage() {
    const char *cmd = "t01proxysvr";
    fprintf(stderr,
            "Usage: %s [options]\n"
                    "\nOptions:\n"
                    "\t-d                  Run daemon or not\n"
                    "\t-p port             Port number listening for proxy client\n"
                    "\t-e engine           I/O engine for storing data\n"
                    "\t-o opt              Engine connection options\n"
                    "\t                    redis option: 127.0.0.1:6379:myqueue\n"
                    "\t                    kafka option: 127.0.0.1:6667;mytopic\n"
                    "\t-l log_file         Logger into file or screen\n"
                    "\n", cmd);

    exit(0);
}

static void parse_options(int argc, char **argv) {
    int opt;

    while ((opt = getopt(argc, argv, "hdp:e:o:l:")) != EOF) {
        switch (opt) {
            case 'd':
                daemon_mode = 1;
                break;

            case 'p':
                port = atoi(optarg);
                break;

            case 'e':
                engine = optarg;
                break;

            case 'o':
                engine_opt = optarg;
                break;

            case 'l':
                strncpy(logfile, optarg, sizeof(logfile));
                break;

            case 'h':
                usage();
                break;

            default:
                usage();
                break;
        }
    }

    if (!engine || !engine_opt) {
        fprintf(stderr, "Engine options should be specified\n");
        exit(1);
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

static void signal_cb(evutil_socket_t sig, short events, void *user_data) {
    struct event_base *base = user_data;
    struct timeval delay = {2, 0};

    shutdown_app = 1;
    t01_log(T01_WARNING, "Caught an interrupt signal, exiting later");

    event_base_loopexit(base, &delay);
}

static void server_on_error(struct bufferevent *bev, short events, void *arg) {
    struct my_param *param = (struct my_param *) arg;
    if (events & BEV_EVENT_EOF) {
        t01_log(T01_WARNING, "Connection closed");
    } else if (events & BEV_EVENT_ERROR) {
        t01_log(T01_WARNING, "Got an error on the connection: %s",
                strerror(errno));
    }
    bufferevent_free(bev);
    zfree(param);
}

static write_ioengine(const char *data, int len) {
    if (store_raw_via_ioengine(&mirror_engine, data, len, 0, 0, 0) < 0) {
        time_t now = time(NULL);
        if (now - last >= 5) {
            t01_log(T01_WARNING,
                    "failed to write mirror ioengine, reconnect every 5 seconds");
            check_ioengine(&mirror_engine);
            last = now;
        }
    }
}


static void server_on_read(struct bufferevent *bev, void *arg) {
    struct evbuffer *input = bufferevent_get_input(bev);
    struct my_param *param = (struct my_param *) arg;
    size_t read_len;
    size_t len = evbuffer_get_length(input);

    while (len > 0) {
        if (param->step == 0) {
            struct proxy_header *hdr = &param->hdr;
            int offset = param->hdr_offset;
            read_len = evbuffer_remove(input, (char *) hdr + offset, HEADER_LEN - offset);
            len -= read_len;
            param->hdr_offset += read_len;
            if (param->hdr_offset != HEADER_LEN) {
                continue;
            }

            if (memcmp(hdr->magic, MAGIC, 8) != 0 || hdr->self_len != HEADER_LEN
                || hdr->data_len >= 1600) {
                t01_log(T01_WARNING, "Received an illegal header %8s, selflen %d, "
                        "datalen %d, drop it!!!", hdr->magic, hdr->self_len, hdr->data_len);
                bufferevent_free(bev);
                param->hdr_offset = 0;
                zfree(param);
                return;
            }
            param->step = 1;
            param->data_len = hdr->data_len;
            param->offset = 0;
            param->count += 1;
            param->hdr_offset = 0;
        } else {
            int remain_len = param->data_len - param->offset;
            read_len = evbuffer_remove(input, param->buf + param->offset, remain_len);
            len -= read_len;
            param->offset += read_len;
            if (param->offset == param->data_len) {
                write_ioengine(param->buf, param->data_len);
                param->step = 0;
                param->offset = 0;
                param->buf[0] = 0;
                param->hdr_offset = 0;
            }
        }
    }
}

void server_on_accept(struct evconnlistener *listener, evutil_socket_t fd,
                      struct sockaddr *address, int socklen, void *arg) {
    struct sockaddr_in *in = (struct sockaddr_in *) address;
    char ip[16];
    evutil_inet_ntop(address->sa_family, &in->sin_addr, ip, sizeof(ip));

    t01_log(T01_NOTICE, "Incoming a new proxy client %s:%d [fd=%d]",
            ip, ntohs(in->sin_port), fd);
    //evutil_make_socket_nonblocking(fd);

    struct my_param *param = zmalloc(sizeof(*param));
    struct event_base *base = evconnlistener_get_base(listener);
    struct bufferevent *new_buff_event = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

    bzero(param, sizeof(*param));
    bufferevent_setcb(new_buff_event, server_on_read, NULL, server_on_error, param);
    bufferevent_enable(new_buff_event, EV_READ | EV_WRITE);
}

static int core_main() {
    struct event_base *base;
    struct evconnlistener *listener;
    struct event *signal_event;
    struct sockaddr_in sin;

    if (daemon_mode) {
        daemonize();
    }

    init_log(T01_NOTICE, logfile);

    if (load_ioengine(&mirror_engine, engine) < 0) {
        t01_log(T01_WARNING, "Unable to load mirror engine %s", engine);
        return -1;
    }
    if (init_ioengine(&mirror_engine, engine_opt) < 0) {
        t01_log(T01_WARNING, "Unable to init mirror engine %s", engine);
        return -1;
    }
    last = time(NULL);

    base = event_base_new();
    if (!base) {
        t01_log(T01_WARNING, "Could not initialize libevent!");
        return -1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);

    listener = evconnlistener_new_bind(base, server_on_accept, (void *) base,
                                       LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_FREE, -1,
                                       (struct sockaddr *) &sin,
                                       sizeof(sin));

    if (!listener) {
        t01_log(T01_WARNING, "Could not create a listener!");
        return -1;
    }

    signal_event = evsignal_new(base, SIGINT, signal_cb, (void *) base);
    if (!signal_event || event_add(signal_event, NULL) < 0) {
        t01_log(T01_WARNING, "Could not create/add a signal event!");
        return -1;
    }

    int t = event_base_dispatch(base);

    evconnlistener_free(listener);
    event_free(signal_event);
    event_base_free(base);

    return t;
}


int main(int argc, char *argv[]) {

    parse_options(argc, argv);

    return core_main();
}
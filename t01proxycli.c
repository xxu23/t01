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

#include "pcap.h"
#include "logger.h"
#include "zmalloc.h"
#include "util.h"
#include "anet.h"
#include "libhl/rqueue.h"

#pragma pack(1)
struct proxy_header {
    char magic[8];
    uint32_t id;
    int self_len;
    int data_len;
};
#pragma pack()

#define MAGIC "\x7aT\x85@\xaf$\xd0$"

#define INIT_HEADER(len) \
    {MAGIC, ++id, sizeof(struct proxy_header), len};

static int live_capture = 0;
static int shutdown_app = 0;
static int qsize = 65536;
static char* iface;
static char* bpfFilter;
static char* logfile;
static char* remote_ip;
static int remote_port = 9777;
static int daemon_mode = 0;
static int sendfd;
static pcap_t* pcap_handle;
static pthread_t threads[2];
static rqueue_t* myqueue;
static time_t upstart;
static int id = 0;


static void usage() {
    const char *cmd = "t01proxycli";
    fprintf(stderr,
            "Usage: %s [options]\n"
                    "\nOptions:\n"
                    "\t-d                  Run daemon or not\n"
                    "\t-i device           Device/pcapfile for reading packet\n"
                    "\t-b bpf              BPF filter as tcpdump (eg tcp port 80) \n"
                    "\t-H host             Proxy server address to reveive packet\n"
                    "\t-P port             Proxy server to reveive packet\n"
                    "\t-n size             Queue size for caching pkt (default 65536)\n"
                    "\t-l log_file         Logger into file or screen\n"
                    "\n", cmd);

    exit(0);
}

static void parse_options(int argc, char **argv) {
    int opt;

    while ((opt = getopt(argc, argv, "hdn:i:l:b:H:P:")) != EOF) {
        switch (opt) {
            case 'd':
                daemon_mode = 1;
                break;

            case 'n':
                qsize = atoi(optarg);
                break;

            case 'i':
                iface = optarg;
                break;

            case 'l':
                logfile = optarg;
                break;

            case 'b':
                bpfFilter = optarg;
                break;

            case 'H':
                remote_ip = optarg;
                break;

            case 'P':
                remote_port = atoi(optarg);
                break;

            case 'h':
                usage();
                break;

            default:
                usage();
                break;
        }
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

static pcap_t* open_device_or_file(const char *pcap_file) {
    u_int snaplen = 1536;
    int promisc = 1;
    char pcap_error[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_handle = NULL;

    if((pcap_handle = pcap_open_live((char*)pcap_file, snaplen, promisc,
                                     500, pcap_error)) == NULL) {
        t01_log(T01_WARNING, "Could not open device %s: %s, try to read it as pcap file",
                pcap_file, pcap_error);
        live_capture = 0;
        /* trying to open a pcap file */
        if((pcap_handle = pcap_open_offline((char*)pcap_file, pcap_error)) == NULL) {
            t01_log(T01_WARNING, "Could not open pcap file %s: %s", pcap_file, pcap_error);
            exit(-1);
        } else {
            t01_log(T01_NOTICE, "Reading packets from pcap file %s...", pcap_file);
        }

    } else {
        live_capture = 1;
        t01_log(T01_NOTICE, "Capturing live traffic from device %s...", pcap_file);
    }

    if(bpfFilter != NULL) {
        struct bpf_program fcode;

        if(pcap_compile(pcap_handle, &fcode, bpfFilter, 1, 0xFFFFFF00) < 0) {
            t01_log(T01_WARNING, "pcap_compile error: '%s'", pcap_geterr(pcap_handle));
        } else {
            if(pcap_setfilter(pcap_handle, &fcode) < 0) {
                t01_log(T01_NOTICE, "pcap_setfilter error: '%s'", pcap_geterr(pcap_handle));
            } else
                t01_log(T01_NOTICE, "Successfully set BPF filter to '%s'", bpfFilter);
        }
    }

    return pcap_handle;
}

static void signal_hander(int sig) {
    t01_log(T01_WARNING, "Received control-C, shutdowning");
    shutdown_app = 1;
    pcap_breakloop(pcap_handle);
}

static void init_system() {

    if (iface == NULL) {
        fprintf(stderr, "Device or Pcapfile must be specified\n");
        exit(1);
    } else if (remote_ip == NULL) {
        fprintf(stderr, "Proxy server must be specified\n");
        exit(1);
    }

    if (daemon_mode) {
        daemonize();
    }
    init_log(T01_NOTICE, logfile);

    myqueue = rqueue_create(qsize, RQUEUE_MODE_OVERWRITE);
    if (!myqueue) {
        t01_log(T01_WARNING, "failed to initialize queue with size %d", qsize);
        exit(1);
    }

    pcap_handle = open_device_or_file(iface);

    signal(SIGINT, signal_hander);
    signal(SIGTERM, signal_hander);

    upstart = time(NULL);
}

static void pcap_process_packet(u_char *args,
                                const struct pcap_pkthdr *header,
                                const u_char *packet) {
    void *data = zmalloc(header->caplen + 4);
    if (!data) {
        return;
    }

    memcpy(data, &header->caplen, sizeof(header->caplen));
    memcpy(data+4, packet, header->caplen);
    rqueue_write(myqueue, data);
}

static void *reader_thread(void *args) {
    t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);

    pcap_loop(pcap_handle, -1, &pcap_process_packet, NULL);

    t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
    shutdown_app = 2;

    return NULL;
}

static void send_packet(void *data, int len) {
    struct pollfd pfds[1];
    pfds[0].fd = sendfd;
    pfds[0].events = POLLIN | POLLOUT;
    poll(pfds, 1, 0);
    if (pfds[0].revents & POLLIN) {
        char buffer[1024];
        int n = read(sendfd, buffer, 1024);
        if (n == 0) {
            t01_log(T01_WARNING, "Disconnect from proxy server");
            close(sendfd);
            sendfd = -1;
            return;
        }
    } else if (pfds[0].revents & POLLOUT) {
        struct proxy_header header = INIT_HEADER(len);
        int n;
        if ( (n=anetWrite(sendfd, (char*)&header, sizeof(header))) < 0
              || (n=anetWrite(sendfd, (char*)data, len)) < 0) {
            close(sendfd);
            sendfd = -1;
        }
    }
}

static int reconnect_remote() {
    if (sendfd <= 0) {
        char err[500];
        int fd = anetTcpConnect(err, remote_ip, remote_port);
        if (fd < 0) {
            return -1;
        } else {
            t01_log(T01_NOTICE, "Succeed to connect to proxy server %s:%d",
                    remote_ip, remote_port);
            sendfd = fd;
            return 0;
        }
    }

    return 0;
}

static void *proxy_thread(void *args) {
    uint64_t total_pkts = 0;
    uint64_t last_pkts = 0;
    uint64_t total_bytes = 0;
    uint64_t last_bytes = 0;
    time_t t1 = time(NULL), t2 = t1;
    char err[500];

    t01_log(T01_NOTICE, "Enter thread %s", __FUNCTION__);
    while (shutdown_app != 1) {
        void *item = NULL;

        if ((item=rqueue_read(myqueue)) == NULL) {
            if (shutdown_app == 2) {
                break;
            }
            usleep(1);
            continue;
        }
        int len = *((int*)item);
        void *data = item + 4;
        total_bytes += len;
        total_pkts++;

        if (sendfd <= 0 && reconnect_remote() < 0) {
            zfree(item);
            usleep(100);
        } else {
            send_packet(data, len);
            zfree(item);
        }

        t2 = time(NULL);
        if(t2 - t1 >= 5) {
            char buf[64], buf1[64];
            time_t t = t2 - t1;
            uint64_t pkt = (total_pkts - last_pkts) / t;
            uint64_t bytes = (total_bytes - last_bytes) / t;
            last_bytes = total_bytes;
            last_pkts = total_pkts;
            t1 = t2;
            t01_log(T01_NOTICE, "Traffic throughput: %s pps / %s/sec",
                    format_packets(pkt, buf), format_traffic(bytes, 0, buf1));
        }
    }

    t01_log(T01_NOTICE, "Leave thread %s", __FUNCTION__);
    return NULL;
}

static void core_main() {
    if (pthread_create(&threads[0], NULL, reader_thread, NULL) != 0) {
        t01_log(T01_WARNING, "Can't create reader thread: %s",
                strerror(errno));
        exit(1);
    }

    if (pthread_create(&threads[1], NULL, proxy_thread, NULL) != 0) {
        t01_log(T01_WARNING, "Can't create proxy thread: %s",
                strerror(errno));
        exit(1);
    }

    for (int i = 0; i < 2; i++) {
        pthread_join(threads[i], NULL);
    }

    t01_log(T01_NOTICE, "See you next time :-)");
}

int main(int argc, char *argv[]) {

    parse_options(argc, argv);
    init_system();
    core_main();

    return 0;
}
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
#include <errno.h>
#include <inttypes.h>
#include "ae.h"
#include "anet.h"
#include "networking.h"
#include "rule.h"
#include "zmalloc.h"
#include "logger.h"

/* With multiplexing we need to take per-client state.
 * Clients are taken in a linked list. */
typedef struct t01Client {
    uint64_t id;            /* Client incremental unique ID. */
    int fd;
    time_t ctime;           /* Client creation time */
    char request[1024*16];
    char reply[1024*16];
    uint8_t command; 
    int req_len;
    uint8_t response;
    int resp_len;
    aeEventLoop *el;
} t01Client;

t01Client *createClient(aeEventLoop *el, int fd) {
    static int client_id = 0;
    t01Client *c = malloc(sizeof(t01Client));

    if (fd != -1) {
        //anetNonBlock(NULL,fd);
        anetEnableTcpNoDelay(NULL,fd);
        if (aeCreateFileEvent(el,fd,AE_READABLE, readQueryFromClient, c) == AE_ERR)
        {
            close(fd);
            free(c);
            return NULL;
        }
    }

    c->id = client_id++;
    c->fd = fd;
    c->ctime = time(NULL);
    c->el = el;
    return c;
}

#define MAX_ACCEPTS_PER_CALL 1000
static void acceptCommonHandler(aeEventLoop *el, int fd) {
    t01Client *c;
    if ((c = createClient(el, fd)) == NULL) {
        t01Log(T01_WARNING,
            "Error registering fd event for the new client: %s (fd=%d)",
            strerror(errno),fd);
        close(fd); /* May be already closed, just ignore errors */
        return;
    }
}

void acceptTcpHandler(aeEventLoop *el, int fd, void *privdata, int mask) {
    int cport, cfd, max = MAX_ACCEPTS_PER_CALL;
    char cip[16];
    char err[ANET_ERR_LEN]; 

    while(max--) {
        cfd = anetTcpAccept(err, fd, cip, sizeof(cip), &cport);
        if (cfd == ANET_ERR) {
            if (errno != EWOULDBLOCK)
                t01Log(T01_WARNING, "Accepting client connection: %s", err);
            return;
        }
        t01Log(T01_NOTICE, "Accepted %s:%d", cip, cport);
        acceptCommonHandler(el, cfd);
    }
}

void acceptUnixHandler(aeEventLoop *el, int fd, void *privdata, int mask) {
    int cfd, max = MAX_ACCEPTS_PER_CALL;
    char err[ANET_ERR_LEN]; 

    while(max--) {
        cfd = anetUnixAccept(err, fd);
        if (cfd == ANET_ERR) {
            if (errno != EWOULDBLOCK)
                t01Log(T01_WARNING, "Accepting client connection: %s", err);
            return;
        }
        t01Log(T01_DEBUG, "Accepted unix socket connection");
        acceptCommonHandler(el, cfd);
    }
}

void freeClient(t01Client *c) {
    if (c->fd != -1 && c->el) {
        aeDeleteFileEvent(c->el, c->fd, AE_READABLE);
        aeDeleteFileEvent(c->el, c->fd, AE_WRITABLE);
        close(c->fd);
     }
    c->el = NULL;
    c->fd = -1;
    free(c);
}

void sendReplyToClient(aeEventLoop *el, int fd, void *privdata, int mask) {
    t01Client *c = (t01Client *)privdata;
    int nwritten = 0, totwritten = 0, objlen;
    struct t01_header header = INIT_T01_HEADER(c->command, c->response);
    header.body_len = c->resp_len;
    
    nwritten = anetWrite(fd, (char *)&header, sizeof(header));
    if (nwritten == -1) {
        if (errno == EAGAIN) {
            nwritten = 0;
        } else {
            t01Log(T01_WARNING, "Error writing header to client: %s", strerror(errno));
            freeClient(c);
            return;
        }
    }

    if(c->resp_len > 0) {
        nwritten = anetWrite(fd, c->reply, c->resp_len);
        if (nwritten == -1) {
            if (errno == EAGAIN) {
                nwritten = 0;
            } else {
                t01Log(T01_WARNING, "Error writing body to client: %s", strerror(errno));
                freeClient(c);
                return;
            }
        }
    }
}

typedef int (*commandAction)(void* in, int len, void* out, int out_len);

static int getRule(void* in, int len, void* out, int out_len) {
    uint32_t id = *(uint32_t*)in;
    int ret = get_rule_by_id(id, out, out_len);
    if(ret < 0){
        snprintf(out, out_len, "rule_id=%u is not found", id);
        return T01_ERR_NOTFOUND;
    }
    return ret;
}

static int getRulesByIds(void* in, int len, void* out, int out_len) {
    uint32_t* ids = (uint32_t*)in;
    len /= sizeof(uint32_t);
    int ret = get_rules_by_ids(ids, len, out, out_len);
    return ret;
}


static int getRuleIds(void* in, int len, void* out, int out_len) {
    int ret = get_rule_ids(out, out_len);
    return ret;
}

static int putRule(void* in, int len, void* out, int out_len) {
    int ret = update_rule(in, len, out, out_len);
    if(ret < 0){
        snprintf(out, out_len, "the rule is not found");
        return T01_ERR_NOTFOUND;
    }
    return ret;
}

static int delRule(void* in, int len, void* out, int out_len) {
    uint32_t id = *(uint32_t*)in;
    int ret = delete_rule_by_id(id, out, out_len);
    if(ret < 0){
        snprintf(out, out_len, "rule_id=%u is not found", id);
        return T01_ERR_NOTFOUND;
    }
    return ret;
}

static int addRule(void* in, int len, void* out, int out_len) {
    int ret = add_rule(in, len, out, out_len);
    if(ret < 0){
        return T01_ERR_INTERNAL;
    }
    
    *((uint32_t*)out) = ret;
    return sizeof(uint32_t);
}

static struct t01Command {
    uint8_t command;
    commandAction action;
}commands[] = {
    { T01_COMMAND_GET_RULE, getRule },
    { T01_COMMAND_PUT_RULE, putRule },
    { T01_COMMAND_DEL_RULE, delRule },
    { T01_COMMAND_ADD_RULE, addRule },
    { T01_COMMAND_GET_RULEIDS, getRuleIds },
    { T01_COMMAND_GET_RULES,  getRulesByIds },
};

static void dispatchCommand(aeEventLoop *el, t01Client *c, int fd) {
    int i;
    struct t01Command* cmd = NULL;

    for(i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        if(commands[i].command == c->command) {
            cmd = &commands[i];
            break;
        }
    }

    if(cmd == NULL) {
        c->response = T01_ERR_NOTSUPPORT;
        strcpy(c->reply, "Not support this command!");
        c->resp_len = strlen(c->reply); 
    } else {
        int ret = cmd->action(c->request, c->req_len, c->reply, sizeof(c->reply));
        if (ret < 0) {
            c->response = ret;
            c->resp_len = strlen(c->reply);
        } else {
            c->response = 0;
            c->resp_len = ret;
        }
    }
}

void readQueryFromClient(aeEventLoop *el, int fd, void *privdata, int mask) {
    t01Client *c = (t01Client*) privdata;
    int nread;
    struct t01_header header;
    
    nread = read(fd, &header, sizeof(header));
    if (nread == -1) {
        if (errno == EAGAIN) {
            nread = 0;
        } else {
            t01Log(T01_WARNING, "Reading header from client: %s",strerror(errno));
            freeClient(c);
            return;
        }
    } else if (nread == 0) {
        t01Log(T01_WARNING, "Client closed connection");
        freeClient(c);
        return;
    }
    if (IS_HEADER_VALID(header)) {
        int datalen = header.body_len;
        c->command = header.command; 
        c->req_len = datalen > 0 ? datalen : 0;
        c->response = c->resp_len = 0;
        if(datalen > 0) {
            nread = anetRead(fd, c->request, datalen);
            if (nread == -1) {
                t01Log(T01_WARNING, "Reading body from client: %s",strerror(errno));
                freeClient(c);
                return;
               }
          }
        dispatchCommand(el, c, fd);
        sendReplyToClient(el, fd, privdata, mask);
    } else {
        t01Log(T01_WARNING, "Invalid client, drop connection");
        freeClient(c);
        return;
    }
}

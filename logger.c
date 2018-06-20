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
#include <inttypes.h>
#include <limits.h>
#include <fcntl.h>
#include <stdarg.h>
#include <time.h>

#include "logger.h"
#include "zmalloc.h"
#include "util.h"

static int verbosity = 1;
static char logfile[256];


/* Low level logging. To use only for very big messages, otherwise
 * t01Log() is to prefer. */
void t01_lograw(int level, const char *msg) {
    const char *c = ".-*#";
    FILE *fp;
    char buf[64];
    int rawmode = (level & T01_LOG_RAW);
    int log_to_stdout = logfile[0] == '\0';

    level &= 0xff; /* clear flags */
    if (level < verbosity) return;

    fp = log_to_stdout ? stdout : fopen(logfile,"a");
    if (!fp) return;

    if (rawmode) {
        fprintf(fp,"%s",msg);
    } else {
        int off;
        struct timeval tv;

        gettimeofday(&tv,NULL);
        off = strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S.",localtime(&tv.tv_sec));
        snprintf(buf+off,sizeof(buf)-off,"%06d",(int)tv.tv_usec);
        fprintf(fp,"[%d] %s %c %s\n",(int)getpid(),buf,c[level],msg);
    }
    fflush(fp);

    if (!log_to_stdout) fclose(fp);
}

/* Like t01LogRaw() but with printf-alike support. This is the function that
 * is used across the code. The raw version is only used in order to dump
 * the INFO output on crash. */
void t01_log(int level, const char *fmt, ...) {
    va_list ap;
    char msg[1024];

    if ((level&0xff) < verbosity) return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    t01_lograw(level,msg);
}

/* Log a fixed message without printf-alike capabilities, in a way that is
 * safe to call from a signal handler.
 *
 * We actually use this only for signals that are not fatal from the point
 * of view of Redis. Signals that are going to kill the server anyway and
 * where we need printf-alike features are served by t01Log(). */
void t01_log_from_handler(int level, const char *msg) {
    int fd;
    int log_to_stdout = logfile[0] == '\0';
    char buf[64];

    if ((level&0xff) < verbosity)
        return;
    fd = log_to_stdout ? STDOUT_FILENO :
                         open(logfile, O_APPEND|O_CREAT|O_WRONLY, 0644);
    if (fd == -1) return;
    ll2string(buf,sizeof(buf),getpid());
    if (write(fd,"[",1) == -1) goto err;
    if (write(fd,buf,strlen(buf)) == -1) goto err;
    if (write(fd," | signal handler] (",20) == -1) goto err;
    ll2string(buf,sizeof(buf),time(NULL));
    if (write(fd,buf,strlen(buf)) == -1) goto err;
    if (write(fd,") ",2) == -1) goto err;
    if (write(fd,msg,strlen(msg)) == -1) goto err;
    if (write(fd,"\n",1) == -1) goto err;
err:
    if (!log_to_stdout) close(fd);
}

void init_log(int _verbosity, const char *_logfile) {
    verbosity = _verbosity;
    if(_logfile && _logfile[0])
        strncpy(logfile, _logfile, sizeof(logfile));
}

/* =========================== Crash handling  ============================== */

void _t01_assert(char *estr, char *file, int line) {
    t01_log(T01_WARNING,"=== ASSERTION FAILED ===");
    t01_log(T01_WARNING,"==> %s:%d '%s' is not true",file,line,estr);
    *((char*)-1) = 'x';
}

void _t01_panic(char *msg, char *file, int line) {
    t01_log(T01_WARNING,"------------------------------------------------");
    t01_log(T01_WARNING,"!!! Software Failure. Press left mouse button to continue");
    t01_log(T01_WARNING,"Guru Meditation: %s #%s:%d",msg,file,line);
    t01_log(T01_WARNING,"------------------------------------------------");
    *((char*)-1) = 'x';
}


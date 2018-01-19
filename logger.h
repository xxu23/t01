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

/* inclusion guard */
#ifndef __LOGGER_H__
#define __LOGGER_H__

#ifdef __cplusplus
extern "C" {
#endif

/* Log levels */
#define T01_DEBUG 0
#define T01_VERBOSE 1
#define T01_NOTICE 2
#define T01_WARNING 3
#define T01_LOG_RAW (1<<10) /* Modifier to log without timestamp */
#define T01_DEFAULT_VERBOSITY T01_NOTICE

void t01_log(int level, const char *fmt, ...);

void t01_lograw(int level, const char *msg);

void t01_log_from_handler(int level, const char *msg);

void init_log(int verbosity, const char *logfile);

/* Debugging stuff */
void _t01_assert(char *estr, char *file, int line);

void _t01_panic(char *msg, char *file, int line);

#define t01_assert(_e) ((_e)?(void)0 : (_t01_assert(#_e,__FILE__,__LINE__),_exit(1)))
#define t01_panic(_e) _t01_panic(#_e,__FILE__,__LINE__),_exit(1)

#ifdef __cplusplus
}
#endif

#endif /* __LOGGER_H__ */

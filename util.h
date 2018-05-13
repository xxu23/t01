/*
 * Copyright (c) 2009-2012, Salvatore Sanfilippo <antirez at gmail dot com>
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

#ifndef __UTIL_H__
#define __UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

int startswith(const char *src, const char *dst);

int endswith(const char *src, const char* dst);

int stringmatchlen(const char *p, int plen, const char *s, int slen, int nocase);

int stringmatch(const char *p, const char *s, int nocase);

long long memtoll(const char *p, int *err);

int ll2string(char *s, size_t len, long long value);

int string2ll(const char *s, size_t slen, long long *value);

int string2l(const char *s, size_t slen, long *value);

int d2string(char *buf, size_t len, double value);

int pathIsBaseName(char *path);

char *ipproto_name(uint8_t proto_id);

int parseipandport(const char *addr, char *ip, size_t len, uint16_t *port);

int manage_interface_promisc_mode(const char *interface, int on);

int create_l2_raw_socket(const char *if_name);

char *format_traffic(float numBits, int bits, char *buf);

char *format_packets(float numPkts, char *buf);

char *etheraddr_string(const unsigned char *ep, char *buf);

int get_interface_mac(const char* device, unsigned char mac[6]);

int ethtool_get_interface_speed(const char *device);

int get_cpu_cores();

uint64_t get_total_ram();

#ifdef __cplusplus
}
#endif

#endif
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <unistd.h>
#include <sys/time.h>
#include <float.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <linux/sockios.h>
#include <sys/sysinfo.h>
#include <errno.h>

#include "util.h"
#include "zmalloc.h"
#include "logger.h"

/* Glob-style pattern matching. */
int stringmatchlen(const char *pattern, int patternLen,
        const char *string, int stringLen, int nocase)
{
    while(patternLen) {
        switch(pattern[0]) {
        case '*':
            while (pattern[1] == '*') {
                pattern++;
                patternLen--;
            }
            if (patternLen == 1)
                return 1; /* match */
            while(stringLen) {
                if (stringmatchlen(pattern+1, patternLen-1,
                            string, stringLen, nocase))
                    return 1; /* match */
                string++;
                stringLen--;
            }
            return 0; /* no match */
            break;
        case '?':
            if (stringLen == 0)
                return 0; /* no match */
            string++;
            stringLen--;
            break;
        case '[':
        {
            int not, match;

            pattern++;
            patternLen--;
            not = pattern[0] == '^';
            if (not) {
                pattern++;
                patternLen--;
            }
            match = 0;
            while(1) {
                if (pattern[0] == '\\') {
                    pattern++;
                    patternLen--;
                    if (pattern[0] == string[0])
                        match = 1;
                } else if (pattern[0] == ']') {
                    break;
                } else if (patternLen == 0) {
                    pattern--;
                    patternLen++;
                    break;
                } else if (pattern[1] == '-' && patternLen >= 3) {
                    int start = pattern[0];
                    int end = pattern[2];
                    int c = string[0];
                    if (start > end) {
                        int t = start;
                        start = end;
                        end = t;
                    }
                    if (nocase) {
                        start = tolower(start);
                        end = tolower(end);
                        c = tolower(c);
                    }
                    pattern += 2;
                    patternLen -= 2;
                    if (c >= start && c <= end)
                        match = 1;
                } else {
                    if (!nocase) {
                        if (pattern[0] == string[0])
                            match = 1;
                    } else {
                        if (tolower((int)pattern[0]) == tolower((int)string[0]))
                            match = 1;
                    }
                }
                pattern++;
                patternLen--;
            }
            if (not)
                match = !match;
            if (!match)
                return 0; /* no match */
            string++;
            stringLen--;
            break;
        }
        case '\\':
            if (patternLen >= 2) {
                pattern++;
                patternLen--;
            }
            /* fall through */
        default:
            if (!nocase) {
                if (pattern[0] != string[0])
                    return 0; /* no match */
            } else {
                if (tolower((int)pattern[0]) != tolower((int)string[0]))
                    return 0; /* no match */
            }
            string++;
            stringLen--;
            break;
        }
        pattern++;
        patternLen--;
        if (stringLen == 0) {
            while(*pattern == '*') {
                pattern++;
                patternLen--;
            }
            break;
        }
    }
    if (patternLen == 0 && stringLen == 0)
        return 1;
    return 0;
}

int stringmatch(const char *pattern, const char *string, int nocase) {
    return stringmatchlen(pattern,strlen(pattern),string,strlen(string),nocase);
}

/* Convert a string representing an amount of memory into the number of
 * bytes, so for instance memtoll("1Gi") will return 1073741824 that is
 * (1024*1024*1024).
 *
 * On parsing error, if *err is not NULL, it's set to 1, otherwise it's
 * set to 0 */
long long memtoll(const char *p, int *err) {
    const char *u;
    char buf[128];
    long mul; /* unit multiplier */
    long long val;
    unsigned int digits;

    if (err) *err = 0;
    /* Search the first non digit character. */
    u = p;
    if (*u == '-') u++;
    while(*u && isdigit(*u)) u++;
    if (*u == '\0' || !strcasecmp(u,"b")) {
        mul = 1;
    } else if (!strcasecmp(u,"k")) {
        mul = 1000;
    } else if (!strcasecmp(u,"kb")) {
        mul = 1024;
    } else if (!strcasecmp(u,"m")) {
        mul = 1000*1000;
    } else if (!strcasecmp(u,"mb")) {
        mul = 1024*1024;
    } else if (!strcasecmp(u,"g")) {
        mul = 1000L*1000*1000;
    } else if (!strcasecmp(u,"gb")) {
        mul = 1024L*1024*1024;
    } else {
        if (err) *err = 1;
        mul = 1;
    }
    digits = u-p;
    if (digits >= sizeof(buf)) {
        if (err) *err = 1;
        return LLONG_MAX;
    }
    memcpy(buf,p,digits);
    buf[digits] = '\0';
    val = strtoll(buf,NULL,10);
    return val*mul;
}

/* Return the number of digits of 'v' when converted to string in radix 10.
 * See ll2string() for more information. */
uint32_t digits10(uint64_t v) {
    if (v < 10) return 1;
    if (v < 100) return 2;
    if (v < 1000) return 3;
    if (v < 1000000000000UL) {
        if (v < 100000000UL) {
            if (v < 1000000) {
                if (v < 10000) return 4;
                return 5 + (v >= 100000);
            }
            return 7 + (v >= 10000000UL);
        }
        if (v < 10000000000UL) {
            return 9 + (v >= 1000000000UL);
        }
        return 11 + (v >= 100000000000UL);
    }
    return 12 + digits10(v / 1000000000000UL);
}

/* Convert a long long into a string. Returns the number of
 * characters needed to represent the number.
 * If the buffer is not big enough to store the string, 0 is returned.
 *
 * Based on the following article (that apparently does not provide a
 * novel approach but only publicizes an already used technique):
 *
 * https://www.facebook.com/notes/facebook-engineering/three-optimization-tips-for-c/10151361643253920
 *
 * Modified in order to handle signed integers since the original code was
 * designed for unsigned integers. */
int ll2string(char* dst, size_t dstlen, long long svalue) {
    static const char digits[201] =
        "0001020304050607080910111213141516171819"
        "2021222324252627282930313233343536373839"
        "4041424344454647484950515253545556575859"
        "6061626364656667686970717273747576777879"
        "8081828384858687888990919293949596979899";
    int negative;
    unsigned long long value;

    /* The main loop works with 64bit unsigned integers for simplicity, so
     * we convert the number here and remember if it is negative. */
    if (svalue < 0) {
        if (svalue != LLONG_MIN) {
            value = -svalue;
        } else {
            value = ((unsigned long long) LLONG_MAX)+1;
        }
        negative = 1;
    } else {
        value = svalue;
        negative = 0;
    }

    /* Check length. */
    uint32_t const length = digits10(value)+negative;
    if (length >= dstlen) return 0;

    /* Null term. */
    uint32_t next = length;
    dst[next] = '\0';
    next--;
    while (value >= 100) {
        int const i = (value % 100) * 2;
        value /= 100;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
        next -= 2;
    }

    /* Handle last 1-2 digits. */
    if (value < 10) {
        dst[next] = '0' + (uint32_t) value;
    } else {
        int i = (uint32_t) value * 2;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
    }

    /* Add sign. */
    if (negative) dst[0] = '-';
    return length;
}

/* Convert a string into a long long. Returns 1 if the string could be parsed
 * into a (non-overflowing) long long, 0 otherwise. The value will be set to
 * the parsed value when appropriate. */
int string2ll(const char *s, size_t slen, long long *value) {
    const char *p = s;
    size_t plen = 0;
    int negative = 0;
    unsigned long long v;

    if (plen == slen)
        return 0;

    /* Special case: first and only digit is 0. */
    if (slen == 1 && p[0] == '0') {
        if (value != NULL) *value = 0;
        return 1;
    }

    if (p[0] == '-') {
        negative = 1;
        p++; plen++;

        /* Abort on only a negative sign. */
        if (plen == slen)
            return 0;
    }

    /* First digit should be 1-9, otherwise the string should just be 0. */
    if (p[0] >= '1' && p[0] <= '9') {
        v = p[0]-'0';
        p++; plen++;
    } else if (p[0] == '0' && slen == 1) {
        *value = 0;
        return 1;
    } else {
        return 0;
    }

    while (plen < slen && p[0] >= '0' && p[0] <= '9') {
        if (v > (ULLONG_MAX / 10)) /* Overflow. */
            return 0;
        v *= 10;

        if (v > (ULLONG_MAX - (p[0]-'0'))) /* Overflow. */
            return 0;
        v += p[0]-'0';

        p++; plen++;
    }

    /* Return if not all bytes were used. */
    if (plen < slen)
        return 0;

    if (negative) {
        if (v > ((unsigned long long)(-(LLONG_MIN+1))+1)) /* Overflow. */
            return 0;
        if (value != NULL) *value = -v;
    } else {
        if (v > LLONG_MAX) /* Overflow. */
            return 0;
        if (value != NULL) *value = v;
    }
    return 1;
}

/* Convert a string into a long. Returns 1 if the string could be parsed into a
 * (non-overflowing) long, 0 otherwise. The value will be set to the parsed
 * value when appropriate. */
int string2l(const char *s, size_t slen, long *lval) {
    long long llval;

    if (!string2ll(s,slen,&llval))
        return 0;

    if (llval < LONG_MIN || llval > LONG_MAX)
        return 0;

    *lval = (long)llval;
    return 1;
}

/* Convert a double to a string representation. Returns the number of bytes
 * required. The representation should always be parsable by strtod(3). */
int d2string(char *buf, size_t len, double value) {
    if (isnan(value)) {
        len = snprintf(buf,len,"nan");
    } else if (isinf(value)) {
        if (value < 0)
            len = snprintf(buf,len,"-inf");
        else
            len = snprintf(buf,len,"inf");
    } else if (value == 0) {
        /* See: http://en.wikipedia.org/wiki/Signed_zero, "Comparisons". */
        if (1.0/value < 0)
            len = snprintf(buf,len,"-0");
        else
            len = snprintf(buf,len,"0");
    } else {
#if (DBL_MANT_DIG >= 52) && (LLONG_MAX == 0x7fffffffffffffffLL)
        /* Check if the float is in a safe range to be casted into a
         * long long. We are assuming that long long is 64 bit here.
         * Also we are assuming that there are no implementations around where
         * double has precision < 52 bit.
         *
         * Under this assumptions we test if a double is inside an interval
         * where casting to long long is safe. Then using two castings we
         * make sure the decimal part is zero. If all this is true we use
         * integer printing function that is much faster. */
        double min = -4503599627370495; /* (2^52)-1 */
        double max = 4503599627370496; /* -(2^52) */
        if (value > min && value < max && value == ((double)((long long)value)))
            len = ll2string(buf,len,(long long)value);
        else
#endif
            len = snprintf(buf,len,"%.17g",value);
    }

    return len;
}

/* Generate the Redis "Run ID", a SHA1-sized random number that identifies a
 * given execution of Redis, so that if you are talking with an instance
 * having run_id == A, and you reconnect and it has run_id == B, you can be
 * sure that it is either a different instance or it was restarted. */
void getRandomHexChars(char *p, unsigned int len) {
    FILE *fp = fopen("/dev/urandom","r");
    char *charset = "0123456789abcdef";
    unsigned int j;

    if (fp == NULL || fread(p,len,1,fp) == 0) {
        /* If we can't read from /dev/urandom, do some reasonable effort
         * in order to create some entropy, since this function is used to
         * generate run_id and cluster instance IDs */
        char *x = p;
        unsigned int l = len;
        struct timeval tv;
        pid_t pid = getpid();

        /* Use time and PID to fill the initial array. */
        gettimeofday(&tv,NULL);
        if (l >= sizeof(tv.tv_usec)) {
            memcpy(x,&tv.tv_usec,sizeof(tv.tv_usec));
            l -= sizeof(tv.tv_usec);
            x += sizeof(tv.tv_usec);
        }
        if (l >= sizeof(tv.tv_sec)) {
            memcpy(x,&tv.tv_sec,sizeof(tv.tv_sec));
            l -= sizeof(tv.tv_sec);
            x += sizeof(tv.tv_sec);
        }
        if (l >= sizeof(pid)) {
            memcpy(x,&pid,sizeof(pid));
            l -= sizeof(pid);
            x += sizeof(pid);
        }
        /* Finally xor it with rand() output, that was already seeded with
         * time() at startup. */
        for (j = 0; j < len; j++)
            p[j] ^= rand();
    }
    /* Turn it into hex digits taking just 4 bits out of 8 for every byte. */
    for (j = 0; j < len; j++)
        p[j] = charset[p[j] & 0x0F];
    if (fp) fclose(fp);
}

/* Return true if the specified path is just a file basename without any
 * relative or absolute path. This function just checks that no / or \
 * character exists inside the specified path, that's enough in the
 * environments where Redis runs. */
int pathIsBaseName(char *path) {
    return strchr(path,'/') == NULL && strchr(path,'\\') == NULL;
}

char *ipproto_name(uint8_t proto_id)
{
	static char proto[8];

	switch (proto_id) {
	case IPPROTO_TCP:
		return ("TCP");
		break;
	case IPPROTO_UDP:
		return ("UDP");
		break;
	case IPPROTO_ICMP:
		return ("ICMP");
		break;
	case IPPROTO_ICMPV6:
		return ("ICMPV6");
		break;
	case 112:
		return ("VRRP");
		break;
	case IPPROTO_IGMP:
		return ("IGMP");
		break;
	default:
		return ("UNKNOWN");
		break;
	}

	snprintf(proto, sizeof(proto), "%u", proto_id);
	return (proto);
}


int parseipandport(const char *addr, char *ip, size_t len, uint16_t *port)
{
	char *temp = zstrdup(addr);
	char *sep = strchr(temp, ':');
	if (sep) {
		*sep = 0;
		strncpy(ip, temp, len);
		sep++;
		*port = atoi(sep);
	} else {
		strncpy(ip, temp, len);
		*port = 0;
	}
	zfree(temp);
	return 0;
}

int manage_interface_promisc_mode(const char *interface, int on) {
    // We need really any socket for ioctl
    int fd;
    struct ifreq ethreq;
    int ioctl_res;
    int promisc_enabled_on_device;
    int ioctl_res_set;

    fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!fd) {
        t01_log(T01_WARNING,
                "Can't create socket for promisc mode manager");
        return -1;
    }

    bzero(&ethreq, sizeof(ethreq));
    strncpy(ethreq.ifr_name, interface, IFNAMSIZ);

    ioctl_res = ioctl(fd, SIOCGIFFLAGS, &ethreq);
    if (ioctl_res == -1) {
        t01_log(T01_WARNING, "Can't get interface flags");
        return -1;
    }

    promisc_enabled_on_device = ethreq.ifr_flags & IFF_PROMISC;
    if (on) {
        if (promisc_enabled_on_device) {
            t01_log(T01_DEBUG,
                    "Interface %s in promisc mode already",
                    interface);
            return 0;
        } else {
            t01_log(T01_DEBUG,
                    "Interface %s in non promisc mode now, switch it on",
                    interface);
            ethreq.ifr_flags |= IFF_PROMISC;
            ioctl_res_set = ioctl(fd, SIOCSIFFLAGS, &ethreq);
            if (ioctl_res_set == -1) {
                t01_log(T01_WARNING,
                        "Can't set interface flags");
                return -1;
            }

            return 1;
        }
    } else {
        if (!promisc_enabled_on_device) {
            t01_log(T01_DEBUG,
                    "Interface %s in normal mode already",
                    interface);
            return 0;
        } else {
            t01_log(T01_DEBUG,
                    "Interface in promisc mode now, switch it off");
            ethreq.ifr_flags &= ~IFF_PROMISC;
            ioctl_res_set = ioctl(fd, SIOCSIFFLAGS, &ethreq);
            if (ioctl_res_set == -1) {
                t01_log(T01_WARNING,
                        "Can't set interface flags");
                return -1;
            }

            return 1;
        }
    }
}

static int get_if_idx(const char *if_name) {
    struct ifreq ifr;
    int ret, sockfd;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset((void *) &ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), if_name);
    ret = ioctl(sockfd, SIOCGIFINDEX, &ifr);
    if (ret < 0) {
        t01_log(T01_WARNING, "failed to get idx of if %s", if_name);
        exit(1);
    }

    ret = ifr.ifr_ifindex;
    close(sockfd);
    return ret;
}

int create_l2_raw_socket(const char *if_name) {
    int ret;
    struct sockaddr_ll sock_addr = {
            .sll_family = AF_PACKET,
            .sll_protocol = 0,
            .sll_ifindex = get_if_idx(if_name)
    };

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        t01_log(T01_WARNING, "failed to create L2 socket %s", strerror(errno));
        exit(1);
    }

    ret = bind(fd, (struct sockaddr *) &sock_addr, sizeof(struct sockaddr_ll));
    if (ret < 0) {
        t01_log(T01_WARNING, "failed to bind socket");
        exit(1);
    }

    return fd;
}

char *format_traffic(float numBits, int bits, char *buf) {
    char unit;

    if (bits)
        unit = 'b';
    else
        unit = 'B';

    if (numBits < 1024) {
        snprintf(buf, 32, "%lu %c", (unsigned long) numBits, unit);
    } else if (numBits < 1048576) {
        snprintf(buf, 32, "%.2f K%c", (float) (numBits) / 1024, unit);
    } else {
        float tmpMBits = ((float) numBits) / 1048576;

        if (tmpMBits < 1024) {
            snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
        } else {
            tmpMBits /= 1024;

            if (tmpMBits < 1024) {
                snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
            } else {
                snprintf(buf, 32, "%.2f T%c",
                         (float) (tmpMBits) / 1024, unit);
            }
        }
    }

    return (buf);
}

char *format_packets(float numPkts, char *buf) {

    if (numPkts < 1000) {
        snprintf(buf, 32, "%.2f", numPkts);
    } else if (numPkts < 1000000) {
        snprintf(buf, 32, "%.2f K", numPkts / 1000);
    } else {
        numPkts /= 1000000;
        snprintf(buf, 32, "%.2f M", numPkts);
    }

    return (buf);
}

char *etheraddr_string(const unsigned char *ep, char *buf) {
    char *hex = "0123456789ABCDEF";
    u_int i, j;
    char *cp;

    cp = buf;
    if((j = *ep >> 4) != 0)
        *cp++ = hex[j];
    else
        *cp++ = '0';

    *cp++ = hex[*ep++ & 0xf];

    for(i = 5; (int)--i >= 0;) {
        *cp++ = ':';
        if((j = *ep >> 4) != 0)
            *cp++ = hex[j];
        else
            *cp++ = '0';

        *cp++ = hex[*ep++ & 0xf];
    }

    *cp = '\0';
    return (buf);
}

struct ethtool_cmd {
    __u32   cmd;
    __u32   supported;      /* Features this interface supports */
    __u32   advertising;    /* Features this interface advertises */
    __u16   speed;          /* The forced speed, 10Mb, 100Mb, gigabit */
    __u8    duplex;         /* Duplex, half or full */
    __u8    port;           /* Which connector port */
    __u8    phy_address;
    __u8    transceiver;    /* Which transceiver to use */
    __u8    autoneg;        /* Enable or disable autonegotiation */
    __u32   maxtxpkt;       /* Tx pkts before generating tx int */
    __u32   maxrxpkt;       /* Rx pkts before generating rx int */
    __u32   reserved[4];
};

int get_interface_mac(const char* device, unsigned char mac[6]) {
    struct ifreq tmp;
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        perror("create socket fail\n");
        return -1;
    }

    memset(&tmp, 0, sizeof(tmp));
    strncpy(tmp.ifr_name, device, sizeof(tmp.ifr_name)-1);
    if ((ioctl(fd, SIOCGIFHWADDR, &tmp)) < 0){
        printf("ioctl");
        close(fd);
        return -1;
    }

    close(fd);
    memcpy(mac, tmp.ifr_hwaddr.sa_data, 6);
    return 0;
}

int ethtool_get_interface_speed(const char *device) {
    struct ifreq ifr;
    int err;
    struct ethtool_cmd ep;
    int fd;

    /* Open control socket. */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, device);
    ep.cmd = 0x00000001;
    ifr.ifr_data = (caddr_t)&ep;
    err = ioctl(fd, SIOCETHTOOL, &ifr);
    if (err != 0) {
        perror("ioctl");
        close(fd);
        return -1;
    }

    close(fd);
    return ep.speed;
}

int get_cpu_cores() {
    return get_nprocs();
}

uint64_t get_total_ram() {
    static uint64_t total = 0;

    if (total == 0) {
        struct sysinfo si;
        sysinfo(&si);
        total = si.totalram;
    }

    return total;
}
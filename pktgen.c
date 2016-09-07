/*
 * Copyright 2016 <copyright holder> <email>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <ifaddrs.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>  

#include "pktgen.h"
#include "rule.h"
#include "ndpi_protocol_ids.h"

static inline unsigned long csum_tcpudp_nofold (unsigned long saddr, unsigned long daddr,
                                                unsigned short len, unsigned short proto,
                                                unsigned int sum)
{
    asm("addl %1, %0\n"    /* 累加daddr */
        "adcl %2, %0\n"    /* 累加saddr */
        "adcl %3, %0\n"    /* 累加len(2字节), proto, 0*/
        "adcl $0, %0\n"    /*加上进位 */
        : "=r" (sum)
        : "g" (daddr), "g" (saddr), "g" ((ntohs(len) << 16) + proto*256), "0" (sum));
    return sum;
} 

static inline unsigned int csum_fold(unsigned int sum)
{
    sum = (sum & 0xffff) + (sum >> 16);      //将高16 叠加到低16
    sum = (sum & 0xffff) + (sum >> 16);      //将产生的进位叠加到 低16
    return (unsigned short)~sum;  
}

static inline unsigned short csum_tcpudp_magic(unsigned long saddr, unsigned long daddr,
                                                   unsigned short len, unsigned short proto,
                                                   unsigned int sum)
{
    return csum_fold(csum_tcpudp_nofold(saddr, daddr, len, proto, sum));
}

static inline unsigned short tcp_v4_check(int len, unsigned long saddr, 
					  unsigned long daddr, unsigned base)
{
  return csum_tcpudp_magic(saddr, daddr, len, IPPROTO_TCP, base);
}

static inline unsigned short from32to16(unsigned a)
{
    unsigned short b = a >> 16;
    asm ("addw %w2, %w0\n\t"
              "adcw $0, %w0\n"
              : "=r" (b)
              : "0" (b), "r" (a));
    return b;
}

static inline unsigned add32_with_carry(unsigned a, unsigned b)
{
    asm("addl %2, %0\n\t"
             "adcl $0, %0"
             : "=r" (a)
             : "0" (a), "r" (b));
    return a;
} 

static inline unsigned do_csum(const unsigned char *buff, unsigned len)
{
    unsigned odd, count;
    unsigned long result = 0;

    if (len == 0)
        return result;

    /* 使起始地址为XXX0，接下来可按2字节对齐 */
    odd = 1 & (unsigned long) buff;
    if (odd) {
        result = *buff << 8; /* 因为机器是小端的 */
        len--;
        buff++;
    }
    count = len >> 1; /* nr of 16-bit words，这里可能余下1字节未算，最后会处理*/

    if (count) {
        /* 使起始地址为XX00，接下来可按4字节对齐 */
        if (2 & (unsigned long) buff) {
            result += *(unsigned short *)buff;
            count--;
            len -= 2;
            buff += 2;
        }
        count >>= 1; /* nr of 32-bit words，这里可能余下2字节未算，最后会处理 */

        if (count) {
            unsigned long zero;
            unsigned count64;
            /* 使起始地址为X000，接下来可按8字节对齐 */
            if (4 & (unsigned long)buff) {
                result += *(unsigned int *)buff;
                count--;
                len -= 4;
                buff += 4;
            }
            count >>= 1; /* nr of 64-bit words，这里可能余下4字节未算，最后会处理*/

            /* main loop using 64byte blocks */
            zero = 0;
            count64 = count >> 3; /* 64字节的块数，这里可能余下56字节未算，最后会处理 */
            while (count64) { /* 反码累加所有的64字节块 */
                asm ("addq 0*8(%[src]), %[res]\n\t"    /* b、w、l、q分别对应8、16、32、64位操作 */
                          "addq 1*8(%[src]), %[res]\n\t"    /* [src]为指定寄存器的别名，效果应该等同于0、1等 */
                          "adcq 2*8(%[src]), %[res]\n\t"
                          "adcq 3*8(%[src]), %[res]\n\t"
                          "adcq 4*8(%[src]), %[res]\n\t"
                          "adcq 5*8(%[src]), %[res]\n\t"
                          "adcq 6*8(%[src]), %[res]\n\t"
                          "adcq 7*8(%[src]), %[res]\n\t"
                          "adcq %[zero], %[res]"
                          : [res] "=r" (result)
                          : [src] "r" (buff), [zero] "r" (zero), "[res]" (result));
                buff += 64;
                count64--;
            }

            /* 从这里开始，反序处理之前可能漏算的字节 */

            /* last upto 7 8byte blocks，前面按8个8字节做计算单位，所以最多可能剩下7个8字节 */
            count %= 8;
            while (count) {
                asm ("addq %1, %0\n\t"
                     "adcq %2, %0\n"
                     : "=r" (result)
                     : "m" (*(unsigned long *)buff), "r" (zero), "0" (result));
                --count;
                buff += 8;
            }

            /* 带进位累加result的高32位和低32位 */
            result = add32_with_carry(result>>32, result&0xffffffff);

            /* 之前始按8字节对齐，可能有4字节剩下 */
            if (len & 4) {
                result += *(unsigned int *) buff;
                buff += 4;
            }
        }

       /* 更早前按4字节对齐，可能有2字节剩下 */
        if (len & 2) {
            result += *(unsigned short *) buff;
            buff += 2;
        }
    }

    /* 最早之前按2字节对齐，可能有1字节剩下 */
    if (len & 1)
        result += *buff;

    /* 再次带进位累加result的高32位和低32位 */
    result = add32_with_carry(result>>32, result & 0xffffffff); 

    /* 这里涉及到一个技巧，用于处理初始地址为奇数的情况 */
    if (odd) {
        result = from32to16(result); /* 累加到result的低16位 */
        /* result为：0 0 a b
         * 然后交换a和b，result变为：0 0 b a
         */
        result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
    }

    return result; /* 返回result的低32位 */
}

static inline unsigned int calc_csum(const unsigned char *buff, unsigned nbytes) 
{
	unsigned short oddbyte;
	unsigned long sum = 0;
	unsigned short* ptr = (unsigned short*)buff;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	return sum;
}

unsigned csum_partial(const unsigned char *buff, unsigned len, unsigned sum)
{
    return add32_with_carry(calc_csum(buff, len), sum);
}

uint16_t csum(uint16_t *ptr, int nbytes, unsigned long sum) 
{
  uint16_t oddbyte;
  register short answer;

  while(nbytes>1) {
    sum+=*ptr++;
    nbytes-=2;
  }
  if(nbytes==1) {
    oddbyte=0;
    *((u_char*)&oddbyte)=*(u_char*)ptr;
    sum+=oddbyte;
  }

  sum = (sum>>16)+(sum & 0xffff);
  sum = sum + (sum>>16);
  answer=(short)~sum;

  return(answer);
}

int make_http_redirect_packet(const char* target_url,  const char* hdr, char* result, int len)
{
  struct ether_header *src_eth = (struct ether_header *)hdr;
  struct iphdr *src_iph = (struct iphdr *)(src_eth+1);
  struct tcphdr *src_tcph = (struct tcphdr *)(src_iph+1);
  struct ether_header *eth = (struct ether_header *)result;
  struct iphdr *iph = (struct iphdr *)(eth+1);
  struct tcphdr *tcph = (struct tcphdr *)(iph+1);  
  char* payload = (char*)(tcph+1);
  
  const char *http_redirect_header = "HTTP/1.1 301 Moved Permanently\r\n"
					  "Connection: keep-alive\r\n"
					  "Location: http://%s\r\n"
					  "Content-Type: text/html\r\n"
					  "Content-length: 0\r\n"
					  "Cache-control: no-cache\r\n"
					  "\r\n";
  int data_len = snprintf(payload, len-sizeof(*eth)-sizeof(*iph)-sizeof(*tcph), http_redirect_header, target_url);  
  
  memcpy(eth->ether_shost, src_eth->ether_dhost, 6); /* 填入数据包源地址 */ 
  memcpy(eth->ether_dhost, src_eth->ether_shost, 6);   /* 填入目的地址 客户端地址 */
  eth->ether_type = htons(0x0800);           /* 以太网帧类型 */
  
  //Fill in the IP Header
  iph->ihl = src_iph->ihl;
  iph->version = src_iph->version;
  iph->tos = 0;
  iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len);
  iph->id = htons(36742);	//Id of this packet
  iph->frag_off = htons(16384);///
  iph->ttl = 128;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;		//Set to 0 before calculating checksum
  iph->saddr = src_iph->daddr; // 源IP地址
  iph->daddr = src_iph->saddr; // 目的IP地址
  //Ip checksum
  iph->check = csum((uint16_t*)iph, 20, 0);
  
  //TCP Header
  tcph->source = src_tcph->dest;
  tcph->dest = src_tcph->source;

  tcph->doff = 5;
  tcph->seq = src_tcph->ack_seq;    
  tcph->ack_seq = htonl(ntohl(src_tcph->seq)+ntohs(src_iph->tot_len)-4*src_tcph->doff-sizeof(*src_iph));

  tcph->fin = 0;
  tcph->syn = 0;
  tcph->rst = 0;
  tcph->psh = 1;
  tcph->ack = 1;
  tcph->urg = 0;

  tcph->window = htons (64240);	/* maximum allowed window size */
  tcph->check = 0;	//leave checksum 0 now, filled later by pseudo header
  tcph->urg_ptr = 0;
  
  //tcph->check = csum_fold(csum_partial((char*)tcph, sizeof(struct tcphdr)+data_len, 
  //  csum_tcpudp_nofold(iph->saddr, iph->daddr, sizeof(struct tcphdr) + data_len, IPPROTO_TCP, 0)
  //));
  
  unsigned int sum = csum_partial((char*)(tcph), sizeof(struct tcphdr)+data_len, 0);
  sum = csum_tcpudp_nofold(iph->saddr, iph->daddr, sizeof(struct tcphdr) + data_len, IPPROTO_TCP, sum);	
  tcph->check = csum_fold(sum);
  
  //tcph->check = tcp_v4_check(sizeof(struct tcphdr)+data_len, iph->saddr, iph->daddr,
   // csum_partial((char*)tcph, sizeof(struct tcphdr)+data_len, 0));
  
  return sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + data_len;
}

int make_packet(const struct rule* rule, const char* hdr, char* packet, int len)
{
  if(rule->action == T01_ACTION_REDIRECT && rule->master_protocol == NDPI_PROTOCOL_HTTP)
    return make_http_redirect_packet(rule->action_params[0], hdr, packet, len);
  return 0;
}

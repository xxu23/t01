/* inclusion guard */
#ifndef __PKTGEN_H__
#define __PKTGEN_H__

struct rule;

int make_packet(const struct rule* rule, const char* hdr, char* packet, int len);

#endif /* __PKTGEN_H__ */

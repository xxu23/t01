#define NETMAP_WITH_LIBS 1
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>

#include <net/netmap_user.h>
#include "ndpi_api.h"
#include "ndpi_util.h"
#include "pktgen.h"
#include "rule.h"

static char ifname[32], ofname[32];
static char configfile[256];
static struct nm_desc *nmr, *out_nmr;
static u_int8_t shutdown_app = 0;
static int rule_num = 0;
static int verbose = 0;
static int enable_all_protocol = 1;
static NDPI_PROTOCOL_BITMASK ndpi_mask;
static struct list_head rule_list;

static char* ipProto2Name(u_short proto_id) {

  static char proto[8];

  switch(proto_id) {
  case IPPROTO_TCP:
    return("TCP");
    break;
  case IPPROTO_UDP:
    return("UDP");
    break;
  case IPPROTO_ICMP:
    return("ICMP");
    break;
  case IPPROTO_ICMPV6:
    return("ICMPV6");
    break;
  case 112:
    return("VRRP");
    break;
  case IPPROTO_IGMP:
    return("IGMP");
    break;
  }

  snprintf(proto, sizeof(proto), "%u", proto_id);
  return(proto);
}

static char* formatTraffic(float numBits, int bits, char *buf) {
  char unit;

  if(bits)
    unit = 'b';
  else
    unit = 'B';

  if(numBits < 1024) {
    snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if(numBits < 1048576) {
    snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/1048576;

    if(tmpMBits < 1024) {
      snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
    } else {
      tmpMBits /= 1024;

      if(tmpMBits < 1024) {
	snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
      } else {
	snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return(buf);
}

static char* formatPackets(float numPkts, char *buf) {

  if(numPkts < 1000) {
    snprintf(buf, 32, "%.2f", numPkts);
  } else if(numPkts < 1000000) {
    snprintf(buf, 32, "%.2f K", numPkts/1000);
  } else {
    numPkts /= 1000000;
    snprintf(buf, 32, "%.2f M", numPkts);
  }

  return(buf);
}


static int manage_interface_promisc_mode(const char* interface, int switch_on) {
    // We need really any socket for ioctl
    int fd;
    struct ifreq ethreq;    
    int ioctl_res;
    int promisc_enabled_on_device;
    int ioctl_res_set;

    fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (!fd) {
        fprintf(stderr, "Can't create socket for promisc mode manager\n");
        return -1;
    }

    bzero(&ethreq, sizeof(ethreq));
    strncpy(ethreq.ifr_name, interface, IFNAMSIZ);

    ioctl_res = ioctl(fd, SIOCGIFFLAGS, &ethreq);
    if (ioctl_res == -1) {
        fprintf(stderr, "Can't get interface flags\n");
        return -1;
    }
 
    promisc_enabled_on_device = ethreq.ifr_flags & IFF_PROMISC;
    if (switch_on) {
        if (promisc_enabled_on_device) {
            printf("Interface %s in promisc mode already\n", interface);
            return 0;
        } else {
             printf("Interface %s in non promisc mode now, switch it on\n", interface);
             ethreq.ifr_flags |= IFF_PROMISC;
             ioctl_res_set = ioctl(fd, SIOCSIFFLAGS, &ethreq);
             if (ioctl_res_set == -1) {
                 fprintf(stderr, "Can't set interface flags\n");
                 return -1;
             }

             return 1;
        }
    } else { 
        if (!promisc_enabled_on_device) {
            printf("Interface %s in normal mode already\n", interface);
            return 0;
        } else {
            fprintf(stderr, "Interface in promisc mode now, switch it off\n");
            ethreq.ifr_flags &= ~IFF_PROMISC;
            ioctl_res_set = ioctl(fd, SIOCSIFFLAGS, &ethreq);
            if (ioctl_res_set == -1) {
                fprintf(stderr, "Can't set interface flags\n");
                return -1;
            }

            return 1;
        }
    }
}

static void on_protocol_discovered(struct ndpi_workflow * workflow,
        struct ndpi_flow_info * flow,  void* header, void* packet) {

  if(flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) {
        flow->detected_protocol = ndpi_guess_undetected_protocol(workflow->ndpi_struct,
							   flow->protocol,
							   ntohl(flow->lower_ip),
							   ntohs(flow->lower_port),
							   ntohl(flow->upper_ip),
							   ntohs(flow->upper_port));
        flow->detected_protocol.master_protocol = NDPI_PROTOCOL_UNKNOWN;
  }
  
  struct rule* rule = match_rule_from_packet(&rule_list, flow, packet);
  if(!rule) return;
  rule->hits ++;
  
  char result[1500] = {0};
  int len = make_packet(rule, packet, result, sizeof(result));
  if(len) {
    nm_inject(out_nmr, result, len);
  
    if(verbose){
      printf("\tHits: %s %s:%u <-> %s:%u ",
	    ipProto2Name(flow->protocol),
	    flow->lower_name,
	    ntohs(flow->lower_port),
	    flow->upper_name,
	    ntohs(flow->upper_port));

      if(flow->detected_protocol.master_protocol) {
        char buf[64];
        printf("[proto: %u.%u/%s]",
	      flow->detected_protocol.master_protocol, flow->detected_protocol.protocol,
	      ndpi_protocol2name(workflow->ndpi_struct,
				 flow->detected_protocol, buf, sizeof(buf)));
      } else
        printf("[proto: %u/%s]",
	      flow->detected_protocol.protocol,
	      ndpi_get_proto_name(workflow->ndpi_struct, flow->detected_protocol.protocol));

      printf("[%u pkts/%llu bytes]", flow->packets, flow->bytes);

      if(flow->host_server_name[0] != '\0') printf("[Host: %s]", flow->host_server_name);
      if(flow->ssl.client_certificate[0] != '\0') printf("[SSL client: %s]", flow->ssl.client_certificate);
      if(flow->ssl.server_certificate[0] != '\0') printf("[SSL server: %s]", flow->ssl.server_certificate);

      printf("\n");
    }
  }
}

struct ndpi_workflow* setup_detection()
{
  struct ndpi_workflow * workflow;
  struct ndpi_workflow_prefs prefs;
  memset(&prefs, 0, sizeof(prefs));
  prefs.decode_tunnels = 0;
  prefs.num_roots = NUM_ROOTS;
  prefs.max_ndpi_flows = MAX_NDPI_FLOWS;
  prefs.quiet_mode = 0;

  workflow = ndpi_workflow_init(&prefs);

  ndpi_workflow_set_flow_detected_callback(workflow, on_protocol_discovered, (void *)(uintptr_t)workflow);

  // enable all protocols
  if(enable_all_protocol) 
    NDPI_BITMASK_SET_ALL(ndpi_mask);
  ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &ndpi_mask);

  // clear memory for results
  memset(workflow->stats.protocol_counter, 0, sizeof(workflow->stats.protocol_counter));
  memset(workflow->stats.protocol_counter_bytes, 0, sizeof(workflow->stats.protocol_counter_bytes));
  memset(workflow->stats.protocol_flows, 0, sizeof(workflow->stats.protocol_flows));
  
  return workflow;
}

static void* report_thread(void* args)
{
  struct ndpi_workflow* workflow = (struct ndpi_workflow*)args;
  struct ndpi_stats* stat = &workflow->stats;
  u_int64_t total_flow_bytes = 0;
  struct timeval begin, end;
  u_int64_t tot_usec;
  u_int64_t raw_packet_count = 0;
  u_int64_t ip_packet_count = 0;
  u_int64_t total_wire_bytes = 0, total_ip_bytes = 0;
  u_int64_t tcp_count = 0, udp_count = 0;
  u_int64_t hits = 0; 

  while(!shutdown_app){
    gettimeofday(&begin, NULL);
    sleep(5);
    gettimeofday(&end, NULL);
    tot_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);

    u_int avg_pkt_size = 0;
    u_int64_t curr_raw_packet_count = stat->raw_packet_count - raw_packet_count;
    u_int64_t curr_ip_packet_count = stat->ip_packet_count - ip_packet_count;
    u_int64_t curr_total_wire_bytes = stat->total_wire_bytes - total_wire_bytes; 
    u_int64_t curr_total_ip_bytes = stat->total_ip_bytes - total_ip_bytes;
    u_int64_t curr_tcp_count = stat->tcp_count - tcp_count;
    u_int64_t curr_udp_count = stat->udp_count - udp_count;
    
    raw_packet_count = stat->raw_packet_count;
    ip_packet_count = stat->ip_packet_count;
    total_wire_bytes = stat->total_wire_bytes; 
    total_ip_bytes = stat->total_ip_bytes;
    tcp_count = stat->tcp_count;
    udp_count = stat->udp_count;
    
    printf("\nTraffic statistics:\n");
    printf("\tEthernet bytes:        %-13llu\n", curr_total_wire_bytes);
    printf("\tIP bytes:              %-13llu (avg pkt size %u bytes)\n", curr_total_ip_bytes, avg_pkt_size);
    printf("\tIP packets:            %-13llu of %llu packets total\n", curr_ip_packet_count, curr_raw_packet_count);
    /* In order to prevent Floating point exception in case of no traffic*/
    if(curr_total_ip_bytes && curr_raw_packet_count)
      avg_pkt_size = (unsigned int)(curr_total_ip_bytes/curr_raw_packet_count);
    printf("\tTCP Packets:           %-13lu\n", curr_tcp_count);
    printf("\tUDP Packets:           %-13lu\n", curr_udp_count);

    if(tot_usec > 0) {
      char buf[32], buf1[32];
      float t = (float)(curr_ip_packet_count*1000000)/(float)tot_usec;
      float b = (float)(curr_total_wire_bytes * 8 *1000000)/(float)tot_usec;
      float traffic_duration = tot_usec;
      printf("\tnDPI throughput:       %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
      t = (float)(curr_ip_packet_count*1000000)/(float)traffic_duration;
      b = (float)(curr_total_wire_bytes * 8 *1000000)/(float)traffic_duration;
      printf("\tTraffic throughput:    %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
      printf("\tTraffic duration:      %.3f sec\n", traffic_duration/1000000);
    }

    struct list_head* pos;
    u_int64_t total_hits = 0;
    list_for_each(pos, &rule_list) {
      struct rule* rule = list_entry(pos, struct rule, list);
      if(rule->used == 0) 
          continue;
      total_hits += rule->hits;
    }
    printf("\tRules hits:            %-13lu (total %llu)\n", total_hits - hits, total_hits);
    hits = total_hits;
  }
  return NULL;
}

static inline int receive_packets(struct netmap_ring *ring,
				  struct ndpi_workflow *workflow)
{
  u_int cur, rx, n;
  struct nm_pkthdr hdr;
  cur = ring->cur;
  n = nm_ring_space(ring);
  for (rx = 0; rx < n; rx++) {
    struct netmap_slot *slot = &ring->slot[cur];
    char *data = NETMAP_BUF(ring, slot->buf_idx);
    hdr.ts = ring->ts;
    hdr.len = hdr.caplen = slot->len;
    cur = nm_ring_next(ring, cur);
    ndpi_workflow_process_packet(workflow, &hdr, (u_char *) data);
  }

  ring->head = ring->cur = cur;
  return (rx);
}

static void main_thread()
{
  int err, i;
  struct pollfd pfd = { .fd = nmr->fd, .events = POLLIN };
  struct ndpi_workflow* workflow = setup_detection();
  pthread_t report_thread_id;
  struct netmap_ring *rxring = NULL;
  struct netmap_if *nifp = nmr->nifp;
  
  err = pthread_create(&report_thread_id, NULL, report_thread,  workflow);
  if (err != 0) {
    printf("create report thread failed(%d)\n", err);
    return;
  }
  
  while(!shutdown_app){
    /* should use a parameter to decide how often to send */
    if (poll(&pfd, 1, 1000) <= 0) {
      continue;
     }
    
    for (i = nmr->first_rx_ring; i <= nmr->last_rx_ring; i++) {
      rxring = NETMAP_RXRING(nifp, i);
      if (nm_ring_empty(rxring))
        continue;
      receive_packets(rxring, workflow);
    }
  }
  
  err = pthread_join(report_thread_id, NULL);
  if (err != 0) {
    printf("join report thread failed(%d)\n", err);
    return;
  }
}

static void usage()
{
  const char *cmd = "t01";
  fprintf(stderr,
	  "Usage:\n"
	  "%s arguments\n"
	  "\t-i interface                interface that captures incoming traffic\n"
	  "\t-o interface               interface that sends outcoming traffic (default same as incoming interface)\n"
	  "\t-c configfile               json rule file for traffic action\n"
	  "\t-m mask                  enable all ndpi protocol or not (default 1)\n"
	  "",
	  cmd);

  exit(0);
}

static void parse_options(int argc, char **argv) {
  int opt;

  while ((opt = getopt(argc, argv, "hi:o:c:m:v")) != EOF) {
    switch (opt) {
    case 'i':
      strncpy(ifname, optarg, sizeof(ifname));
      break;
    
    case 'o':
      strncpy(ofname, optarg, sizeof(ofname));
      break;

    case 'm':
      enable_all_protocol = atoi(optarg);
      break;

    case 'c':
      strcpy(configfile, optarg);
      break;
      
    case 'v':
      verbose = 1;
      break;

    case 'h':
      usage();
      break;

    default:
      usage();
      break;
    }
  }

   // check parameters
  if(ifname[0] ==0 && configfile[0] == 0) {
    usage();
  }
}

static void signal_hander(int sig)
{
  static int called = 0;
  printf("received control-C, shutdowning\n");
  if(called) return; else called = 1;
  shutdown_app = 1;
}

int main(int argc, char **argv)
{
  struct nmreq base;
  char interface[64];

  parse_options(argc, argv);  

  manage_interface_promisc_mode(ifname, 1); 
  printf("Please disable all types of offload for this NIC manually: ethtool -K %s gro off gso off tso off lro off\n", ifname);

  bzero(&base, sizeof(base));
  sprintf(interface, "netmap:%s", ifname);      
  nmr = nm_open(interface, &base, 0, NULL); 
  if (nmr == NULL){
    printf("Unable to open %s: %s\n", ifname, strerror(errno));
    return 1;
  }
  
  if(ofname[0] == 0 || strcmp(ifname, ofname) == 0){
    out_nmr = nmr;
  } else {
    manage_interface_promisc_mode(ofname, 1); 
    printf("Please disable all types of offload for this NIC manually: ethtool -K %s gro off gso off tso off lro off\n", ofname);
    sprintf(interface, "netmap:%s", ofname);      
    out_nmr = nm_open(interface, &base, 0, NULL); 
    if (out_nmr == NULL){
      printf("Unable to open %s: %s, use %s instead\n", ofname, strerror(errno), ifname);
      out_nmr = nmr;
    }
  }
  
  if(configfile){
    INIT_LIST_HEAD(&rule_list);
    rule_num = load_rules_from_file(configfile, &rule_list, &ndpi_mask);
    if(rule_num > 0){
      printf("Load %d rules from file %s\n", rule_num, configfile);
    } else {
      rule_num = 0;
    }
  }
  
  signal(SIGINT, signal_hander);
  main_thread();

  if(out_nmr != nmr)
    nm_close(out_nmr);
  nm_close(nmr);
  destroy_rules(&rule_list);
  
  return 0;
}

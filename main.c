#define NETMAP_WITH_LIBS 
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>

#include <net/netmap_user.h>
#include "ndpi_api.h"
#include "ndpi_util.h"
#include "pktgen.h"
#include "rule.h"

static char ifname[32], ofname[32];
static char configfile[256];
static struct nm_desc *nmr, *out_nmr;
static u_int8_t shutdown_app = 0;
static struct rule* rules;
static int rule_num = 0;
static int verbose = 0;
static int enable_all_protocol = 1;
static NDPI_PROTOCOL_BITMASK ndpi_mask;

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
  
  if(verbose){
    FILE *out = stdout;
    fprintf(out, "\t%s %s%s%s:%u <-> %s%s%s:%u ",
	    ipProto2Name(flow->protocol),
	    (flow->ip_version == 6) ? "[" : "",
	    flow->lower_name,
	    (flow->ip_version == 6) ? "]" : "",
	    ntohs(flow->lower_port),
	    (flow->ip_version == 6) ? "[" : "",
	    flow->upper_name,
	    (flow->ip_version == 6) ? "]" : "",
	    ntohs(flow->upper_port));

    if(flow->vlan_id > 0) fprintf(out, "[VLAN: %u]", flow->vlan_id);

    if(flow->detected_protocol.master_protocol) {
      char buf[64];

      fprintf(out, "[proto: %u.%u/%s]",
	      flow->detected_protocol.master_protocol, flow->detected_protocol.protocol,
	      ndpi_protocol2name(workflow->ndpi_struct,
				 flow->detected_protocol, buf, sizeof(buf)));
    } else
      fprintf(out, "[proto: %u/%s]",
	      flow->detected_protocol.protocol,
	      ndpi_get_proto_name(workflow->ndpi_struct, flow->detected_protocol.protocol));

    fprintf(out, "[%u pkts/%llu bytes]",
	    flow->packets, (long long unsigned int)flow->bytes);

    if(flow->host_server_name[0] != '\0') fprintf(out, "[Host: %s]", flow->host_server_name);
    if(flow->ssl.client_certificate[0] != '\0') fprintf(out, "[SSL client: %s]", flow->ssl.client_certificate);
    if(flow->ssl.server_certificate[0] != '\0') fprintf(out, "[SSL server: %s]", flow->ssl.server_certificate);
    if(flow->bittorent_hash[0] != '\0') fprintf(out, "[BT Hash: %s]", flow->bittorent_hash);

    fprintf(out, "\n");
  }
  
  int rule_id = match_rule_from_packet(rules, rule_num, flow, packet);
  if(rule_id < 0) return;
  
  char result[1500] = {0};
  int len = make_packet(&rules[rule_id], packet, result, sizeof(result));
  if(len) nm_inject(out_nmr, result, len); 
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
  /* ndpi_thread_info[thread_id].workflow->ndpi_struct->http_dont_dissect_response = 1; */

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
    uint64_t curr_udp_count = stat->udp_count - udp_count;
    
    raw_packet_count = stat->raw_packet_count;
    ip_packet_count = stat->ip_packet_count;
    total_wire_bytes = stat->total_wire_bytes; 
    total_ip_bytes = stat->total_ip_bytes;
    tcp_count = stat->tcp_count;
    udp_count = stat->udp_count;
    
    printf("\nTraffic statistics:\n");
    printf("\tEthernet bytes:        %-13llu\n", curr_total_wire_bytes);
    printf("\tIP packets:            %-13llu of %llu packets total\n", curr_ip_packet_count, curr_raw_packet_count);
    /* In order to prevent Floating point exception in case of no traffic*/
    if(curr_total_ip_bytes && curr_raw_packet_count)
      avg_pkt_size = (unsigned int)(curr_total_ip_bytes/curr_raw_packet_count);
    printf("\tIP bytes:              %-13llu (avg pkt size %u bytes)\n", curr_total_ip_bytes, avg_pkt_size);
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
  }
  return NULL;
}

static void main_thread()
{
  struct pollfd pfd = { .fd = nmr->fd, .events = POLLIN };
  struct ndpi_workflow* workflow = setup_detection();
  pthread_t report_thread_id = NULL;
  
  pthread_create(&report_thread_id, NULL, report_thread,  workflow);
  
  while(!shutdown_app){
    /* should use a parameter to decide how often to send */
    if (poll(&pfd, 1, 300) <= 0) {
      //printf("poll error/timeout on queue: %s\n", strerror(errno));
      continue;
    }
    
    struct nm_pkthdr h;
    u_char* data = nm_nextpkt(nmr, &h);         /* 接收到来的数据包 why not h??? */
    if(!data) continue;
    
    ndpi_workflow_process_packet(workflow, &h, data);
  }
  
  if(report_thread_id)
    pthread_join(report_thread_id, NULL);
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
      sprintf(ifname, "netmap:%s", optarg);
      break;
    
    case 'o':
      sprintf(ofname, "netmap:%s", optarg);
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

  if(out_nmr != nmr)
    nm_close(out_nmr);
  nm_close(nmr);
}

int main(int argc, char **argv)
{
  parse_options(argc, argv);
  
  struct nmreq base;
  bzero(&base, sizeof(base));
  nmr = nm_open(ifname, &base, 0, NULL); 
  if (nmr == NULL){
    printf("Unable to open %s: %s\n", ifname, strerror(errno));
    return 1;
  }
  
  if(ofname[0] == 0){
    out_nmr = nmr;
  } else {
    out_nmr = nm_open(ofname, &base, 0, NULL); 
    if (out_nmr == NULL){
      printf("Unable to open %s: %s, use %s instead\n", ofname, strerror(errno), ifname);
      out_nmr = nmr;
    }
  }
  
  
  if(configfile){
    rule_num = load_rules_from_file(configfile, &rules, &ndpi_mask);
    if(rule_num > 0){
      printf("Load %d rules from file\n", rule_num, configfile);
    } else {
      rule_num = 0;
    }
  }
  
  signal(SIGINT, signal_hander);
  main_thread();
  
  return 0;
}

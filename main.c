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

static char ifname[32];
static char configfile[256];
static struct nm_desc* nmr;
static u_int8_t shutdown_app = 0;
static struct rule* rules;
static int rule_num = 0;

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
    
    int rule_id = match_rule_from_packet(rules, rule_num, flow, packet);
    if(rule_id < 0) return;
    
    char result[1500] = {0};
    int len = make_packet(&rules[rule_id], packet, result, sizeof(result));
    if(len) nm_inject(nmr, result, len); 
}


struct ndpi_workflow* setup_detection()
{
  NDPI_PROTOCOL_BITMASK all;
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
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &all);

  // clear memory for results
  memset(workflow->stats.protocol_counter, 0, sizeof(workflow->stats.protocol_counter));
  memset(workflow->stats.protocol_counter_bytes, 0, sizeof(workflow->stats.protocol_counter_bytes));
  memset(workflow->stats.protocol_flows, 0, sizeof(workflow->stats.protocol_flows));
  
  return workflow;
}

static void main_thread(struct nm_desc* nmr)
{
  struct pollfd pfd = { .fd = nmr->fd, .events = POLLIN };
  struct ndpi_workflow* workflow = setup_detection();
  
  while(!shutdown_app){
    /* should use a parameter to decide how often to send */
    if (poll(&pfd, 1, 3000) <= 0) {
      //printf("poll error/timeout on queue: %s\n", strerror(errno));
      continue;
    }
    
    struct nm_pkthdr h;
    u_char* data = nm_nextpkt(nmr, &h);         /* 接收到来的数据包 why not h??? */
    if(!data) continue;
    ndpi_workflow_process_packet(workflow, &h, data);
  }
}

static void usage()
{
  const char *cmd = "pkt-gen";
  fprintf(stderr,
	  "Usage:\n"
	  "%s arguments\n"
	  "\t-i interface		interface name\n"
	  "\t-c configfile		Specify a configuration file for action selected p\n"
	  "",
	  cmd);

  exit(0);
}

static void parse_options(int argc, char **argv) {

  char *device = "eth0";
  char *config = NULL;
  int opt;

  while ((opt = getopt(argc, argv, "hi:c:")) != EOF) {
    switch (opt) {
    case 'i':
      device = optarg;
      sprintf(ifname, "netmap:%s", device);
      break;

    case 'c':
      strcpy(configfile, optarg);
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
  
  if(configfile){
    rule_num = load_rules_from_file(configfile, &rules);
    if(rule_num > 0){
      printf("Load %d rules from file\n", rule_num, configfile);
    } else {
      rule_num = 0;
    }
  }
  
  signal(SIGINT, signal_hander);
  main_thread(nmr);
  
  return 0;
}
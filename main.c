#define _GNU_SOURCE
#include <stdio.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include <unistd.h>
#include <sys/poll.h>

#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>

#include <sched.h>
#include <pthread.h>

#include "ndpi_api.h"
#include "ndpi_util.h"
#include "pktgen.h"
#include "rule.h"

#define MAX_IFNAMELEN	64	

static struct rule *rules;
static int rule_num = 0;
static int verbose = 0;
static int enable_all_protocol = 1;
static NDPI_PROTOCOL_BITMASK ndpi_mask;

/*
 * global arguments for all threads
 */
struct glob_arg {
	int nthreads;
	int cpus;	/* cpus used for running */
	int system_cpus;	/* cpus on the system */
	int affinity;
	int main_fd;
	struct nm_desc *nmd;
	int report_interval;		/* milliseconds between prints */
	void *mmap_addr;
	char ifname[MAX_IFNAMELEN];
	char ofname[MAX_IFNAMELEN];
	char rulefile[256];
};
static struct glob_arg g;

// struct associated to a workflow for a thread
struct reader_thread {
	struct ndpi_workflow * workflow;
	struct nm_desc *nmd;
	pthread_t thread;
	int me;
	int affinity;
	int main_fd;
	int used;
	int completed;
	int cancel;
	int fd;
};
static struct reader_thread *t01_threads;
static int global_nthreads;

static char *ipProto2Name(u_short proto_id)
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
	}

	snprintf(proto, sizeof(proto), "%u", proto_id);
	return (proto);
}

static char *formatTraffic(float numBits, int bits, char *buf)
{
	char unit;

	if (bits)
		unit = 'b';
	else
		unit = 'B';

	if (numBits < 1024) {
		snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
	} else if (numBits < 1048576) {
		snprintf(buf, 32, "%.2f K%c", (float)(numBits) / 1024, unit);
	} else {
		float tmpMBits = ((float)numBits) / 1048576;

		if (tmpMBits < 1024) {
			snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
		} else {
			tmpMBits /= 1024;

			if (tmpMBits < 1024) {
				snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
			} else {
				snprintf(buf, 32, "%.2f T%c",
					 (float)(tmpMBits) / 1024, unit);
			}
		}
	}

	return (buf);
}

static char *formatPackets(float numPkts, char *buf)
{

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

/* set the thread affinity. */
static int setaffinity(pthread_t me, int i)
{
	cpu_set_t cpumask;

	if (i == -1)
		return 0;

	/* Set thread affinity affinity.*/
	CPU_ZERO(&cpumask);
	CPU_SET(i, &cpumask);

	if (pthread_setaffinity_np(me, sizeof(cpu_set_t), &cpumask) != 0) {
		D("Unable to set affinity: %s", strerror(errno));
		return 1;
	}
	return 0;
}

static int manage_interface_promisc_mode(const char *interface, int switch_on)
{
	// We need really any socket for ioctl
	int fd;
	struct ifreq ethreq;
	int ioctl_res;
	int promisc_enabled_on_device;
	int ioctl_res_set;

	fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (!fd) {
		fprintf(stderr,
			"Can't create socket for promisc mode manager\n");
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
			printf("Interface %s in promisc mode already\n",
			       interface);
			return 0;
		} else {
			printf
			    ("Interface %s in non promisc mode now, switch it on\n",
			     interface);
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
			printf("Interface %s in normal mode already\n",
			       interface);
			return 0;
		} else {
			fprintf(stderr,
				"Interface in promisc mode now, switch it off\n");
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

static void on_protocol_discovered(struct ndpi_workflow *workflow,
				   struct ndpi_flow_info *flow, 
				   void *udata, void *header, void *packet)
{
	const u_int16_t thread_id = (uintptr_t) udata;
	if (flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) {
		flow->detected_protocol =
		    ndpi_guess_undetected_protocol(workflow->ndpi_struct,
						   flow->protocol,
						   ntohl(flow->lower_ip),
						   ntohs(flow->lower_port),
						   ntohl(flow->upper_ip),
						   ntohs(flow->upper_port));
		flow->detected_protocol.master_protocol = NDPI_PROTOCOL_UNKNOWN;
	}

	if (verbose) {
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

		if (flow->vlan_id > 0)
			fprintf(out, "[VLAN: %u]", flow->vlan_id);

		if (flow->detected_protocol.master_protocol) {
			char buf[64];

			fprintf(out, "[proto: %u.%u/%s]",
				flow->detected_protocol.master_protocol,
				flow->detected_protocol.protocol,
				ndpi_protocol2name(workflow->ndpi_struct,
						   flow->detected_protocol, buf,
						   sizeof(buf)));
		} else
			fprintf(out, "[proto: %u/%s]",
				flow->detected_protocol.protocol,
				ndpi_get_proto_name(workflow->ndpi_struct,
						    flow->
						    detected_protocol.protocol));

		fprintf(out, "[%u pkts/%llu bytes]",
			flow->packets, (long long unsigned int)flow->bytes);

		if (flow->host_server_name[0] != '\0')
			fprintf(out, "[Host: %s]", flow->host_server_name);
		if (flow->ssl.client_certificate[0] != '\0')
			fprintf(out, "[SSL client: %s]",
				flow->ssl.client_certificate);
		if (flow->ssl.server_certificate[0] != '\0')
			fprintf(out, "[SSL server: %s]",
				flow->ssl.server_certificate);
		if (flow->bittorent_hash[0] != '\0')
			fprintf(out, "[BT Hash: %s]", flow->bittorent_hash);

		fprintf(out, "\n");
	}

	int rule_id = match_rule_from_packet(rules, rule_num, flow, packet);
	if (rule_id < 0)
		return;

	char result[1500] = { 0 };
	int len = make_packet(&rules[rule_id], packet, result, sizeof(result));
	if (len)
		nm_inject(t01_threads[thread_id].nmd, result, len);
}

struct ndpi_workflow *setup_detection(u_int16_t thread_id)
{
	struct ndpi_workflow *workflow;
	struct ndpi_workflow_prefs prefs;
	memset(&prefs, 0, sizeof(prefs));
	prefs.decode_tunnels = 0;
	prefs.num_roots = NUM_ROOTS;
	prefs.max_ndpi_flows = MAX_NDPI_FLOWS;
	prefs.quiet_mode = 0;

	workflow = ndpi_workflow_init(&prefs);

	ndpi_workflow_set_flow_detected_callback(workflow,
						 on_protocol_discovered,
						 (void *)(uintptr_t)thread_id);

	// enable all protocols
	if (enable_all_protocol)
		NDPI_BITMASK_SET_ALL(ndpi_mask);
	ndpi_set_protocol_detection_bitmask2(workflow->ndpi_struct, &ndpi_mask);

	// clear memory for results
	memset(workflow->stats.protocol_counter, 0,
	       sizeof(workflow->stats.protocol_counter));
	memset(workflow->stats.protocol_counter_bytes, 0,
	       sizeof(workflow->stats.protocol_counter_bytes));
	memset(workflow->stats.protocol_flows, 0,
	       sizeof(workflow->stats.protocol_flows));

	return workflow;
}

static void main_thread()
{
	struct timeval begin, end;
	u_int64_t tot_usec;
	u_int64_t raw_packet_count = 0;
	u_int64_t ip_packet_count = 0;
	u_int64_t total_wire_bytes = 0, total_ip_bytes = 0;
	u_int64_t tcp_count = 0, udp_count = 0;
	int i;
	for (;;) {
		int done = 0;

		gettimeofday(&begin, NULL);
		usleep(1000 * g.report_interval);
		gettimeofday(&end, NULL);
		tot_usec =
		    end.tv_sec * 1000000 + end.tv_usec -
		    (begin.tv_sec * 1000000 + begin.tv_usec);
		
		u_int avg_pkt_size = 0;
		u_int64_t curr_raw_packet_count = 0;
		u_int64_t curr_ip_packet_count = 0;
		u_int64_t curr_total_wire_bytes = 0;
		u_int64_t curr_total_ip_bytes = 0;
		u_int64_t curr_tcp_count = 0;
		u_int64_t curr_udp_count = 0;

		/* accumulate counts for all threads */
		for (i = 0; i < g.nthreads; i++) {
			struct ndpi_stats *stat;
			struct ndpi_workflow *workflow = t01_threads[i].workflow;
			if(!workflow) continue;
			stat = &workflow->stats;
			curr_raw_packet_count += stat->raw_packet_count;
			curr_ip_packet_count += stat->ip_packet_count;
			curr_total_wire_bytes += stat->total_wire_bytes;
			curr_total_ip_bytes += stat->total_ip_bytes;
			curr_tcp_count += stat->tcp_count;
			curr_udp_count += stat->udp_count;
			
			if (t01_threads[i].used == 0)
				done++;
		}
		curr_raw_packet_count -= raw_packet_count;
		curr_ip_packet_count -= ip_packet_count;
		curr_total_wire_bytes -= total_wire_bytes;
		curr_total_ip_bytes -= total_ip_bytes;
		curr_tcp_count -= tcp_count;
		curr_udp_count -= udp_count;

		raw_packet_count = 0;
		ip_packet_count = 0;
		total_wire_bytes = 0, total_ip_bytes = 0;
		tcp_count = 0, udp_count = 0;
		for (i = 0; i < g.nthreads; i++) {
			struct ndpi_stats *stat;
			struct ndpi_workflow *workflow = t01_threads[i].workflow;
			if(!workflow) continue;
			stat = &workflow->stats;
			raw_packet_count += stat->raw_packet_count;
			ip_packet_count += stat->ip_packet_count;
			total_wire_bytes += stat->total_wire_bytes;
			total_ip_bytes += stat->total_ip_bytes;
			tcp_count += stat->tcp_count;
			udp_count += stat->udp_count;
		}	
		
		printf("\nTraffic statistics:\n");
		printf("\tEthernet bytes:        %-13llu\n",
		       curr_total_wire_bytes);
		/* In order to prevent Floating point exception in case of no traffic */
		if (curr_total_ip_bytes && curr_raw_packet_count)
			avg_pkt_size =
			    (unsigned int)(curr_total_ip_bytes /
					   curr_raw_packet_count);
		printf
		    ("\tIP bytes:              %-13llu (avg pkt size %u bytes)\n",
		     curr_total_ip_bytes, avg_pkt_size);
		printf
		    ("\tIP packets:            %-13llu of %llu packets total\n",
		     curr_ip_packet_count, curr_raw_packet_count);
		printf("\tTCP Packets:           %-13lu\n", curr_tcp_count);
		printf("\tUDP Packets:           %-13lu\n", curr_udp_count);

		if (tot_usec > 0) {
			char buf[32], buf1[32];
			float t =
			    (float)(curr_ip_packet_count * 1000000) /
			    (float)tot_usec;
			float b =
			    (float)(curr_total_wire_bytes * 8 * 1000000) /
			    (float)tot_usec;
			float traffic_duration = tot_usec;
			printf("\tnDPI throughput:       %s pps / %s/sec\n",
			       formatPackets(t, buf), formatTraffic(b, 1,
								    buf1));
			t = (float)(curr_ip_packet_count * 1000000) /
			    (float)traffic_duration;
			b = (float)(curr_total_wire_bytes * 8 * 1000000) /
			    (float)traffic_duration;
			printf("\tTraffic throughput:    %s pps / %s/sec\n",
			       formatPackets(t, buf), formatTraffic(b, 1,
								    buf1));
			printf("\tTraffic duration:      %.3f sec\n",
			       traffic_duration / 1000000);
		}
		if (done == g.nthreads)
			break;
	}

	/* final round */
	for (i = 0; i < g.nthreads; i++) {
		if (t01_threads[i].used)
			pthread_join(t01_threads[i].thread, NULL); /* blocking */
		close(t01_threads[i].fd);

		if (t01_threads[i].completed == 0)
			printf("ouch, thread %d exited with error\n", i);
	}

	munmap(g.nmd->mem, g.nmd->req.nr_memsize);
	close(g.main_fd);
}

static void *process_thread(void *data)
{
	struct reader_thread *mythread = (struct reader_thread *) data;
	struct pollfd pfd = { .fd = mythread->fd, .events = POLLIN };
	int i;

	if (setaffinity(mythread->thread, mythread->affinity))
		goto quit;

	printf("reading from %s fd %d main_fd %d\n",
		g.ifname, mythread->fd, mythread->main_fd);
	
	/* main loop, exit after 1s silence */
	while (!mythread->cancel) {
		if (poll(&pfd, 1, 1000) <= 0) {
			continue;
		}
		struct nm_pkthdr h;
		u_char *data = nm_nextpkt(mythread->nmd, &h);
		if (!data)
			continue;

		ndpi_workflow_process_packet(mythread->workflow, &h, data);
	}

	mythread->completed = 1;

quit:
	/* reset the ``used`` flag. */
	mythread->used = 0;

	return (NULL);
}


static void start_threads()
{
	int i;

	t01_threads = calloc(g.nthreads, sizeof(*t01_threads));
	for (i = 0; i < g.nthreads; i++) {
		struct reader_thread *t = &t01_threads[i];
		bzero(t, sizeof(*t));
		t->fd = -1;

	    	struct nm_desc nmd = *g.nmd; /* copy, we overwrite ringid */
		uint64_t nmd_flags = 0;
		nmd.self = &nmd;

		if (i > 0) {
			/* the first thread uses the fd opened by the main
			 * thread, the other threads re-open /dev/netmap
			 */
			if (g.nthreads > 1) {
				nmd.req.nr_flags =
					g.nmd->req.nr_flags & ~NR_REG_MASK;
				nmd.req.nr_flags |= NR_REG_ONE_NIC;
				nmd.req.nr_ringid = i;
			}
			/* Only touch one of the rings (rx is already ok) */
			nmd_flags |= NETMAP_NO_TX_POLL;

			/* register interface. Override ifname and ringid etc. */
			t->nmd = nm_open(g.ifname, NULL, nmd_flags |
				NM_OPEN_IFNAME | NM_OPEN_NO_MMAP, &nmd);
			if (t->nmd == NULL) {
				fprintf(stderr, "Unable to open %s: %s\n",
					g.ifname, strerror(errno));
				continue;
			}
		} else {
			t->nmd = g.nmd;
		}
		t->fd = t->nmd->fd;

		t->used = 1;
		t->me = i;
		if (g.affinity >= 0) {
			t->affinity = (g.affinity + i) % g.system_cpus;
		} else {
			t->affinity = -1;
		}

		t->workflow = setup_detection(i);
		if (pthread_create(&t->thread, NULL, process_thread, t) == -1) {
			D("Unable to create thread %d: %s", i, strerror(errno));
			t->used = 0;
		}
	}
}

static void usage()
{
	const char *cmd = "t01";
	fprintf(stderr,
		"Usage:\n"
		"%s arguments\n"
		"\t-i interface		interface that captures incoming traffic\n"
		"\t-o interface		interface that sends outcoming traffic (default same as incoming interface)\n"
		"\t-r filename		json rule file for traffic action\n"
		"\t-m mask			enable all ndpi protocol or not (default 1)\n"
		"\t-c cores			cores to use\n"
		"\t-p threads		processes/threads to use\n"
		"", cmd);

	exit(0);
}

static int system_ncpus()
{
	int ncpus = sysconf(_SC_NPROCESSORS_ONLN);
	return ncpus;
}


static void parse_options(int argc, char **argv)
{
	int opt;

	while ((opt = getopt(argc, argv, "hi:o:r:m:c:p:v")) != EOF) {
		switch (opt) {
		case 'i':
			sprintf(g.ifname, "netmap:%s", optarg);
			break;

		case 'o':
			sprintf(g.ofname, "netmap:%s", optarg);
			break;

		case 'm':
			enable_all_protocol = atoi(optarg);
			break;

		case 'r':
			strcpy(g.rulefile, optarg);
			break;

		case 'v':
			verbose = 1;
			break;

		case 'c':
			g.cpus = atoi(optarg);
			break;

		case 'p':
			g.nthreads = atoi(optarg);
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
	if (g.ifname[0] == 0 && g.rulefile[0] == 0) {
		usage();
	}
}

static void signal_hander(int sig)
{
	static int called = 0;
	int i;
	printf("received control-C, shutdowning\n");
	if (called)
		return;
	else
		called = 1;
	for (i = 0; i < global_nthreads; i++) {
		t01_threads[i].cancel = 1;
	}
	signal(SIGINT, SIG_DFL);
}

int main(int argc, char **argv)
{
	struct nmreq base_nmd;
	int devqueues = 1;

	g.main_fd = -1;
	g.report_interval = 5000;
	g.affinity = -1;
	g.nthreads = 1;
	g.cpus = 1;	

	parse_options(argc, argv);

	g.system_cpus = system_ncpus();
	if (g.cpus < 0 || g.cpus > g.system_cpus) {
		printf("%d cpus is too high, have only %d cpus\n", g.cpus, g.system_cpus);
		usage();
	}
	printf("running on %d cpus (have %d)\n", g.cpus, g.system_cpus);
	if (g.cpus == 0)
		g.cpus = g.system_cpus;


	manage_interface_promisc_mode(g.ifname+7, 1);
	printf
	    ("Please disable all types of offload for this NIC manually: ethtool -K %s gro off gso off tso off lro off\n",
	     g.ifname);

	bzero(&base_nmd, sizeof(base_nmd));
	base_nmd.nr_flags |= NR_ACCEPT_VNET_HDR;
	base_nmd.nr_tx_rings = base_nmd.nr_rx_rings = 0;
	base_nmd.nr_tx_slots = base_nmd.nr_rx_slots = 0;
	g.nmd = nm_open(g.ifname, &base_nmd, 0, NULL);
	if (g.nmd == NULL) {
		fprintf(stderr, "Unable to open %s: %s\n", g.ifname, strerror(errno));
		return 1;
	}

	if (g.nthreads > 1) {
		struct nm_desc saved_desc = *g.nmd;
		saved_desc.self = &saved_desc;
		saved_desc.mem = NULL;
		nm_close(g.nmd);
		saved_desc.req.nr_flags &= ~NR_REG_MASK;
		saved_desc.req.nr_flags |= NR_REG_ONE_NIC;
		saved_desc.req.nr_ringid = 0;
		g.nmd = nm_open(g.ifname, &base_nmd, NM_OPEN_IFNAME, &saved_desc);
		if (g.nmd == NULL) {
			fprintf(stderr, "Unable to open %s: %s\n", g.ifname, strerror(errno));
			return 1;
		}
	}
	g.main_fd = g.nmd->fd;
	printf("mapped %dKB at %p\n", g.nmd->req.nr_memsize>>10, g.nmd->mem);

	devqueues = g.nmd->req.nr_rx_rings;
	if (g.nthreads < 1 || g.nthreads > devqueues) {
		fprintf(stderr, "bad nthreads %d, have %d queues\n", g.nthreads, devqueues);
		// continue, fail later
	}

	printf("Receiving from %s: %d queues, %d threads and %d cpus.\n",
			g.ifname, devqueues, g.nthreads, g.cpus);

	if (g.rulefile) {
		rule_num = load_rules_from_file(g.rulefile, &rules, &ndpi_mask);
		if (rule_num > 0) {
			printf("Load %d rules from file\n", rule_num,
			       g.rulefile);
		} else {
			rule_num = 0;
		}
	}

	global_nthreads = g.nthreads;
	signal(SIGINT, signal_hander);

	start_threads();
	main_thread();

	return 0;
}

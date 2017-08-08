/*
 * Netmap engine
 *
 */
#define _GNU_SOURCE
#define NETMAP_WITH_LIBS 1
#include <string.h>
#include <sys/poll.h>
#include <net/netmap_user.h>

#include "../ioengine.h"
#include "logger.h"

static int netmap_connect(struct ioengine_data *td, const char *args)
{
	struct nm_desc *nmr;
	struct nmreq base;
	char interface[64];

	bzero(&base, sizeof(base));
	sprintf(interface, "netmap:%s", args);
	nmr = nm_open(interface, &base, 0, NULL);
	if (nmr == NULL) {
		t01_log(T01_WARNING, "Unable to open %s: %s", args,
			strerror(errno));
		return -1;
	}

	td->private = nmr;
	return 0;
}

static int netmap_disconnect(struct ioengine_data *td)
{
	struct nm_desc *nmr = (struct nm_desc *) td->private;
	nm_close(nmr);
	return 0;
}

static int netmap_ping(struct ioengine_data *td) {
	return 0;
}

static int netmap_show_help()
{
	printf("--engine-opt=interface\n"
	       "interface   : Nic interface for transfer data\n");
	return 0;
}

static int netmap_write(struct ioengine_data *td, const char *args, int args_len,
		       const char *buffer, int len)
{
	struct nm_desc *nmr = (struct nm_desc *) td->private;
	struct pollfd pfd;

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = nmr->fd;
	pfd.events = POLLOUT;

	if(poll(&pfd, 1, 1000) < 0)
		return -1;

	return nm_inject(nmr, buffer, len);
}

static struct ioengine_ops ioengine = {
	.name = "netmap",
	.connect = netmap_connect,
	.disconnect = netmap_disconnect,
	.ping = netmap_ping,
	.show_help = netmap_show_help,
	.write = netmap_write,
};

static void io_init io_netmap_register(void)
{
	register_ioengine(&ioengine);
}

static void io_exit io_netmap_unregister(void)
{
	unregister_ioengine(&ioengine);
}

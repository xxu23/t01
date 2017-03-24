#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <event2/event.h>
#include <event2/http.h>

void set_http_server_cb(struct evhttp *http);

int slave_registry_master(const char *master_ip, int master_port, int port);

int master_check_slaves();

#endif

// event compatability.

#ifndef __EVENT_COMPAT_H
#define __EVENT_COMPAT_H

#include <arpa/inet.h>

#include <event.h>

#if ( _EVENT_NUMERIC_VERSION < 0x02000000 )
typedef int evutil_socket_t;

struct event * event_new(struct event_base *evbase, evutil_socket_t sfd, short flags, void (*fn)(int, short, void *), void *arg);
void event_free(struct event *ev);
struct event * evsignal_new(struct event_base *evbase, int sig, void (*fn)(int, short, void *), void *arg);
struct event * evtimer_new(struct event_base *evbase, void (*fn)(int, short, void *), void *arg);
int evutil_parse_sockaddr_port(const char *ip_as_string, struct sockaddr *out, int *outlen);

struct evconnlistener {
	
};

#endif


#endif

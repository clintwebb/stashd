
#include "event-compat.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>


#if ( _EVENT_NUMERIC_VERSION < 0x02000000 )

// event_new is a 2.0 function that creates a new event, sets it and then returns the pointer to the new event structure.   1.4 does not have that function, so we wrap an event_set here instead.
struct event * event_new(struct event_base *evbase, evutil_socket_t sfd, short flags, void (*fn)(int, short, void *), void *arg) {
        struct event *ev;

        assert(evbase && sfd >= 0 && flags != 0 && fn);
        ev = calloc(1, sizeof(*ev));
        assert(ev);
        event_set(ev, sfd, flags, fn, arg);
        event_base_set(evbase, ev);
        
        return(ev);
}

void event_free(struct event *ev)
{
        assert(ev);
        event_del(ev);
        free(ev);
}

struct event * evsignal_new(struct event_base *evbase, int sig, void (*fn)(int, short, void *), void *arg)
{
        struct event *ev;
        ev = event_new(evbase, sig, EV_SIGNAL|EV_PERSIST, fn, arg);
        assert(ev);
        return(ev);
}


struct event * evtimer_new(struct event_base *evbase, void (*fn)(int, short, void *), void *arg)
{
	struct event *ev;
	
	assert(evbase && fn);
	ev = calloc(1, sizeof(*ev));
	assert(ev);
	event_set(ev, -1, EV_TIMEOUT, fn, arg);
	event_base_set(evbase, ev);
	
	return(ev);
}


// pulled in from libevent 2.0.3 (alpha) to add compatibility for older libevents.
int evutil_parse_sockaddr_port(const char *ip_as_string, struct sockaddr *out, int *outlen) {
	int port;
	char buf[128];
	const char *cp, *addr_part, *port_part;
	int is_ipv6;
	/* recognized formats are:
	 * [ipv6]:port
	 * ipv6
	 * [ipv6]
	 * ipv4:port
	 * ipv4
	 */
	
	cp = strchr(ip_as_string, ':');
	if (*ip_as_string == '[') {
		int len;
		if (!(cp = strchr(ip_as_string, ']'))) { return -1; }
		len = cp-(ip_as_string + 1);
		if (len > (int)sizeof(buf)-1) { return -1; }
		memcpy(buf, ip_as_string+1, len);
		buf[len] = '\0';
		addr_part = buf;
		if (cp[1] == ':') port_part = cp+2;
			else port_part = NULL;
			is_ipv6 = 1;
	} else if (cp && strchr(cp+1, ':')) {
		is_ipv6 = 1;
		addr_part = ip_as_string;
		port_part = NULL;
	} else if (cp) {
		is_ipv6 = 0;
		if (cp - ip_as_string > (int)sizeof(buf)-1) { return -1; }
		memcpy(buf, ip_as_string, cp-ip_as_string);
		buf[cp-ip_as_string] = '\0';
	addr_part = buf;
	port_part = cp+1;
	} else {
		addr_part = ip_as_string;
		port_part = NULL;
		is_ipv6 = 0;
	}
	
	if (port_part == NULL) { port = 0; } 
	else {
		port = atoi(port_part);
		if (port <= 0 || port > 65535) { return -1; }
	}
	
	if (!addr_part) return -1; /* Should be impossible. */
		
		struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	if (1 != inet_pton(AF_INET, addr_part, &sin.sin_addr)) return -1;
			   if (sizeof(sin) > *outlen) return -1;
			   memset(out, 0, *outlen);
	memcpy(out, &sin, sizeof(sin));
	*outlen = sizeof(sin);
	return 0;
}

static void evconn_cb(int sfd, short flags, void *arg)
{
	assert(0);
	
	// check the arg, has a valid function pointer.
	// accept the socket.
	// cd
}


// simulate the listener stuff from libevent2.
// static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx);
struct evconnlistener * evconnlistener_new_bind( struct event_base *evbase, void (*fn)(struct evconnlistener *, int, struct sockaddr *, int), void *arg, int flags, int queues, struct sockaddr *sin, int slen )
{
	struct evconnlistener *listener;

	assert(evbase && fn);
	assert(flags == LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE);
	assert(sin && slen > 0);
	
	assert(0);
	
	// create the socket.
	// bind the socket.
	// listen.
	// set the READ event.
	
	return(listener);
}



#endif


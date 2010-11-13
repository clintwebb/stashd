//-----------------------------------------------------------------------------
// stashd
//	Enhanced hash-map storage database.
//-----------------------------------------------------------------------------


// includes
#include "stash-common.h"
#include <stash.h>

// include libevent.  If we are using 1.x version of libevent, we need to do 
// things slightly different than if we are using 2.x of libevent.
#include <event.h>
#if ( _EVENT_NUMERIC_VERSION < 0x02000000 )
#define LIBEVENT_OLD_VER  
#endif

#if ( _EVENT_NUMERIC_VERSION >= 0x02000000 )
#include <event2/listener.h>
#endif


#include <assert.h>
#include <errno.h>
#include <expbuf.h>
#include <fcntl.h>
#include <linklist.h>
#include <netdb.h>
#include <pwd.h>
#include <risp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


#if (RISP_VERSION < 0x00020400)
#error "Needs librisp v2.04.00 or higher"
#endif

#if (LIBSTASH_VERSION < 0x00000600)
#error "Requires libstash v0.06 or higher."
#endif




#define PACKAGE 						"stashd"
#define VERSION 						"0.10"


#define DEFAULT_BUFSIZE 4096

#ifndef INVALID_HANDLE
#define INVALID_HANDLE -1
#endif




// libevent compatability.   If libevent1.x is used, it doesnt have as much stuff as libevent2.0
#ifdef LIBEVENT_OLD_VER  
typedef int evutil_socket_t;

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



#endif



typedef struct {
	// event base for listening on the sockets, and timeout events.
	struct event_base *evbase;

	// risp object to process a RISP stream.  This can be from the network or from the disk.   THe stream protocol should be compatible even though they would be handled differently.
	risp_t *risp;
	risp_t *risp_req;
	risp_t *risp_data;
	risp_t *risp_attr;
	
	// linked list of listening sockets.
	list_t *servers;

	// generic read buffer for reading from the socket or from the file.  It should always be empty, and anything left after processing should be put in a pending buffer.
	expbuf_t *readbuf;
	
	// general reply buffer.   THe contents would have been generated for the client, but this one can be used by all of them to wrap the reply values inside a STASH_CMD_REPLY.
	expbuf_t *replybuf;

	// number of connections that we are currently listening for activity from.
	int conncount;
	
	// startup settings.
	const char *interfaces;
	int maxconns;
	int verbose;
	int daemonize;
	const char *storepath;
	const char *username;
	const char *pid_file;

	struct event *sigint_event;
	struct event *sighup_event;

	storage_t *storage;
	
} control_t;


typedef struct {
	#ifdef LIBEVENT_OLD_VER  
		evutil_socket_t handle;
		struct event listen_event;
	#else
		struct evconnlistener *listener;
	#endif
	list_t *clients;
	control_t *control;
} server_t;


// attribute pair.
typedef struct {
	stash_keyid_t keyid;
	stash_value_t *value;
	int expires;
} raw_attr_t;



typedef struct {
	evutil_socket_t handle;
	struct event *read_event;
	struct event *write_event;
	server_t *server;
	expbuf_t *pending;
	expbuf_t *outbuffer;
	
	user_t *user;			// when authenticated, points to the user object in storage.
	
	expbuf_t *replybuf;
	unsigned int failcode;
	int closing;			// 1 if the socket is closing (only needed if something is pending).
	
	list_t *raw_attrlist;		// raw_attr_t - list of attributes parsed 
	
	int req_id;
} client_t;



//-----------------------------------------------------------------------------
// Pre-declare our handlers, because often they need to interact with functions
// that are used to invoke them.
#ifdef LIBEVENT_OLD_VER
	static void accept_conn_cb_old(evutil_socket_t fd, const short flags, void *ctx);
#else
	static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx);
#endif
static void read_handler(int fd, short int flags, void *arg);
static void write_handler(int fd, short int flags, void *arg);


//-----------------------------------------------------------------------------
// Create and init our controller object.   The  control object will have
// everything in it that is needed to run this server.  It is in this object
// because we need to pass a pointer to the handler that will be doing the work.
static void control_init(control_t *control)
{
	assert(control != NULL);

	control->evbase = NULL;
	control->sigint_event = NULL;
	control->sighup_event = NULL;
	control->conncount = 0;
	control->interfaces = NULL;
	control->maxconns = 1024;
	control->risp = NULL;
	control->risp_req = NULL;
	control->risp_data = NULL;
	control->risp_attr = NULL;
	control->verbose = 0;
	control->daemonize = 0;
	control->storepath = NULL;
	control->username = NULL;
	control->pid_file = NULL;
	
	control->readbuf = expbuf_init(NULL, DEFAULT_BUFSIZE);
	control->replybuf = expbuf_init(NULL, DEFAULT_BUFSIZE);
	
	control->storage = NULL;
}

static void control_cleanup(control_t *control)
{
	assert(control != NULL);

	assert(control->readbuf);
	control->readbuf = expbuf_free(control->readbuf);
	assert(control->readbuf == NULL);
	
	assert(control->replybuf);
	control->replybuf = expbuf_free(control->replybuf);
	assert(control->replybuf == NULL);

	control->interfaces = NULL;
	control->storepath = NULL;
	control->username = NULL;
	control->pid_file = NULL;
	
	assert(control->risp == NULL);
	assert(control->risp_req == NULL);
	assert(control->risp_data == NULL);
	assert(control->risp_attr == NULL);
	assert(control->conncount == 0);
	assert(control->sigint_event == NULL);
	assert(control->sighup_event == NULL);
	assert(control->evbase == NULL);
	assert(control->storage == NULL);
}


//-----------------------------------------------------------------------------
// Initialise the server object.
static void server_init(server_t *server, control_t *control)
{
	assert(server);
	assert(control);

#ifndef LIBEVENT_OLD_VER
	server->listener = NULL;
#endif
	server->control = control;

	assert(control->maxconns > 0);
	assert(control->conncount == 0);

	server->clients = ll_init(NULL);
	assert(server->clients);
}


 

#ifdef LIBEVENT_OLD_VER

// parse the interface string which will look something like "127.0.0.1:3345", 
// and given a pointer to a buffer, it will copy the address part to the 
// buffer.
static void parse_interface(char *full, char *portbuf, char *interface, int len)
{
	char *copy, *next, *argument;
	int ll;
	
	assert(full && portbuf && interface && len > 0);
	
	copy = strdup(full);
	assert(copy);
	next = copy;
	argument = strsep(&next, ":");
	if (argument) {
			
		// remove spaces from the begining of the key.
		while(*argument==' ') { argument++; }
		while(*next==' ') { next++; }
		assert(*argument && *next);		// the parts should not be empty.
		
		ll = strlen(argument);
		assert(ll < len);
		strcpy(interface, argument);
		
		ll = strlen(next);
		assert(ll < len);
		strcpy(portbuf, next);
	}
	
	free(copy);
}

static int non_blocking(evutil_socket_t sfd)
{
	int flags;

	assert(sfd >= 0);
	
	if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 || fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) { 
		return -1;
	}
	else {
		return 0;
	}
}

// function copied from memcached.  It creates a new socket handle and sets it to non-blocking.
static int new_socket(struct addrinfo *ai) 
{
	int sfd;
	int flags;
	
	if ((sfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
		return -1;
	}
	
	if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 || fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) { 
		perror("setting O_NONBLOCK");
		close(sfd);
		return -1;
	}
	return sfd;
}


static void server_listen(server_t *server, char *interface)
{
	char ifbuff[32];
	char portbuff[32];
	int sfd;
	struct addrinfo *ai;
	struct addrinfo *next;
	struct addrinfo hints = { .ai_flags = AI_PASSIVE, .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM };
	int error;
	int flags =1;
	struct linger ling = {0, 0};
	int success = 0;
	
	assert(server && interface);
	
	// first parse out the interface so that we have address and port.
	parse_interface(interface, portbuff, ifbuff, 32);
	printf("listening on %s:%s\n", ifbuff, portbuff);

	assert(ifbuff[0] && portbuff[0]);
	
	error= getaddrinfo(ifbuff, portbuff, &hints, &ai);
	assert(error == 0);
	
	
	// keep looping on the results until we listen on one of them.
	for (next= ai; next && success == 0; next= next->ai_next) {
		
		if ((sfd = new_socket(next)) == -1) {
			/* getaddrinfo can return "junk" addresses,
			 * we make sure at least one works before erroring.
			 */
			continue;
		}
		
		setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
		error = setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags));
		assert(error == 0);
		error = setsockopt(sfd, SOL_SOCKET, SO_LINGER, (void *)&ling, sizeof(ling));
		assert(error == 0);
		#ifdef TCP_NODELAY
			error = setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));
			assert(error == 0);
		#endif
		
		if (bind(sfd, next->ai_addr, next->ai_addrlen) == -1) {
			if (errno != EADDRINUSE) {
				perror("bind()");
				close(sfd);
				freeaddrinfo(ai);
				return;
			}
			close(sfd);
			continue;
		} else {
			success ++;
			if (listen(sfd, 5) == -1) {
				perror("listen()");
				close(sfd);
				freeaddrinfo(ai);
				return;
			}
		}

		assert(server->control);
		assert(server->control->evbase);

		event_set(&server->listen_event, sfd, EV_READ | EV_PERSIST, accept_conn_cb_old, (void *)server);
		event_base_set(server->control->evbase, &server->listen_event);
		event_add(&server->listen_event, NULL);
	}
	
	freeaddrinfo(ai);
}

#else
/// using libevent2.x or higher, which makes it easier.


//-----------------------------------------------------------------------------
// Listen for socket connections on a particular interface.
static void server_listen(server_t *server, char *interface)
{
	struct sockaddr_in sin;
	int len;
	
	assert(server);
	assert(interface);
	
	memset(&sin, 0, sizeof(sin));
	// 	sin.sin_family = AF_INET;
	len = sizeof(sin);
	
	assert(sizeof(struct sockaddr_in) == sizeof(struct sockaddr));
	if (evutil_parse_sockaddr_port(interface, (struct sockaddr *)&sin, &len) != 0) {
		assert(0);
	}
	else {
		
		assert(server->listener == NULL);
		assert(server->control);
		assert(server->control->evbase);
		
		server->listener = evconnlistener_new_bind(
								server->control->evbase,
								accept_conn_cb,
								server,
								LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE,
								-1,
								(struct sockaddr*)&sin,
								sizeof(sin)
							);
		assert(server->listener);
	}	
}
#endif 
// different functionality depending on the version of libevent.



static void init_servers(control_t *control)
{
	server_t *server;
	char *copy;
	char *next;
	char *argument;
	const char *interfaces = "127.0.0.1:13600";
	
	assert(control);
	
	if (control->interfaces) {
		interfaces = control->interfaces;
	}
	
	assert(interfaces);
	assert(control->servers == NULL);
	
	
	control->servers = ll_init(control->servers);
	assert(control->servers);

	// make a copy of the supplied string, because we will be splitting it into
	// its key/value pairs. We dont want to mangle the string that was supplied.
	copy = strdup(interfaces);
	assert(copy);

	next = copy;
	while (next != NULL && *next != '\0') {
		argument = strsep(&next, ",");
		if (argument) {
		
			// remove spaces from the begining of the key.
			while(*argument==' ') { argument++; }
			
			if (strlen(argument) > 0) {
				server = malloc(sizeof(*server));
				server_init(server, control);
				ll_push_head(control->servers, server);
		
				if (control->verbose) printf("listen: %s\n", argument);
				
				server_listen(server, argument);
			}
		}
	}
	
	free(copy);
}











//-----------------------------------------------------------------------------
// Initialise the client structure.
static void client_init ( client_t *client, server_t *server, evutil_socket_t handle, struct sockaddr *address, int socklen)
{
	int s;
	
	assert(client);
	assert(server);

	assert(handle > 0);
	client->handle = handle;
	
	if (server->control->verbose) printf("New client - handle=%d\n", handle);
	
	client->read_event = NULL;
	client->write_event = NULL;
	client->server = server;

	// add the client to the list for the server.
	assert(server->clients);
	ll_push_tail(server->clients, client);

	client->outbuffer = expbuf_init(NULL, 0);
	assert(client->outbuffer);
	
	client->pending = expbuf_init(NULL, 0);
	assert(client->pending);
	
	client->replybuf = expbuf_init(NULL, 0);
	assert(client->replybuf);
	
	client->req_id = 0;
	client->user = NULL;
	
	client->raw_attrlist = NULL;
	
	// assign fd to client object.
	assert(server->control);
	assert(server->control->evbase);
	assert(client->handle > 0);
	client->read_event = event_new(
		server->control->evbase,
		client->handle,
		EV_READ|EV_PERSIST,
		read_handler,
		client);
	assert(client->read_event);
	s = event_add(client->read_event, NULL);
	assert(s == 0);
}


#ifdef LIBEVENT_OLD_VER
//-----------------------------------------------------------------------------
// accept an http connection.  Create the client object, and then attach the
// file handle to it.
static void accept_conn_cb_old( evutil_socket_t listen_socket, const short flags, void *ctx)
{
	client_t *client;
	server_t *server = (server_t *) ctx;
	socklen_t addrlen;
	struct sockaddr addr;
	evutil_socket_t sfd;
	
	assert(listen_socket > 0);
	assert(flags == EV_READ);
	assert(ctx);
	assert(server);
	
	addrlen = sizeof(addr);
	if ((sfd = accept(listen_socket, (struct sockaddr *)&addr, &addrlen)) == -1) {
		// somehow the accept failed... need to handle it gracefully.
		assert(0);
	}
	else {
		// set non-blocking
		if (non_blocking(sfd) != 0) {
			// non-blocking failed... 
			assert(0);
		}
		else {
			printf("accepted client connection: socket=%d\n", sfd);
			
			// create client object.
			// TODO: We should be pulling these client objects out of a mempool.
			assert(sizeof(client_t) == sizeof(*client));
			client = calloc(1, sizeof(*client));
			assert(client);
			client_init(client, server, sfd, &addr, addrlen);
		}
	}
}
#else
//-----------------------------------------------------------------------------
// accept an http connection.  Create the client object, and then attach the
// file handle to it.
static void accept_conn_cb(
	struct evconnlistener *listener,
	evutil_socket_t fd,
	struct sockaddr *address,
	int socklen,
	void *ctx)
{
	client_t *client;
	server_t *server = (server_t *) ctx;

	assert(listener);
	assert(fd > 0);
	assert(address && socklen > 0);
	assert(ctx);
	assert(server);

	// create client object.
	// TODO: We should be pulling these client objects out of a mempool.
	client = malloc(sizeof(*client));
	assert(client);
	client_init(client, server, fd, address, socklen);
}
#endif


//-----------------------------------------------------------------------------
// Free the resources used by the client object.
static void client_free(client_t *client)
{
	assert(client);
	
	assert(client->server);
	assert(client->server->control);
	if (client->server->control->verbose >= 2) printf("client_free: handle=%d\n", client->handle);
	
	assert(client->raw_attrlist == NULL);
	
	assert(client->replybuf);
	assert(BUF_LENGTH(client->replybuf) == 0);
	client->replybuf = expbuf_free(client->replybuf);
	assert(client->replybuf == NULL);
	
	assert(client->pending);
	assert(BUF_LENGTH(client->pending) == 0);
	client->pending = expbuf_free(client->pending);
	assert(client->pending == NULL);
	
	assert(client->outbuffer);
	expbuf_clear(client->outbuffer);
	client->outbuffer = expbuf_free(client->outbuffer);
	assert(client->outbuffer == NULL);
	
	if (client->read_event) {
		event_free(client->read_event);
		client->read_event = NULL;
	}
	
	if (client->write_event) {
		event_free(client->write_event);
		client->write_event = NULL;
	}
	
	if (client->handle != INVALID_HANDLE) {
		EVUTIL_CLOSESOCKET(client->handle);
		client->handle = INVALID_HANDLE;
	}
	
	
	// remove the client from the server list.
	assert(client->server);
	assert(client->server->clients);
	assert(ll_count(client->server->clients) > 0);
	ll_remove(client->server->clients, client);
	assert(ll_count(client->server->clients) >= 0);
	
	client->server = NULL;
}


static void client_shutdown(client_t *client)
{
	assert(client);
	
	assert(client->handle >= 0);
	
	assert(client->read_event);
	assert(client->server);
	
	assert(client->pending);
	assert(client->outbuffer);
	
	assert(client->replybuf);
	assert(BUF_LENGTH(client->replybuf) == 0);

	assert(client->closing == 0);
	
	if (BUF_LENGTH(client->pending) > 0 || BUF_LENGTH(client->outbuffer) > 0) {
		client->closing = 1;
	}
	else {
		client_free(client);
	}
}



static void server_shutdown(server_t *server)
{
	client_t *client;
	
	assert(server);
	assert(server->control);

	// need to close the listener socket.
	#ifdef LIBEVENT_OLD_VER
	if(server->handle >= 0) {
		event_del(&server->listen_event);
		close(server->handle);
		server->handle = INVALID_HANDLE;
	}
	#else
	if (server->listener) {
		evconnlistener_free(server->listener);
		server->listener = NULL;
	}
	#endif

	assert(server->clients);
	ll_start(server->clients);
	while (( client = ll_next(server->clients))) {
		client_shutdown(client);
	}
	ll_finish(server->clients);
}


//-----------------------------------------------------------------------------
// Cleanup the server object.
static void server_free(server_t *server)
{
	assert(server);
	
	server_shutdown(server);
	
	assert(server->clients);
	printf("server->clients = %d\n", ll_count(server->clients));
	assert(ll_count(server->clients) == 0);
	server->clients = ll_free(server->clients);
	assert(server->clients == NULL);
	
	assert(server->control);
	server->control = NULL;
}


static void cleanup_servers(control_t *control)
{
	server_t *server;
	
	assert(control);
	assert(control->servers);
	
	while ((server = ll_pop_head(control->servers))) {
		server_free(server);
		free(server);
	}
	
	control->servers = ll_free(control->servers);
	assert(control->servers == NULL);
}



//-----------------------------------------------------------------------------
static void sigint_handler(evutil_socket_t fd, short what, void *arg)
{
	server_t *server;
	control_t *control = (control_t *) arg;

	// need to initiate an RQ shutdown.
	assert(control);
	
	// need to send a message to each node telling them that we are shutting down.
	assert(control->servers);
	ll_start(control->servers);
	while ((server = ll_next(control->servers))) {
		server_shutdown(server);
	}
	ll_finish(control->servers);
	
	// delete the signal events.
	assert(control->sigint_event);
	event_free(control->sigint_event);
	control->sigint_event = NULL;

	assert(control->sighup_event == NULL);
//	event_free(control->sighup_event);
//	control->sighup_event = NULL;
}


//-----------------------------------------------------------------------------
// When SIGHUP is received, we need to re-load the config database.  At the
// same time, we should flush all caches and buffers to reduce the system's
// memory footprint.   It should be as close to a complete app reset as
// possible.
static void sighup_handler(evutil_socket_t fd, short what, void *arg)
{
//  	control_t *control = (control_t *) arg;

	assert(arg);

	// clear out all cached objects.
	assert(0);

	// reload the config database file.
	assert(0);

}









//-----------------------------------------------------------------------------
// when the write event fires, we will try to write everything to the socket.
// If everything has been sent, then we will remove the write_event, and the
// outbuffer.
static void write_handler(int fd, short int flags, void *arg)
{
	client_t *client;
	int res;
	
	assert(fd > 0);
	assert(arg);

	client = arg;

	// PERF: if a performance issue is found with sending large chunks of data 
	//       that dont fit in single send, we might be wasting time by purging 
	//       sent data from hte buffer which results in moving data in memory.
	
	assert(client->write_event);
	assert(client->outbuffer);
	
	res = send(client->handle, BUF_DATA(client->outbuffer), BUF_LENGTH(client->outbuffer), 0);
	if (res > 0) {
		
		assert(res <= BUF_LENGTH(client->outbuffer));
		expbuf_purge(client->outbuffer, res);

		assert(BUF_LENGTH(client->outbuffer) >= 0);
		if (BUF_LENGTH(client->outbuffer) == 0) {
			// we've sent everything....

			// all data has been sent, so we clear the write event.
			assert(client->write_event);
			event_free(client->write_event);
			client->write_event = NULL;
			assert(client->read_event);
		}
	}
	else if (res == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
		// the connection has closed, so we need to clean up.
		client_free(client);
	}
}

static value_t * value_free(value_t *value)
{
	if (value->valtype == STASH_VALTYPE_STR) {
		assert((value->datalen == 0 && value->value.str == NULL) || (value->datalen > 0 && value->value.str));
		if (value->value.str) {
			free((void*)value->value.str);
		}
	}
	free(value);
	return(NULL);
}

//-----------------------------------------------------------------------------
// given a list of attributes, need to pull em from the list and free each one.  
// If the attribute has a value that is another list, we need to recursively 
// call this functon.
static void raw_attrlist_free(list_t *list) 
{
	raw_attr_t *rawattr;
	
	assert(list);
	while ((rawattr = ll_pop_head(list))) {
		assert(rawattr->keyid);
		assert(rawattr->value);
		rawattr->value = value_free(rawattr->value);
		assert(rawattr->value == NULL);
	}
}



// A request has come in from a client connection.  Need to 
static void cmdRequest(client_t *client, const risp_length_t length, const risp_data_t *data)
{
	risp_length_t processed;
	int cnt;
	control_t *control;
	
	assert(client && length >= 0 && data);

	assert(client->replybuf);
	assert(BUF_LENGTH(client->replybuf) == 0);
	client->failcode = STASH_ERR_OK;
	
	assert(client->server);
	assert(client->server->control);
	control = client->server->control;
	
	assert(control->replybuf);
	assert(BUF_LENGTH(control->replybuf) == 0);
	
	assert(client->raw_attrlist == NULL);
	
	// take the data and put it through the 'request' risp parser.
	assert(control->risp_req);
	risp_clear_all(control->risp_req);
	processed = risp_process(control->risp_req, client, length, data);
	assert(processed == length);

	if (client->raw_attrlist) {
		// the Set returned becuse of an error. Need to free the attribute list.
		raw_attrlist_free(client->raw_attrlist);
		assert(ll_count(client->raw_attrlist) == 0);
		client->raw_attrlist = ll_free(client->raw_attrlist);
		assert(client->raw_attrlist == NULL);
	}
	
	// check the risp structure for unprocessed messages.  There shouldn't be any.
	for (cnt=0; cnt<256; cnt++) {
		if (control->risp_req->commands[cnt].handler == NULL) {
			if (control->risp_req->commands[cnt].set) {
				printf("cmdRequest: Unexpected operation: %d\n", cnt);
			}
		}
	}
	
	// the reply should have been generated by now.
	assert(client->replybuf);
	if (client->failcode == STASH_ERR_OK) {
		// add the replybuf to the outpbuf 
		assert(BUF_LENGTH(control->replybuf) == 0);
		
		rispbuf_addInt(client->replybuf, STASH_CMD_REQUEST_ID, client->req_id);
		rispbuf_addBuffer(control->replybuf, STASH_CMD_REPLY, client->replybuf);
	}
	else {
		// we have a failure... 
		assert(BUF_LENGTH(client->replybuf) == 0);
		assert(BUF_LENGTH(control->replybuf) == 0);
		
		rispbuf_addInt(client->replybuf, STASH_CMD_REQUEST_ID, client->req_id);
		rispbuf_addInt(client->replybuf, STASH_CMD_FAILCODE, client->failcode);
		rispbuf_addBuffer(control->replybuf, STASH_CMD_FAILED, client->replybuf);
	}

	client->req_id = 0;
	expbuf_clear(client->replybuf);
	assert(client->outbuffer);
	expbuf_add(client->outbuffer, BUF_DATA(control->replybuf), BUF_LENGTH(control->replybuf));
	expbuf_clear(control->replybuf);
	
	// if there isn't a write event set, then we need to set one.
	assert(client->outbuffer);
	assert(BUF_LENGTH(client->outbuffer) > 0);
	if (client->write_event == NULL) {
		assert(control->evbase);
		assert(client->handle >= 0);
		client->write_event = event_new( control->evbase, client->handle, EV_WRITE | EV_PERSIST, write_handler, (void *)client); assert(client->write_event);
		assert(client->write_event);
		event_add(client->write_event, NULL);
	}
	
	assert(BUF_LENGTH(client->replybuf) == 0);
	assert(BUF_LENGTH(control->replybuf) == 0);
}


static void cmdRequestID(client_t *client, const risp_int_t value) 
{
	assert(client);
	assert(value > 0);
	
	assert(client->req_id == 0);
	client->req_id = value;
}


// most of the operations are going to have to parse the supplied data into a 
// risp object.   This function will do that.  For convenience, we will return 
// the risp_data object.
static risp_t * procRispData(client_t *client, const risp_length_t length, const risp_data_t *data) 
{
	risp_length_t processed;
	
	assert(client->server);
	assert(client->server->control);
	assert(client->server->control->risp_data);
	
	// make sure the client 'attribute' data is cleared.
// 	assert(client->raw_attrlist);
// 	assert(ll_count(client->raw_attrlist) == 0);
	
	risp_clear_all(client->server->control->risp_data);
	processed = risp_process(client->server->control->risp_data, client, length, data);
	assert(processed == length);
	
	return(client->server->control->risp_data);
}


static void cmdLogin(client_t *client, const risp_length_t length, const risp_data_t *data)
{
	risp_t *rdata;
	char *username;
	char *password;
	user_t *user;
	
	assert(client);
	assert(length);
	assert(data);
	
	// expand the data
	rdata = procRispData(client, length, data);
	assert(rdata);
	
	assert(risp_isset(rdata, STASH_CMD_USERNAME));
	assert(risp_isset(rdata, STASH_CMD_PASSWORD));

	username = risp_getstring(rdata, STASH_CMD_USERNAME);
	password = risp_getstring(rdata, STASH_CMD_PASSWORD);
	
	assert(username);
	assert(password);

	assert(client->replybuf);
	assert(BUF_LENGTH(client->replybuf) == 0);
	
	assert(client->server);
	assert(client->server->control);
	assert(client->server->control->storage);
	user = storage_getuser(client->server->control->storage, NULL_USER_ID, username);
	
	if (user == NULL) {
		// we dont have this username in our system.
		assert(client->user == NULL);
		assert(client->replybuf);
		assert(BUF_LENGTH(client->replybuf) == 0);
		
		client->failcode = STASH_ERR_AUTHFAILED;
	}
	else {
		// we have this username... does the passwords match.
		assert(user->uid > 0);
		assert(client->user == NULL);
		assert(user->password);
		if (strcmp(password, user->password) == 0) {
			// passwords match.
			client->user = user;
			client->failcode = STASH_ERR_OK;
			
			// create the reply.
			assert(client->replybuf);
			assert(BUF_LENGTH(client->replybuf) == 0);
			rispbuf_addInt(client->replybuf, STASH_CMD_USER_ID, user->uid);
		}
		else {
			// password didn't match.
			assert(client->user == NULL);
			assert(client->replybuf);
			assert(BUF_LENGTH(client->replybuf) == 0);
			
			client->failcode = STASH_ERR_AUTHFAILED;
		}
	}
}



static void cmdCreateUser(client_t *client, const risp_length_t length, const risp_data_t *data)
{
	risp_t *rdata;
	char *username;
	user_t *user;
	
	assert(client);
	assert(length);
	assert(data);

	// make sure that the logged in user has rights to create new users.
	assert(client->user);
	if (storage_check_rights(client->user, NULL, NULL, STASH_RIGHT_ADDUSER) == 0) {
		// dont have rights to do this action.
		assert(client->replybuf);
		assert(BUF_LENGTH(client->replybuf) == 0);
		
		client->failcode = STASH_ERR_INSUFFICIENTRIGHTS;
	}
	else {
		
		// expand the data
		rdata = procRispData(client, length, data);
		assert(rdata);
		
		assert(risp_isset(rdata, STASH_CMD_USERNAME));
		username = risp_getstring(rdata, STASH_CMD_USERNAME);
		assert(username);
		
		assert(client->replybuf);
		assert(BUF_LENGTH(client->replybuf) == 0);
		
		assert(client->server);
		assert(client->server->control);
		assert(client->server->control->storage);
		user = storage_getuser(client->server->control->storage, NULL_USER_ID, username);
		
		if (user == NULL) {
			// we dont have this username in our system, so we can create it.
			assert(client->user);
			assert(client->user->uid > 0);
			user = storage_create_username(client->server->control->storage, client->user->uid, username);
			assert(user);
			assert(user->uid > 0);
			
			client->failcode = STASH_ERR_OK;
			
			// create the reply.
			assert(client->replybuf);
			assert(BUF_LENGTH(client->replybuf) == 0);
			rispbuf_addInt(client->replybuf, STASH_CMD_USER_ID, user->uid);
		}
		else {
			// we have this username... does the passwords match.
			assert(client->user);
			assert(client->replybuf);
			assert(BUF_LENGTH(client->replybuf) == 0);
			
			client->failcode = STASH_ERR_USEREXISTS;
		}
	}
}


static void cmdSetPassword(client_t *client, const risp_length_t length, const risp_data_t *data)
{
	risp_t *rdata;
	userid_t uid = NULL_USER_ID;
	char *username = NULL;
	char *password = NULL;
	user_t *user;
	
	assert(client);
	assert(length);
	assert(data);
	
	// make sure that the logged in user has rights to create new users.
	assert(client->user);
	
	// expand the data
	rdata = procRispData(client, length, data);
	assert(rdata);
		
	if (risp_isset(rdata, STASH_CMD_USER_ID)) {
		uid = risp_getvalue(rdata, STASH_CMD_USER_ID);
		assert(uid > 0);
	}
	else if (risp_isset(rdata, STASH_CMD_USERNAME)) {
		username = risp_getstring(rdata, STASH_CMD_USERNAME);
		assert(username);
	}
	assert(uid > 0 || username);
		
	if (risp_isset(rdata, STASH_CMD_PASSWORD)) {
		password = risp_getstring(rdata, STASH_CMD_PASSWORD);
		assert(password);
	}
	
	
	assert(client->replybuf);
	assert(BUF_LENGTH(client->replybuf) == 0);
		
	assert(client->server);
	assert(client->server->control);
	assert(client->server->control->storage);
	user = storage_getuser(client->server->control->storage, uid, username);
		
	if (user == NULL) {
		// we do not have this username... 
		assert(client->user);
		assert(client->replybuf);
		assert(BUF_LENGTH(client->replybuf) == 0);
		
		client->failcode = STASH_ERR_USERNOTEXIST;
	}
	else {
		// we dont have this username in our system, so we can create it.
		assert(client->user);
		assert(client->user->uid > 0);
		assert(user->uid > 0);
		
		// check the rights.
		if (client->user->uid == user->uid || storage_check_rights(client->user, NULL, NULL, STASH_RIGHT_ADDUSER)) {
			storage_set_password(client->server->control->storage, client->user->uid, user->uid, password);
			client->failcode = STASH_ERR_OK;
		}
		else {
			// logged in user does not have right to change password for this user.
			client->failcode = STASH_ERR_INSUFFICIENTRIGHTS;
		}
		
		// there is no reply this time..
		assert(client->replybuf);
		assert(BUF_LENGTH(client->replybuf) == 0);
	}
}

// this operation is used to return an ID to a named object.  It does a number of combinations.
static void cmdGetID(client_t *client, const risp_length_t length, const risp_data_t *data)
{
	risp_t *rdata;
	namespace_t *ns;
	table_t *table;
	skey_t *key;
	user_t *user;
	
	assert(client && length > 0 && data);
	
	// make sure that the logged in user has rights to create new users.
	assert(client->user);

	// expand the data
	rdata = procRispData(client, length, data);
	assert(rdata);

	assert(client->replybuf);
	assert(BUF_LENGTH(client->replybuf) == 0);
	
	if (risp_isset(rdata, STASH_CMD_USERNAME)) {
		assert(client->server);
		assert(client->server->control);
		assert(client->server->control->storage);
		user = storage_getuser(client->server->control->storage, 0, risp_getstring(rdata, STASH_CMD_USERNAME));
		
		if (user == NULL) {
			// namespace doesnt exist.
			assert(client->user);
			assert(client->replybuf);
			assert(BUF_LENGTH(client->replybuf) == 0);
			
			client->failcode = STASH_ERR_USERNOTEXIST;
		}
		else {
			// found the namespace, so now we create the table.
			assert(user->uid > 0);
			
			client->failcode = STASH_ERR_OK;
			
			// create the reply.
			assert(client->replybuf);
			assert(BUF_LENGTH(client->replybuf) == 0);
			rispbuf_addInt(client->replybuf, STASH_CMD_USER_ID, user->uid);
		}
	}
	else if (risp_isset(rdata, STASH_CMD_NAMESPACE)) {
		assert(client->server);
		assert(client->server->control);
		assert(client->server->control->storage);
		ns = storage_getnamespace(client->server->control->storage, 0, risp_getstring(rdata, STASH_CMD_NAMESPACE));
		
		if (ns == NULL) {
			// namespace doesnt exist.
			assert(client->user);
			assert(client->replybuf);
			assert(BUF_LENGTH(client->replybuf) == 0);
			
			client->failcode = STASH_ERR_NSNOTEXIST;
		}
		else {
			// found the namespace, so now we create the table.
			assert(ns->id > 0);
			
			client->failcode = STASH_ERR_OK;
			
			// create the reply.
			assert(client->replybuf);
			assert(BUF_LENGTH(client->replybuf) == 0);
			rispbuf_addInt(client->replybuf, STASH_CMD_NAMESPACE_ID, ns->id);
		}
	}
	else {
		assert(client->replybuf);
		assert(BUF_LENGTH(client->replybuf) == 0);
		
		assert(client->server);
		assert(client->server->control);
		assert(client->server->control->storage);
		assert(risp_isset(rdata, STASH_CMD_NAMESPACE_ID));
		ns = storage_getnamespace(client->server->control->storage, risp_getvalue(rdata, STASH_CMD_NAMESPACE_ID), NULL);
		
		if (ns == NULL) {
			// namespace doesnt exist.
			assert(client->user);
			assert(client->replybuf);
			assert(BUF_LENGTH(client->replybuf) == 0);
			
			client->failcode = STASH_ERR_NSNOTEXIST;
		}
		else {
			// found the namespace, so now we need to lookup the table.
			assert(ns->id > 0);

			if (risp_isset(rdata, STASH_CMD_TABLE)) {
				assert(client->server);
				assert(client->server->control);
				assert(client->server->control->storage);
				table = storage_gettable(client->server->control->storage, ns, 0, risp_getstring(rdata, STASH_CMD_TABLE));
				
				if (table == NULL) {
					// table doesnt exist.
					assert(client->user);
					assert(client->replybuf);
					assert(BUF_LENGTH(client->replybuf) == 0);
					
					client->failcode = STASH_ERR_TABLENOTEXIST;
				}
				else {
					// found the namespace, so now we create the table.
					assert(table->tid > 0);
					
					client->failcode = STASH_ERR_OK;
					
					// create the reply.
					assert(client->replybuf);
					assert(BUF_LENGTH(client->replybuf) == 0);
					rispbuf_addInt(client->replybuf, STASH_CMD_TABLE_ID, table->tid);
				}
			}
			else {
			
				assert(risp_isset(rdata, STASH_CMD_TABLE_ID));
				table = storage_gettable(client->server->control->storage, ns, risp_getvalue(rdata, STASH_CMD_TABLE_ID), NULL);
				if (table == NULL) {
					assert(0);
				}
				else {
				
					if (risp_isset(rdata, STASH_CMD_KEY)) {
						
						key = storage_getkey(table, 0, risp_getstring(rdata, STASH_CMD_KEY));
						if (key == NULL) {
							// key wasn't found.
							
							// if the table is in strict mode, we return an error.  Otherwise we create a key.
							if (table->option_strict == 0) {
								assert(client->user);
								
								if (storage_check_rights(client->user, ns, table, STASH_RIGHT_CREATE)) {
									key = storage_create_key(client->server->control->storage, client->user, table, risp_getstring(rdata, STASH_CMD_KEY));
									assert(key);
								}
							}
						}

						if (key) {
							assert(key->kid > 0);
							client->failcode = STASH_ERR_OK;
							
							// create the reply.
							assert(client->replybuf);
							assert(BUF_LENGTH(client->replybuf) == 0);
							rispbuf_addInt(client->replybuf, STASH_CMD_KEY_ID, key->kid);
						}
						else {
							client->failcode = STASH_ERR_KEYNOTEXIST;
						}
					}
					else {
						assert(0);
					}
				}
			}
		}
	}
}


static void cmdCreateTable(client_t *client, const risp_length_t length, const risp_data_t *data)
{
	risp_t *rdata;
	nsid_t nsid;
	namespace_t *ns;
	char *tablename;
	unsigned short optmap;
	table_t *table;
	
	assert(client && length > 0 && data);
	
	// expand the data
	rdata = procRispData(client, length, data);
	assert(rdata);
		
	assert(risp_isset(rdata, STASH_CMD_NAMESPACE_ID));
	nsid = risp_getvalue(rdata, STASH_CMD_NAMESPACE_ID);
	assert(nsid > 0);

	assert(client->server);
	assert(client->server->control);
	assert(client->server->control->storage);
	ns = storage_getnamespace(client->server->control->storage, nsid, NULL);
	
	if (ns == NULL) {
		// we dont have this namespace.
		assert(client->replybuf);
		assert(BUF_LENGTH(client->replybuf) == 0);
		
		client->failcode = STASH_ERR_NSNOTEXIST;
	}
	else {

		// make sure that the logged in user has rights to create new users.
		assert(client->user);
		if (storage_check_rights(client->user, ns, NULL, STASH_RIGHT_CREATE) == 0) {
			// dont have rights to do this action.
			assert(client->replybuf);
			assert(BUF_LENGTH(client->replybuf) == 0);
			
			client->failcode = STASH_ERR_INSUFFICIENTRIGHTS;
		}
		else {
			
			assert(client->replybuf);
			assert(BUF_LENGTH(client->replybuf) == 0);
			
			assert(risp_isset(rdata, STASH_CMD_TABLE));
			tablename = risp_getstring(rdata, STASH_CMD_TABLE);
			assert(tablename > 0);
			
			optmap = 0;
			if (risp_isset(rdata, STASH_CMD_STRICT)) { optmap |= STASH_TABOPT_STRICT; }
			if (risp_isset(rdata, STASH_CMD_UNIQUE)) { optmap |= STASH_TABOPT_UNIQUE; }
			if (risp_isset(rdata, STASH_CMD_OVERWRITE)) { optmap |= STASH_TABOPT_OVERWRITE; }

	
			// check first that the table name is not already in use within this namespace.
			table = storage_gettable(client->server->control->storage, ns, 0, tablename);
			if (table == NULL) {
				// the table wasn't found, so we should be able to create it.
				assert(client->user);
				assert(client->user->uid > 0);
				table = storage_create_table(client->server->control->storage, client->user, ns, tablename, optmap);
				assert(table);
				assert(table->tid > 0);
					
				client->failcode = STASH_ERR_OK;
				
				if (client->server->control->verbose) {
					assert(ns->name);
					printf("Table '%s' created in namespace '%s'.\n", tablename, ns->name);
				}
				
				// create the reply.
				assert(client->replybuf);
				assert(BUF_LENGTH(client->replybuf) == 0);
				rispbuf_addInt(client->replybuf, STASH_CMD_TABLE_ID, table->tid);
			}
			else {
				// table already exists.
				assert(client->replybuf);
				assert(BUF_LENGTH(client->replybuf) == 0);
				
				client->failcode = STASH_ERR_TABLEEXISTS;
			}
		}
	}
}



static void cmdGrant(client_t *client, const risp_length_t length, const risp_data_t *data)
{
	risp_t *rdata;
	user_t *user = NULL;
	namespace_t *ns = NULL;
	table_t *table = NULL;
	unsigned short optmap;
	storage_t *storage;
	short valid;
	
	assert(client && length > 0 && data);
	
	assert(client->server);
	assert(client->server->control);
	assert(client->server->control->storage);
	storage = client->server->control->storage;
	
	// expand the data
	rdata = procRispData(client, length, data);
	assert(rdata);
	
	if (risp_isset(rdata, STASH_CMD_USER_ID)) {
		user = storage_getuser(storage, risp_getvalue(rdata, STASH_CMD_USER_ID), NULL);
		assert(user);
	}
	else {
		assert(client->user);
		user = client->user;
	}
	
	if (risp_isset(rdata, STASH_CMD_NAMESPACE_ID)) {
		ns = storage_getnamespace(storage, risp_getvalue(rdata, STASH_CMD_NAMESPACE_ID), NULL);
		assert(ns);
	}
	
	if (risp_isset(rdata, STASH_CMD_TABLE_ID)) {
		table = storage_gettable(storage, ns, risp_getvalue(rdata, STASH_CMD_TABLE_ID), NULL);
		assert(table);
	}

	// build the optmap, 
	optmap = 0;
	if (risp_isset(rdata, STASH_CMD_RIGHT_ADDUSER)) optmap |= STASH_RIGHT_ADDUSER;
	if (risp_isset(rdata, STASH_CMD_RIGHT_CREATE))  optmap |= STASH_RIGHT_CREATE;
	if (risp_isset(rdata, STASH_CMD_RIGHT_DROP))    optmap |= STASH_RIGHT_DROP;
	if (risp_isset(rdata, STASH_CMD_RIGHT_SET))     optmap |= STASH_RIGHT_SET;
	if (risp_isset(rdata, STASH_CMD_RIGHT_UPDATE))  optmap |= STASH_RIGHT_UPDATE;
	if (risp_isset(rdata, STASH_CMD_RIGHT_DELETE))  optmap |= STASH_RIGHT_DELETE;
	if (risp_isset(rdata, STASH_CMD_RIGHT_QUERY))   optmap |= STASH_RIGHT_QUERY;
	if (risp_isset(rdata, STASH_CMD_RIGHT_LOCK))    optmap |= STASH_RIGHT_LOCK;
	
	// we need to check that the current user has the right to add this grant.
	// if the user doesnt have this specific right, then we need to see if the user has the right to add it by inferred rights.
	valid = 0;

	// make sure that the logged in user has rights to create new users.
	assert(client->user);
	if (storage_check_rights(client->user, ns, table, optmap)) {
		// this user has this specific set of rights, so they can be granted to others.
		valid = 1;
	}
	else {
		// the user doesn't have those specific rights, but still might have rights to set rights based on other rights they have.
		if (ns && table) {
			// namespace and table were both specified, so check if the user has rightes to CREATE on this table.  If they do, then they can set other rights.
			if (storage_check_rights(client->user, ns, table, STASH_RIGHT_CREATE)) {
				valid = 1;
			}
			else if (storage_check_rights(client->user, ns, NULL, STASH_RIGHT_CREATE)) {
				valid = 1;
			}
		}
		else if (ns) {
			// only a namespace was specified, so we need to check if this user has CREATE rights at a global level.
			if (storage_check_rights(client->user, ns, NULL, STASH_RIGHT_CREATE)) {
				valid = 1;
			}
			else if (storage_check_rights(client->user, NULL, NULL, STASH_RIGHT_CREATE)) {
				valid = 1;
			}
		}
	}


	if (valid == 0) {
		// dont have rights to do this action.
		assert(client->replybuf);
		assert(BUF_LENGTH(client->replybuf) == 0);
		
		client->failcode = STASH_ERR_INSUFFICIENTRIGHTS;
	}
	else {
		storage_grant(storage, client->user->uid, user, ns, table, optmap);
		client->failcode = STASH_ERR_OK;
	}
}





// Since we can receive multiple ATTRIBUTE entries in particular commands, we need to pull out the data, and 
// 		STASH_CMD_ATTRIBUTE <>        [optional]
// 			STASH_CMD_KEY_ID <int32>      [optional]
// 			STASH_CMD_VALUE <>
// 				STASH_CMD_AUTO            [optional]
// 				STASH_CMD_INTEGER <int32> [optional]
// 				STASH_CMD_STRING <str>    [optional]
// 				STASH_CMD_DATETIME <str>  [optional]
// 				STASH_CMD_DATE <int32>    [optional]
// 				STASH_CMD_TIME <int32>    [optional]
// 				STASH_CMD_HASHMAP <>      [optional]
// 					STASH_CMD_ATTRIBUTE <>        [optional]
// 						STASH_CMD_KEY 
// 						STASH_CMD_VALUE <>
// 							...
// 					STASH_CMD_ATTRIBUTE <>        [optional]
// 						STASH_CMD_KEY 
// 						STASH_CMD_VALUE <>
// 							...
// 		STASH_CMD_ATTRIBUTE <>
// 			...
static void cmdAttribute(client_t *client, const risp_length_t length, const risp_data_t *data)
{
	risp_length_t processed;
	raw_attr_t *raw;
	risp_length_t dlen;
	risp_data_t *ddata;
	risp_t *risp_attr = NULL;
	
	
	assert(client && length > 0 && data);
	
	// initialse a new risp object, because we will need to get the values out of the stream.
	assert(client->server);
	assert(client->server->control);
	assert(client->server->control->risp_attr);
	risp_attr = client->server->control->risp_attr;
	
	// process out the values in the risp stream.
	risp_clear_all(risp_attr);
	processed = risp_process(risp_attr, NULL, length, data);
	assert(processed == length);
	
	// we should have these entries.
	assert(risp_isset(risp_attr, STASH_CMD_KEY_ID));
	assert(risp_isset(risp_attr, STASH_CMD_VALUE));
	
	// create a new raw object to hold the data.
	raw = calloc(1, sizeof(*raw));
	assert(raw);
	assert(raw->expires == 0);

	// get the keyid.
	raw->keyid = risp_getvalue(risp_attr, STASH_CMD_KEY_ID);
	assert(raw->keyid > 0);
	
	// parse out the value component.  The value object is complicated because it can contain a lot of data.  Values can contain lists and hashmaps which also need to be stored in it.
	assert(risp_isset(risp_attr, STASH_CMD_VALUE));
	ddata = risp_getdata(risp_attr, STASH_CMD_VALUE);
	dlen = risp_getlength(risp_attr, STASH_CMD_VALUE);
	assert(ddata);
	assert(dlen > 0);
	raw->value = stash_parse_value(ddata, dlen);
	assert(raw->value);

	// if we have an expiry
	if (risp_isset(risp_attr, STASH_CMD_EXPIRES)) {
		// then we need to set the expiry time on the attribute object.
		raw->expires = risp_getvalue(risp_attr, STASH_CMD_EXPIRES);
	}
	
	// add the value to the attrlist.
	assert(client->raw_attrlist);
	ll_push_tail(client->raw_attrlist, raw);
}


static void cmdSet(client_t *client, const risp_length_t length, const risp_data_t *data)
{
	risp_t      *rdata;
	namespace_t *ns;
	table_t     *table;
	storage_t   *storage;
	row_t       *row;
	name_t      *name;
	raw_attr_t  *rawattr;	// attribute received from the client.
	skey_t      *key;
	attr_t      *attr;
	attr_t      *tmp_attr;
	int          expires = 0;
	expbuf_t    *buf_row;
	expbuf_t    *buf_attr;
	expbuf_t    *buf_value;
	int attr_count = 0;
	int autoval;
	
	assert(client && length > 0 && data);
	
	assert(client->raw_attrlist == NULL);
	client->raw_attrlist = ll_init(NULL);
	assert(client->raw_attrlist);
	assert(ll_count(client->raw_attrlist) == 0);
	
	// expand the data
	rdata = procRispData(client, length, data);
	assert(rdata);
	
	// at this point, the risp data has been processed, and we should have at 
	// least one attribute in the list.
	if (ll_count(client->raw_attrlist) <= 0) {
		// need to return an error.
		client->failcode = STASH_ERR_GENERICFAIL;
		return;
	}
	
	// grab the pointer of the storage object for easier use.
	assert(client->server);
	assert(client->server->control);
	assert(client->server->control->storage);
	storage = client->server->control->storage;

	assert(risp_isset(rdata, STASH_CMD_NAMESPACE_ID));
 	ns = storage_getnamespace(storage, risp_getvalue(rdata, STASH_CMD_NAMESPACE_ID), NULL);
	
	if (ns == NULL) {
		// we dont have this namespace.
		client->failcode = STASH_ERR_NSNOTEXIST;
		return;
	}

	assert(ns);
	assert(risp_isset(rdata, STASH_CMD_TABLE_ID));
	table = storage_gettable(storage, ns, risp_getvalue(rdata, STASH_CMD_TABLE_ID), NULL);

	if (table == NULL) {
		// the table doesnt exist.
		client->failcode = STASH_ERR_TABLENOTEXIST;
		return;
	}

	// now that we have ns and table, we need to check that this user has rights to add to this table.
	assert(client->user);
	if (storage_check_rights(client->user, ns, table, STASH_RIGHT_SET) == 0) {
		// dont have rights to do this action.
		client->failcode = STASH_ERR_INSUFFICIENTRIGHTS;
		return;
	}

	// if we are given a rowID, then we need to modify an existing record.
	if (risp_isset(rdata, STASH_CMD_ROW_ID)) {
		row = storage_getrow(storage, table, risp_getvalue(rdata, STASH_CMD_ROW_ID));
		assert(row);
	}
	else {
		// we are not given a rowID, so we need to create a new record.
		row = NULL;
					
		// so now we should have at least a NAME_ID or a NAME.
		name = storage_getname(table, 
								risp_isset(rdata, STASH_CMD_NAME_ID) ? risp_getvalue(rdata, STASH_CMD_NAME_ID) : 0, 
								risp_isset(rdata, STASH_CMD_NAME)    ? risp_getstring(rdata, STASH_CMD_NAME) : NULL);
		if (name && (table->option_unique > 0 && table->option_overwrite == 0)) {
			// the name already exists, and we are not going to overwrite it.  
			// Need to return an error.
			client->failcode = STASH_ERR_NOTUNIQUE;
			return;
		}
		else if (name == NULL && table->option_strict > 0) {
			// we dont have a name.   If we are strict, we need to fail.
			client->failcode = STASH_ERR_NOTSTRICT;
			return;
		}
		else {
						
			if (name == NULL) {
				if (storage_check_rights(client->user, ns, table, STASH_RIGHT_CREATE) == 0) {
					// we need to create a new name, but dont have rights to do that.
					client->failcode = STASH_ERR_INSUFFICIENTRIGHTS;
					return;
				}

				// need to create a new name.
				assert(risp_isset(rdata, STASH_CMD_NAME));
				name = storage_create_name(storage, client->user, table, risp_getstring(rdata, STASH_CMD_NAME), STASH_NAMEOPT_TRANSIENT);
				assert(name);
			}
			
			// table is ok, and we have a name.  so we can accept that.
			assert(name);
		
			// now that we have a name.  If the table is UNIQUE, and OVERWRITE, then we need to get the row from the name object.... if a row exist.
			if (table->option_unique > 0 && ll_count(name->i_rowlist) > 0) {
				if (table->option_overwrite == 0) { 
					// row already exists for this name, and we are not set to over-write.
					client->failcode = STASH_ERR_ROWEXISTS;
					return;
				} 
				else {
					// there is a row already existing, and we need to overwrite it.
					assert(ll_count(name->i_rowlist) == 1);
					row = ll_get_head(name->i_rowlist);
				}
			}
			
			if (risp_isset(rdata, STASH_CMD_EXPIRES)) {
				expires = risp_getvalue(rdata, STASH_CMD_EXPIRES);
			}
			
			
			// create new row with the specified name object.
			if (row == NULL) {
				row = storage_create_row(storage, client->user, table, name, expires);
				assert(row);
			}
			
			assert(row);
		}
	}
			
			
	// at this point, we should have the row that we need to insert the attributes into.
	assert(row);

	buf_row = expbuf_init(NULL, 512);
	assert(row->rid > 0);
	rispbuf_addInt(buf_row, STASH_CMD_ROW_ID, row->rid);
	
	// get the name from the row.  add it to the stream.
	assert(row->name);
	assert(row->name->nid > 0);
	rispbuf_addInt(buf_row, STASH_CMD_NAME_ID, row->name->nid);
	
	buf_attr = expbuf_init(NULL, 512);
	assert(buf_attr);
	
	buf_value = expbuf_init(NULL, 512);
	assert(buf_value);
	
	assert(client->raw_attrlist);
	assert(ll_count(client->raw_attrlist) > 0);
	assert(attr_count == 0);

	// we need to go through each attribute in the list, and if it matches any attribute we already have, then we need to replace it.  If there are no matches, then we need to add it.
	while ((rawattr = ll_pop_head(client->raw_attrlist))) {
	
		assert(rawattr->keyid > 0 && rawattr->value);
		key = storage_getkey(table, rawattr->keyid, NULL);
		assert(key);
		
		// need to ensure that the key doesnt already exist for this row.
		attr = NULL;
		ll_start(row->attrlist);
		while(attr == NULL && (tmp_attr = ll_next(row->attrlist))) {
			if (tmp_attr->key == key) {
				// we have a match where the key already exists for the table.
				// we need to look at the table mode to see what to do here.
				assert(0);
				
				attr = tmp_attr;
			}
		}
		ll_finish(row->attrlist);
		
		// set the attribute.
		if (attr == NULL) {
			assert(rawattr->expires >= 0);

			
			if (rawattr->value->valtype == STASH_VALTYPE_AUTO) {
				autoval = 1;
			}
			else {
				autoval = 0;
			}
			
			attr = storage_setattr(storage, client->user, row, key, rawattr->value, rawattr->expires);
			assert(attr);
			
			if (autoval == 1) {
				assert(BUF_LENGTH(buf_value) == 0);
				assert(attr->value->valtype == STASH_VALTYPE_INT);
				stash_build_value(buf_value, attr->value);
				
				rispbuf_addInt(buf_attr, STASH_CMD_KEY_ID, attr->key->kid);
				rispbuf_addBuffer(buf_attr, STASH_CMD_VALUE, buf_value);
				expbuf_clear(buf_value);
				
				rispbuf_addBuffer(buf_row, STASH_CMD_ATTRIBUTE, buf_attr);
				expbuf_clear(buf_attr);
				
				attr_count ++;
				assert(attr_count > 0);
			}
		}
		else {
			assert(0);
		}
		
		// need to free up the rawattr.
		value_free(rawattr->value);
		free(rawattr);
	}

	// add the attribute count.
	assert(attr_count >= 0);
	rispbuf_addInt(buf_row, STASH_CMD_COUNT, attr_count);

	// add it to the main buffer, as a ROW entry.
	rispbuf_addBuffer(client->replybuf, STASH_CMD_ROW, buf_row);
	buf_row = expbuf_free(buf_row);
	assert(buf_row == NULL);

	rispbuf_addInt(client->replybuf, STASH_CMD_COUNT, 1);
	
	
// 	printf("failcode=%d, buflen=%d\n", client->failcode, BUF_LENGTH(client->replybuf));
	assert((client->failcode == STASH_ERR_OK && BUF_LENGTH(client->replybuf) > 0) || (client->failcode != STASH_ERR_OK && BUF_LENGTH(client->replybuf) == 0));
	
	
	if (client->server->control->verbose) {
		assert(ns->name && table->name);
		printf("SET to '%s:%s'resulted in %d.\n", ns->name, table->name, client->failcode);
	}
}


static void cmdSetExpiry(client_t *client, const risp_length_t length, const risp_data_t *data)
{
	risp_t      *rdata;
	storage_t   *storage;
	namespace_t *ns;
	table_t     *table;
	skey_t      *key;
	attr_t      *attr;
	attr_t      *tmp_attr;
	row_t       *row;
	stash_keyid_t keyid;
	
	assert(client && length > 0 && data);
	
	// expand the data
	rdata = procRispData(client, length, data);
	assert(rdata);
	
	// grab the pointer of the storage object for easier use.
	assert(client->server);
	assert(client->server->control);
	assert(client->server->control->storage);
	storage = client->server->control->storage;
	
	assert(risp_isset(rdata, STASH_CMD_NAMESPACE_ID));
	ns = storage_getnamespace(storage, risp_getvalue(rdata, STASH_CMD_NAMESPACE_ID), NULL);
	if (ns == NULL) {
		// we dont have this namespace.
		client->failcode = STASH_ERR_NSNOTEXIST;
		return;
	}
	
	assert(ns);
	assert(risp_isset(rdata, STASH_CMD_TABLE_ID));
	table = storage_gettable(storage, ns, risp_getvalue(rdata, STASH_CMD_TABLE_ID), NULL);
	if (table == NULL) {
		// the table doesnt exist.
		client->failcode = STASH_ERR_TABLENOTEXIST;
		return;
	}
	
	// now that we have ns and table, we need to check that this user has rights to add to this table.
	assert(client->user);
	if (storage_check_rights(client->user, ns, table, STASH_RIGHT_UPDATE) == 0) {
		// dont have rights to do this action.
		client->failcode = STASH_ERR_INSUFFICIENTRIGHTS;
		return;
	}
	
	// at a minimum, we should be given a rowID
	assert(risp_isset(rdata, STASH_CMD_ROW_ID));
	row = storage_getrow(storage, table, risp_getvalue(rdata, STASH_CMD_ROW_ID));
	assert(row);
	
	// if we were given a key, then we need to get the key object.
	keyid = 0;
	if (risp_isset(rdata, STASH_CMD_KEY_ID)) {
		keyid = risp_getvalue(rdata, STASH_CMD_KEY_ID);
	}
	
	key = NULL;
	if (keyid > 0) {
		assert(table);
		key = storage_getkey(table, keyid, NULL);
		if (key == NULL) {
			// we dont have this namespace.
			client->failcode = STASH_ERR_KEYNOTEXIST;
			return;
		}
	}

	// if we have a key object, then we need to go through the list of 
	// attributes.  If we find one that contains this key, then we will have 
	// an 'attr', otherwise it will be NULL.
	attr = NULL;
	if (key) {
		
		// need to ensure that the key doesnt already exist for this row.
		assert(row);
		assert(row->attrlist);
		ll_start(row->attrlist);
		while(attr == NULL && (tmp_attr = ll_next(row->attrlist))) {
			if (tmp_attr->key == key) {
				attr = tmp_attr;
			}
		}
		ll_finish(row->attrlist);
	}

	assert(client);
	assert(client->user);
	assert(client->user->uid);
	assert(risp_isset(rdata, STASH_CMD_EXPIRES));
	storage_set_expiry(storage, client->user->uid, row, attr, risp_getvalue(rdata, STASH_CMD_EXPIRES));

	assert(client->failcode == STASH_ERR_OK || (client->failcode != STASH_ERR_OK && BUF_LENGTH(client->replybuf) == 0));
}


static void cmdDelete(client_t *client, const risp_length_t length, const risp_data_t *data)
{
	risp_t      *rdata;
	storage_t   *storage;
	namespace_t *ns;
	table_t     *table;
	skey_t      *key;
	row_t       *row;
	stash_keyid_t keyid;
	
	assert(client && length > 0 && data);
	
	
	printf("Received DELETE cmd\n");
	
	// expand the data
	rdata = procRispData(client, length, data);
	assert(rdata);
	
	// grab the pointer of the storage object for easier use.
	assert(client->server);
	assert(client->server->control);
	assert(client->server->control->storage);
	storage = client->server->control->storage;
	
	assert(risp_isset(rdata, STASH_CMD_NAMESPACE_ID));
	ns = storage_getnamespace(storage, risp_getvalue(rdata, STASH_CMD_NAMESPACE_ID), NULL);
	if (ns == NULL) {
		// we dont have this namespace.
		client->failcode = STASH_ERR_NSNOTEXIST;
		return;
	}
	
	assert(ns);
	assert(risp_isset(rdata, STASH_CMD_TABLE_ID));
	table = storage_gettable(storage, ns, risp_getvalue(rdata, STASH_CMD_TABLE_ID), NULL);
	if (table == NULL) {
		// the table doesnt exist.
		client->failcode = STASH_ERR_TABLENOTEXIST;
		return;
	}
	
	// now that we have ns and table, we need to check that this user has rights to add to this table.
	assert(client->user);
	if (storage_check_rights(client->user, ns, table, STASH_RIGHT_DELETE) == 0) {
		// dont have rights to do this action.
		client->failcode = STASH_ERR_INSUFFICIENTRIGHTS;
		return;
	}
	
	// at a minimum, we should be given a rowID
	assert(risp_isset(rdata, STASH_CMD_ROW_ID));
	row = storage_getrow(storage, table, risp_getvalue(rdata, STASH_CMD_ROW_ID));
	assert(row);
	
	// if we were given a key, then we need to get the key object.
	keyid = 0;
	if (risp_isset(rdata, STASH_CMD_KEY_ID)) {
		keyid = risp_getvalue(rdata, STASH_CMD_KEY_ID);
	}
	
	key = NULL;
	if (keyid > 0) {
		
		// if we have a keyid, then obviously we are only wanting to delete one 
		// attribute from the row.  We need to find the attribute and delete it.
		
		assert(table);
		key = storage_getkey(table, keyid, NULL);
		if (key == NULL) {
			// we dont have this namespace.
			client->failcode = STASH_ERR_KEYNOTEXIST;
			return;
		}
	}

	assert(client);
	assert(client->user);
	assert(client->user->uid > 0);
	storage_delete(storage, client->user, row, key);
	
	assert(client->failcode == STASH_ERR_OK || (client->failcode != STASH_ERR_OK && BUF_LENGTH(client->replybuf) == 0));
}




static stash_cond_t * parse_condition(table_t *table, const risp_length_t length, const risp_data_t *data)
{
	risp_t *risp;
	risp_t *risp_data;
	risp_length_t processed;
	stash_cond_t *cond = NULL; 
	int len;
	risp_data_t *tmp;
	
	assert(table && length > 0 && data);
	
	// create the risp object.
	risp = risp_init(NULL);  
	risp_data = risp_init(NULL);
	assert(risp && risp_data);
	
	cond = calloc(1, sizeof(*cond));
	assert(cond);
	
	// parse the data into the risp object.
	processed = risp_process(risp, NULL, length, data);
	assert(processed == length);

	if (risp_isset(risp, STASH_CMD_COND_EQUALS)) {
		cond->condtype = STASH_CONDTYPE_EQUALS;
		
		len = risp_getlength(risp, STASH_CMD_COND_EQUALS);
		processed = risp_process(risp_data, NULL, len, risp_getdata(risp, STASH_CMD_COND_EQUALS));
		assert(processed == len);
		
		assert(risp_isset(risp_data, STASH_CMD_KEY_ID));
		cond->kid = risp_getvalue(risp_data, STASH_CMD_KEY_ID);
		
		cond->key_ptr = storage_getkey(table, cond->kid, NULL);
		assert(cond->key_ptr);
		
		assert(risp_isset(risp_data, STASH_CMD_VALUE));
		cond->value = stash_parse_value(risp_getdata(risp_data, STASH_CMD_VALUE), risp_getlength(risp_data, STASH_CMD_VALUE));
		assert(cond->value);
	}
	else if (risp_isset(risp, STASH_CMD_COND_NAME)) {
		cond->condtype = STASH_CONDTYPE_NAME;
		
		len = risp_getlength(risp, STASH_CMD_COND_NAME);
		processed = risp_process(risp_data, NULL, len, risp_getdata(risp, STASH_CMD_COND_NAME));
		assert(processed == len);

		assert(cond->nameid == 0);
		assert(cond->name == NULL);
		assert(cond->name_ptr == NULL);
		if (risp_isset(risp_data, STASH_CMD_NAME_ID)) {
			cond->name_ptr = storage_getname(table, risp_getvalue(risp_data, STASH_CMD_NAME_ID), NULL);
		}
		else if (risp_isset(risp_data, STASH_CMD_NAME)) {
			cond->name_ptr = storage_getname(table, 0, risp_getstring(risp_data, STASH_CMD_NAME));
		}
	}
	else if (risp_isset(risp, STASH_CMD_COND_AND) || risp_isset(risp, STASH_CMD_COND_OR)) {
		
		// processing AND and OR is almost identicle except that the source is different.
		
		if (risp_isset(risp, STASH_CMD_COND_AND)) {
			cond->condtype = STASH_CONDTYPE_AND;
			len = risp_getlength(risp, STASH_CMD_COND_AND);
			tmp = risp_getdata(risp, STASH_CMD_COND_AND);
		}
		else {
			cond->condtype = STASH_CONDTYPE_OR;
			len = risp_getlength(risp, STASH_CMD_COND_OR);
			tmp = risp_getdata(risp, STASH_CMD_COND_OR);
		}
		assert(len > 0 && tmp);
		processed = risp_process(risp_data, NULL, len, tmp);
		assert(processed == len);
		
		// now we should get out STASH_CMD_COND_A and STASH_CMD_COND_B.  We recursively parse out those buffers and create conditions for them.
		assert(cond->ca == NULL);
		assert(cond->cb == NULL);
		assert(risp_isset(risp_data, STASH_CMD_COND_A));
		assert(risp_isset(risp_data, STASH_CMD_COND_B));
		
		cond->ca = parse_condition(table, risp_getlength(risp_data, STASH_CMD_COND_A), risp_getdata(risp_data, STASH_CMD_COND_A));
		cond->cb = parse_condition(table, risp_getlength(risp_data, STASH_CMD_COND_B), risp_getdata(risp_data, STASH_CMD_COND_B));
		assert(cond->ca);
		assert(cond->cb);
	}
	else if (risp_isset(risp, STASH_CMD_COND_NOT)) {
		cond->condtype = STASH_CONDTYPE_NOT;
		cond->ca = parse_condition(table, risp_getlength(risp, STASH_CMD_COND_NOT), risp_getdata(risp, STASH_CMD_COND_NOT));
		cond->cb = NULL;
	}
	else if (risp_isset(risp, STASH_CMD_COND_EXISTS)) {
		cond->condtype = STASH_CONDTYPE_EXISTS;
		
		len = risp_getlength(risp, STASH_CMD_COND_EQUALS);
		processed = risp_process(risp_data, NULL, len, risp_getdata(risp, STASH_CMD_COND_EQUALS));
		assert(processed == len);
		
		assert(risp_isset(risp_data, STASH_CMD_KEY_ID));
		cond->kid = risp_getvalue(risp_data, STASH_CMD_KEY_ID);
		
		cond->key_ptr = storage_getkey(table, cond->kid, NULL);
		// if key_ptr is NULL at this point, then the key doesnt exist.
		
		assert(risp_isset(risp_data, STASH_CMD_VALUE) == 0);
		assert(cond->value == NULL);
	}
	else {
		// got some other condition we dont handle yet, but should.
		assert(0);
	}
	
	risp_data = risp_shutdown(risp_data);
	assert(risp_data == NULL);
	
	risp = risp_shutdown(risp);
	assert(risp == NULL);
	
	return(cond);
}



static void cmdQuery(client_t *client, const risp_length_t length, const risp_data_t *data)
{
	risp_t *rdata;
	namespace_t *ns;
	table_t *table;
// 	skey_t *key;
	stash_cond_t *condition;
	list_t *rows;
	row_t *row;
	attr_t *attr;
	expbuf_t *buf_value;
	expbuf_t *buf_attr;
	expbuf_t *buf_row;
	struct timeval tv;
	int currtime;
	int row_count;
	int attr_count;
	
	
	assert(client && length && data);
	assert(client->user);
	assert(client->server);
	assert(client->server->control);
	assert(client->server->control->storage);
	
	// expand the data
	rdata = procRispData(client, length, data);
	assert(rdata);
	
	assert(client->replybuf);
	assert(BUF_LENGTH(client->replybuf) == 0);

	gettimeofday(&tv, NULL);
	currtime = tv.tv_sec;
	
	assert(risp_isset(rdata, STASH_CMD_NAMESPACE_ID));
	ns = storage_getnamespace(client->server->control->storage, risp_getvalue(rdata, STASH_CMD_NAMESPACE_ID), NULL);
	if (ns == NULL) {
		// namespace doesnt exist.
		assert(client->user);
		assert(client->replybuf);
		assert(BUF_LENGTH(client->replybuf) == 0);
		
		client->failcode = STASH_ERR_NSNOTEXIST;
	}
	else {
		// found the namespace, so now we look for the table.
		assert(ns->id > 0);
		
		assert(risp_isset(rdata, STASH_CMD_TABLE_ID));
		table = storage_gettable(client->server->control->storage, ns, risp_getvalue(rdata, STASH_CMD_TABLE_ID), NULL);
		if (table == NULL) {
			assert(0);
		}
		else {
			
			// check user rights.
			if (storage_check_rights(client->user, ns, table, STASH_RIGHT_QUERY) == 0) {
				// we need to create a new name, but dont have rights to do that.
				client->failcode = STASH_ERR_INSUFFICIENTRIGHTS;
			}
			else {

				if (risp_isset(rdata, STASH_CMD_CONDITION)) {
					condition = parse_condition(table, risp_getlength(rdata, STASH_CMD_CONDITION), risp_getdata(rdata, STASH_CMD_CONDITION));
					assert(condition);
				}
				else {
					condition = NULL;
				}
				
				// how can we best determine which entries to include?  If we dont have a condition, then return everything.
				// PERF:  This will be really bad performance.  IT should really look at the keys in the condition structure to determine which one to look at first.  It should be one that is in an EQUALS inside an AND or by itself. 
				// for now though, we will simply iterate through every row in the table, and return the rows that match all the conditions.
					
					
				// to do this, we will need to use the storage engine.  
				
				// We provide the namespace and the table, and the 
				// condition, and it will return a list of pointers.  
				// Each pointer will point to a row.  We will use another 
				// function to get the appropriate keys out of the rows, 
				// and return them.
				rows = storage_query(client->server->control->storage, table, condition);
				assert(rows);
				
				assert(client->replybuf);
				assert(BUF_LENGTH(client->replybuf) == 0);
				
				buf_value = expbuf_init(NULL, 0);
				buf_attr = expbuf_init(NULL, 0);
				buf_row = expbuf_init(NULL, 0);
				
				
				row_count = 0;
				while((row = ll_pop_head(rows))) {
					assert(row->table == table);
					assert(row->rid > 0);
					
					// if the row hasn't expired.
					// TODO: if the row has expired... should we clean it up now?
					if (row->expires == 0 || row->expires > currtime) {
						row_count ++;
						
						rispbuf_addInt(buf_row, STASH_CMD_ROW_ID, row->rid);
						
						// get the name from the row.  add it to the stream.
						assert(row->name);
						assert(row->name->nid > 0);
						rispbuf_addInt(buf_row, STASH_CMD_NAME_ID, row->name->nid);
						
						assert(buf_attr);
						assert(BUF_LENGTH(buf_attr) == 0);
						
						// for each attribute in the row, we need to create a 
						attr_count = 0;
						assert(row->attrlist);
						ll_start(row->attrlist);
						while ((attr = ll_next(row->attrlist))) {
							assert(attr->row == row);
							assert(attr->key);
							assert(attr->key->kid > 0);
							assert(attr->value);

							if (attr->expires == 0 || attr->expires > currtime) {
								attr_count ++;
								
								stash_build_value(buf_value, attr->value);
								
								rispbuf_addInt(buf_attr, STASH_CMD_KEY_ID, attr->key->kid);
								rispbuf_addBuffer(buf_attr, STASH_CMD_VALUE, buf_value);
								expbuf_clear(buf_value);
								
								rispbuf_addBuffer(buf_row, STASH_CMD_ATTRIBUTE, buf_attr);
								expbuf_clear(buf_attr);
								
							}
						}

						// add the attribute count.
						assert(attr_count >= 0);
						rispbuf_addInt(buf_row, STASH_CMD_COUNT, attr_count);

						// add it to the main buffer, as a ROW entry.
						rispbuf_addBuffer(client->replybuf, STASH_CMD_ROW, buf_row);
						expbuf_clear(buf_row);
					}
				}
				
				assert(row_count >= 0);
				rispbuf_addInt(client->replybuf, STASH_CMD_COUNT, row_count);
				
				
				buf_value = expbuf_free(buf_value); assert(buf_value == NULL);
				buf_attr = expbuf_free(buf_attr); assert(buf_attr == NULL);
				buf_row = expbuf_free(buf_row); assert(buf_row == NULL);;
				
				
				assert(BUF_LENGTH(client->replybuf) > 0);
				client->failcode = STASH_ERR_OK;
			}
		}
	}
}



// This function is called when data is available on the socket.  We need to 
// read the data from the socket, and process as much of it as we can.  We 
// need to remember that we might possibly have leftover data from previous 
// reads, so we will need to append the new data in that case.
static void read_handler(int fd, short int flags, void *arg)
{
	client_t *client = (client_t *) arg;
	int res;
	control_t *control;
	// 	int done;
	risp_length_t processed;
	expbuf_t *buf;
	
	assert(fd >= 0);
	assert(flags != 0);
	assert(client);
	assert(client->handle == fd);
	
	assert(client->server);
	assert(client->server->control);
	control = client->server->control;
	
	printf("received read event, about to recv data on socket:%d\n", fd);
	
	// read data from the socket.
	assert(control->readbuf);
	assert(BUF_LENGTH(control->readbuf) == 0 && BUF_MAX(control->readbuf) > 0 && BUF_DATA(control->readbuf) != NULL);
	res = read(fd, BUF_DATA(control->readbuf), BUF_MAX(control->readbuf));
	if (res > 0) {
		
		printf("received %d bytes from socket:%d\n", res, fd);
		
		// got some data.
		assert(res <= BUF_MAX(control->readbuf));
		BUF_LENGTH(control->readbuf) = res;
		
		// if we got the max of the buffer, then we should increase the size of the buffer.
		if (res == BUF_MAX(control->readbuf)) {
			expbuf_shrink(control->readbuf, DEFAULT_BUFSIZE);	// give the buffer some extra kb.
			assert(BUF_MAX(control->readbuf) > BUF_LENGTH(control->readbuf));
		}
		
		assert(client->pending);
		if (BUF_LENGTH(client->pending) > 0) {
			expbuf_add(client->pending, BUF_DATA(control->readbuf), BUF_LENGTH(control->readbuf));
			expbuf_clear(control->readbuf);
			buf = client->pending;
		}
		else {
			buf = control->readbuf;
		}
		
		// process the data received, and remove what was processed, from the buffer.
		assert(control->risp);
		processed = risp_process(control->risp, client, BUF_LENGTH(buf), BUF_DATA(buf));
		if (processed > 0) {
			expbuf_purge(buf, processed);
		}
		
		if (BUF_LENGTH(control->readbuf) > 0) {
			expbuf_add(client->pending, BUF_DATA(control->readbuf), BUF_LENGTH(control->readbuf));
			expbuf_clear(control->readbuf);
		}
	}
	else {
		// the connection was closed, or there was an error.
		printf("socket %d closed. res=%d, errno=%d,'%s'\n", fd, res, errno, strerror(errno));
		
		// free the client resources.
		client_free(client);
		client = NULL;
	}
	
	assert(control);
	assert(control->readbuf);
	assert(BUF_LENGTH(control->readbuf) == 0);
}




//-----------------------------------------------------------------------------
// print some info to the user, so that they can know what the parameters do.
static void usage(void) {
	printf(PACKAGE " " VERSION "\n");
	printf("-l <ip_addr:port>  interface to listen on, default is INDRR_ANY\n");
	printf("-c <num>           max simultaneous connections, default is 1024\n");
	printf("-b <path>          storage path\n");
	printf("\n");
	printf("-d                 run as a daemon\n");
	printf("-P <file>          save PID in <file>, only used with -d option\n");
	printf("-u <username>      assume identity of <username> (only when run as root)\n");
	printf("\n");
	printf("-v                 verbose (print errors/warnings while in event loop)\n");
	printf("-h                 print this help and exit\n");
	return;
}



static void parse_params(control_t *control, int argc, char **argv)
{
	int c;
	
	assert(control);
	assert(argc >= 0);
	assert(argv);
	
	// process arguments
	/// Need to check the options in here, there're possibly ones that we dont need.
	while ((c = getopt(argc, argv, "c:hvd:u:P:l:b:")) != -1) {
		switch (c) {
			case 'c':
				control->maxconns = atoi(optarg);
				assert(control->maxconns > 0);
				break;
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'v':
				control->verbose++;
				break;
			case 'd':
				assert(control->daemonize == 0);
				control->daemonize = 1;
				break;
			case 'b':
				assert(control->storepath == NULL);
				control->storepath = optarg;
				assert(control->storepath != NULL);
				assert(control->storepath[0] != '\0');
				break;
			case 'u':
				assert(control->username == NULL);
				control->username = optarg;
				assert(control->username != NULL);
				assert(control->username[0] != 0);
				break;
			case 'P':
				assert(control->pid_file == NULL);
				control->pid_file = optarg;
				assert(control->pid_file != NULL);
				assert(control->pid_file[0] != 0);
				break;
			case 'l':
				assert(control->interfaces == NULL);
				control->interfaces = strdup(optarg);
				assert(control->interfaces != NULL);
				assert(control->interfaces[0] != 0);
				break;
				
			default:
				fprintf(stderr, "Illegal argument \"%c\"\n", c);
				return;
				
		}
	}
}


void daemonize(const char *username, const char *pidfile, const int noclose)
{
	struct passwd *pw;
	struct sigaction sa;
	int fd;
	FILE *fp;
	
	if (username != NULL) {
		assert(username[0] != '\0');
		if (getuid() == 0 || geteuid() == 0) {
			if (username == 0 || *username == '\0') {
				fprintf(stderr, "can't run as root without the -u switch\n");
				exit(EXIT_FAILURE);
			}
			pw = getpwnam((const char *)username);
			if (pw == NULL) {
				fprintf(stderr, "can't find the user %s to switch to\n", username);
				exit(EXIT_FAILURE);
			}
			if (setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
				fprintf(stderr, "failed to assume identity of user %s\n", username);
				exit(EXIT_FAILURE);
			}
		}
	}
	
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	if (sigemptyset(&sa.sa_mask) == -1 || sigaction(SIGPIPE, &sa, 0) == -1) {
		perror("failed to ignore SIGPIPE; sigaction");
		exit(EXIT_FAILURE);
	}
	
	switch (fork()) {
		case -1:
			exit(EXIT_FAILURE);
		case 0:
			break;
		default:
			_exit(EXIT_SUCCESS);
	}
	
	if (setsid() == -1)
		exit(EXIT_FAILURE);
	
	(void)chdir("/");
	
	if (noclose == 0 && (fd = open("/dev/null", O_RDWR, 0)) != -1) {
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		if (fd > STDERR_FILENO)
			(void)close(fd);
	}
	
	// save the PID in if we're a daemon, do this after thread_init due to a
	// file descriptor handling bug somewhere in libevent
	if (pidfile != NULL) {
		if ((fp = fopen(pidfile, "w")) == NULL) {
			fprintf(stderr, "Could not open the pid file %s for writing\n", pidfile);
			exit(EXIT_FAILURE);
		}
		
		fprintf(fp,"%ld\n", (long)getpid());
		if (fclose(fp) == -1) {
			fprintf(stderr, "Could not close the pid file %s.\n", pidfile);
			exit(EXIT_FAILURE);
		}
	}
}



//-----------------------------------------------------------------------------
// Main... process command line parameters, and then setup our listening 
// sockets and event loop.
int main(int argc, char **argv) 
{
	control_t *control  = NULL;
	struct timeval time_start, time_stop;

///============================================================================
/// Initialization.
///============================================================================

	// create the 'control' object that will be passed to all the handlers so
	// that they have access to the information that they require.
	control = malloc(sizeof(*control));
	control_init(control);

	parse_params(control, argc, argv);
	
	if (control->storepath == NULL) {
		fprintf(stderr, "stashd requires -b parameter.\n");
		exit(1);
	}
	
	// daemonize
	if (control->daemonize) {
		assert(0);	// not completed, apparently.
// 		daemonize(control->username, control->pid_file, control->verbose);
	}
	
	// create our event base which will be the pivot point for pretty much everything.
	assert(control);
	#ifndef LIBEVENT_OLD_VER
		assert(event_get_version_number() == LIBEVENT_VERSION_NUMBER);
	#endif
	control->evbase = event_base_new();
	assert(control->evbase);

	// initialise signal handlers.
	assert(control);
	assert(control->evbase);
	control->sigint_event = evsignal_new(control->evbase, SIGINT, sigint_handler, control);
// 	control->sighup_event = evsignal_new(control->evbase, SIGHUP, sighup_handler, control);
	assert(control->sigint_event);
// 	assert(control->sighup_event);
	event_add(control->sigint_event, NULL);
// 	event_add(control->sighup_event, NULL);
	
	

	assert(control);
	assert(control->risp == NULL);
	control->risp = risp_init(NULL);
	assert(control->risp != NULL);
	risp_add_command(control->risp, STASH_CMD_REQUEST,     &cmdRequest);

	assert(control);
	assert(control->risp_req == NULL);
	control->risp_req = risp_init(NULL);
	assert(control->risp_req != NULL);
	risp_add_command(control->risp_req, STASH_CMD_REQUEST_ID,   &cmdRequestID);
	risp_add_command(control->risp_req, STASH_CMD_LOGIN,        &cmdLogin);
	risp_add_command(control->risp_req, STASH_CMD_CREATE_USER,  &cmdCreateUser);
	risp_add_command(control->risp_req, STASH_CMD_SET_PASSWORD, &cmdSetPassword);
	risp_add_command(control->risp_req, STASH_CMD_GETID,        &cmdGetID);
	risp_add_command(control->risp_req, STASH_CMD_CREATE_TABLE, &cmdCreateTable);
	risp_add_command(control->risp_req, STASH_CMD_SET,          &cmdSet);
	risp_add_command(control->risp_req, STASH_CMD_SET_EXPIRY,   &cmdSetExpiry);
	risp_add_command(control->risp_req, STASH_CMD_GRANT,        &cmdGrant);
	risp_add_command(control->risp_req, STASH_CMD_QUERY,        &cmdQuery);
	risp_add_command(control->risp_req, STASH_CMD_DELETE,       &cmdDelete);
	
	assert(control);
	assert(control->risp_data == NULL);
	control->risp_data = risp_init(NULL);
	assert(control->risp_data);
	risp_add_command(control->risp_data, STASH_CMD_ATTRIBUTE,   &cmdAttribute);
	
	assert(control->risp_attr == NULL);
	control->risp_attr = risp_init(NULL);
	assert(control->risp_attr);
	
	
	
	// load the data from the specified data directory. 
	gettimeofday(&time_start, NULL);
	control->storage = storage_init(NULL);
	assert(control->storage);
	assert(control->storepath);
	storage_lock_master(control->storage, control->storepath);
	storage_process(control->storage, control->storepath, KEEP_OPEN, LOAD_DATA);
	gettimeofday(&time_stop, NULL);
	if (control->verbose > 0) { printf("Stored data loaded in %d seconds.\n", (int) (time_stop.tv_sec - time_start.tv_sec)); }

	// if we are using libevent2.0 or higher, then we can add an evbase to the storage engine so that it can set timers.
	// older libevents have not been coded for...
#ifndef LIBEVENT_OLD_VER
	assert(control);
	assert(control->storage);
	assert(control->evbase);
	storage_set_evbase(control->storage, control->evbase);
#endif
	
	// initialise the servers that we listen on.
	init_servers(control);
	

///============================================================================
/// Main Event Loop.
///============================================================================

	// enter the processing loop.  This function will not return until there is
	// nothing more to do and the service has shutdown.  Therefore everything
	// needs to be setup and running before this point.  Once inside the
	// rq_process function, everything is initiated by the RQ event system.
	assert(control);
	if (control->verbose > 0) { printf("Starting main loop.\n"); }
	assert(control->evbase);
	event_base_dispatch(control->evbase);

///============================================================================
/// Shutdown
///============================================================================

	assert(control);
	if (control->verbose > 0) { printf("Freeing the event base.\n"); }
	assert(control->evbase);
	event_base_free(control->evbase);
	control->evbase = NULL;

	// cleanup the servers objects.
	if (control->verbose > 0) { printf("Cleaning up servers.\n"); }
	cleanup_servers(control);

	// make sure signal handlers have been cleared.
	assert(control);
	assert(control->sigint_event == NULL);
	assert(control->sighup_event == NULL);

	assert(control);
	if (control->verbose > 0) { printf("Shutting down RISP.\n"); }
	
	assert(control->risp);
	control->risp = risp_shutdown(control->risp);
	assert(control->risp == NULL);
	
	assert(control->risp_req);
	control->risp_req = risp_shutdown(control->risp_req);
	assert(control->risp_req == NULL);
	
	assert(control->risp_data);
	control->risp_data = risp_shutdown(control->risp_data);
	assert(control->risp_data == NULL);

	assert(control->risp_attr);
	control->risp_attr = risp_shutdown(control->risp_attr);
	assert(control->risp_attr == NULL);
	
	
	// cleanup the storage 
	assert(control);
	if (control->verbose > 0) { printf("Shutting down storage engine.\n"); }
	assert(control->storage);
	assert(control->storepath);
	storage_unlock_master(control->storage, control->storepath);
	storage_free(control->storage);
	control->storage = NULL;		
	
	
	// we are done, cleanup what is left in the control structure.
	if (control->verbose > 0) { printf("Final cleanup.\n"); }
	
	control_cleanup(control);
	free(control);

	return 0;
}



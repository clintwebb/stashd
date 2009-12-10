//-----------------------------------------------------------------------------
// stashd
//	Enhanced hash-map storage database.
//-----------------------------------------------------------------------------


// includes
#include <assert.h>
#include <errno.h>
#include <event.h>
#include <event2/listener.h>
#include <expbuf.h>
#include <linklist.h>
#include <netdb.h>
#include <risp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>



#define PACKAGE						"stashd"
#define VERSION						"0.10"


#define DEFAULT_BUFSIZE	4096
#define INVALID_HANDLE -1

typedef struct {
	// event base for listening on the sockets, and timeout events.
	struct event_base *evbase;

	// risp object to process a RISP stream.  This can be from the network or from the disk.   THe stream protocol should be compatible even though they would be handled differently.
	risp_t *risp;
	
	// linked list of listening sockets.
	list_t *servers;

	// generic read buffer for reading from the socket or from the file.  It should always be empty, and anything left after processing should be put in a pending buffer.
	expbuf_t *readbuf;

	// number of connections that we are currently listening for activity from.
	int conncount;
	
	// startup settings.
	char *interfaces;
	int maxconns;
	int verbose;
	int daemonize;
	char *storepath;
	char *username;
	char *pid_file;

	struct event *sigint_event;
	struct event *sighup_event;

} control_t;


typedef struct {
	struct evconnlistener *listener;
	list_t *clients;
	control_t *control;
} server_t;


typedef struct {
	evutil_socket_t handle;
	struct event *read_event;
	struct event *write_event;
	server_t *server;
	expbuf_t *pending;
	expbuf_t *outbuffer;
 	int out_sent;
	
	// returned data.
	expbuf_t *filedata;
	expbuf_t *content_type;
} client_t;



//-----------------------------------------------------------------------------
// Pre-declare our handlers, because often they need to interact with functions
// that are used to invoke them.
static void accept_conn_cb(struct evconnlistener *listener, evutil_socket_t fd, struct sockaddr *address, int socklen, void *ctx);
static void read_handler(int fd, short int flags, void *arg);
static void write_handler(int fd, short int flags, void *arg);


//-----------------------------------------------------------------------------
// Create and init our controller object.   The  control object will have
// everything in it that is needed to run this server.  It is in this object
// because we need to pass a pointer to the handler that will be doing the work.
static void init_control(control_t *control)
{
	assert(control != NULL);

	control->evbase = NULL;
	control->sigint_event = NULL;
	control->sighup_event = NULL;
	control->conncount = 0;
	control->interfaces = NULL;
	control->maxconns = 1024;
	control->risp = NULL;
	control->verbose = 0;
	control->daemonize = 0;
	control->storepath = NULL;
	control->username = NULL;
	control->pid_file = NULL;
	
	control->readbuf = (expbuf_t *) malloc(sizeof(expbuf_t));
	expbuf_init(control->readbuf, DEFAULT_BUFSIZE);
}

static void cleanup_control(control_t *control)
{
	assert(control != NULL);

	assert(control->readbuf);
	expbuf_free(control->readbuf);
	free(control->readbuf);
	control->readbuf = NULL;

	control->interfaces = NULL;
	control->storepath = NULL;
	control->username = NULL;
	control->pid_file = NULL;
	
	assert(control->risp == NULL);
	assert(control->conncount == 0);
	assert(control->sigint_event == NULL);
	assert(control->sighup_event == NULL);
	assert(control->evbase == NULL);
}


//-----------------------------------------------------------------------------
// Initialise the server object.
static void server_init(server_t *server, control_t *control)
{
	assert(server);
	assert(control);

	server->control = control;

	assert(control->maxconns > 0);
	assert(control->conncount == 0);

	server->clients = (list_t *) malloc(sizeof(list_t));
	ll_init(server->clients);
}


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
	
	
	control->servers = (list_t *) malloc(sizeof(list_t));
	ll_init(control->servers);

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
				server = (server_t *) malloc(sizeof(server_t));
				server_init(server, control);
				ll_push_head(control->servers, server);
		
				server_listen(server, argument);
			}
		}
	}
	
	free(copy);
}


//-----------------------------------------------------------------------------
// Cleanup the server object.
static void server_free(server_t *server)
{
	assert(server);

	assert(server->clients);
	assert(ll_count(server->clients) == 0);
	ll_free(server->clients);
	free(server->clients);
	server->clients = NULL;

	if (server->listener) {
		evconnlistener_free(server->listener);
		server->listener = NULL;
	}

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

	ll_free(control->servers);
	free(control->servers);
	control->servers = NULL;
}








//-----------------------------------------------------------------------------
// Initialise the client structure.
static void client_init (
	client_t *client,
	server_t *server,
	evutil_socket_t handle,
	struct sockaddr *address,
	int socklen)
{
	assert(client);
	assert(server);

	assert(handle > 0);
	client->handle = handle;
	
	fprintf(stderr, "New client - handle=%d\n", handle);
	
	client->read_event = NULL;
	client->write_event = NULL;
	client->server = server;

	// add the client to the list for the server.
	assert(server->clients);
	ll_push_tail(server->clients, client);


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
	event_add(client->read_event, NULL);

	client->outbuffer = NULL;
	client->out_sent = 0;
}


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
	client = (client_t *) malloc(sizeof(client_t));
	client_init(client, server, fd, address, socklen);
}




//-----------------------------------------------------------------------------
static void sigint_handler(evutil_socket_t fd, short what, void *arg)
{
 	control_t *control = (control_t *) arg;

	// need to initiate an RQ shutdown.
	assert(control);
	
	// need to send a message to each node telling them that we are shutting down.
	assert(0);

	// delete the signal events.
	assert(control->sigint_event);
	event_free(control->sigint_event);
	control->sigint_event = NULL;

	assert(control->sighup_event);
	event_free(control->sighup_event);
	control->sighup_event = NULL;
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
// Free the resources used by the client object.
static void client_free(client_t *client)
{
	assert(client);

	fprintf(stderr, "client_free: handle=%d\n", client->handle);

	if (client->outbuffer) {
		expbuf_clear(client->outbuffer);
		expbuf_free(client->outbuffer);
		free(client->outbuffer);
		client->outbuffer = NULL;
		client->out_sent = 0;
	}
	assert(client->out_sent == 0);
		
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

	client->server = NULL;
}




static void cmdInvalid(void *ptr, void *data, risp_length_t len)
{
	// this callback is called if we have an invalid command.  We shouldn't be receiving any invalid commands.
	unsigned char *cast;

	assert(ptr != NULL);
	assert(data != NULL);
	assert(len > 0);
	
	cast = (unsigned char *) data;
	printf("Received invalid (%d)): [%d, %d, %d]\n", len, cast[0], cast[1], cast[2]);
	assert(0);
}


static void cmdClear(client_t *client) {
	assert(client);

	if (client->filedata) {
		expbuf_clear(client->filedata);
		expbuf_free(client->filedata);
		free(client->filedata);
		client->filedata = NULL;
	}
	assert(client->filedata == NULL);
}



//-----------------------------------------------------------------------------
// when the write event fires, we will try to write everything to the socket.
// If everything has been sent, then we will remove the write_event, and the
// outbuffer.
static void write_handler(int fd, short int flags, void *arg)
{
	client_t *client;
	int res;
	int length;
	
	assert(fd > 0);
	assert(arg);

	client = arg;

	assert(client->write_event);
	assert(client->outbuffer);
	assert(client->out_sent < BUF_LENGTH(client->outbuffer));

	length = BUF_LENGTH(client->outbuffer) - client->out_sent;

	if (client->server->control->verbose > 1) 
		fprintf(stderr, "write_handler: length=%d, sent=%d, tosend=%d\n", BUF_LENGTH(client->outbuffer), client->out_sent, length);
	
	res = send(client->handle, BUF_DATA(client->outbuffer)+client->out_sent, length, 0);
	if (res > 0) {
		assert(res <= length);
		client->out_sent += res;

		assert(client->out_sent <= BUF_LENGTH(client->outbuffer));
		if (client->out_sent == BUF_LENGTH(client->outbuffer)) {
			// we've sent everything....

			fprintf(stderr, "write_handler: All sent.\n");

			// everything has been sent from the outbuffer, so we can clear it.
			expbuf_clear(client->outbuffer);
			expbuf_free(client->outbuffer);
			free(client->outbuffer);
			client->outbuffer = NULL;
			client->out_sent = 0;

			// all data has been sent, so we clear the write event.
			assert(client->write_event);
			event_free(client->write_event);
			client->write_event = NULL;
			assert(client->read_event);
		}
	}
	else 	if (res == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
		// the connection has closed, so we need to clean up.
		client_free(client);
	}
}



//-----------------------------------------------------------------------------
// We've gotten a reply from the http consumer.  We need to take that data and
// form a reply that we send.
static void cmdReply(client_t *client) {
	assert(client);
	assert(client->filedata);
	assert(client->content_type);

	// all output needs to go in the outbuffer.
	assert(client->outbuffer == NULL);
	assert(client->out_sent == 0);
	client->outbuffer = (expbuf_t *) malloc(sizeof(expbuf_t));
	expbuf_init(client->outbuffer, 1024);

	expbuf_print(client->outbuffer, "HTTP/1.1 200 OK\r\n");
	expbuf_print(client->outbuffer, "Content-Length: %d\r\n", BUF_LENGTH(client->filedata));
	expbuf_print(client->outbuffer, "Keep-Alive: timeout=5, max=100\r\n");
	expbuf_print(client->outbuffer, "Connection: Keep-Alive\r\n");
	expbuf_print(client->outbuffer, "Content-Type: %s\r\n\r\n", expbuf_string(client->content_type));

	expbuf_add(client->outbuffer, BUF_DATA(client->filedata), BUF_LENGTH(client->filedata));
// 	expbuf_print(client->outbuffer, "\r\n");

	// TODO: Need to supply these headers also.
// Date: Thu, 03 Sep 2009 21:49:33 GMT
// Server: Apache/2.2.11 (Unix)
// Last-Modified: Thu, 03 Sep 2009 21:47:59 GMT
// ETag: "758017-95-472b3564641c0"
// Accept-Ranges: bytes
// Vary: Accept-Encoding,User-Agent


	// create the write_event (with persist).  We will not try to send it
	// directly to the socket.  We will wait until the write_event fires.
	assert(client->write_event == NULL);
	assert(client->server);
	assert(client->server->control);
	assert(client->server->control->evbase);
	assert(client->handle > 0);
	client->write_event = event_new(client->server->control->evbase, client->handle, EV_WRITE | EV_PERSIST, write_handler, client);
	event_add(client->write_event, NULL);

	// PERF: Put this back in the bufpool.
	assert(client->filedata);
	expbuf_clear(client->filedata);
	expbuf_free(client->filedata);
	free(client->filedata);
	client->filedata = NULL;

	assert(client->content_type);
	expbuf_clear(client->content_type);
	expbuf_free(client->content_type);
	free(client->content_type);
	client->content_type = NULL;	
}


static void cmdContentType(client_t *client, const risp_length_t length, const risp_data_t *data)
{
	assert(client);
	assert(length >= 0);
	assert(data != NULL);

	// save the host info somewhere
	assert(client->content_type == NULL);
	client->content_type = (expbuf_t *) malloc(sizeof(expbuf_t));
	expbuf_init(client->content_type, length+1);
	assert(length > 0);
	expbuf_set(client->content_type, data, length);
}



static void cmdFile(client_t *client, const risp_length_t length, const risp_data_t *data)
{
	assert(client);
	assert(length >= 0);
	assert(data != NULL);

	// PERF: get the filedata buffer from the buff pool.

	// save the host info somewhere
	assert(client->filedata == NULL);
	client->filedata = (expbuf_t *) malloc(sizeof(expbuf_t));
	expbuf_init(client->filedata, length);
	assert(length > 0);
	expbuf_set(client->filedata, data, length);
}












// This function is called when data is available on the socket.  We need to read the data from the socket, and process as much of it as we can.  We need to remember that we might possibly have leftover data from previous reads, so we will need to append the new data in that case.
static void read_handler(int fd, short int flags, void *arg)
{
	client_t *client = (client_t *) arg;
	int res;
	control_t *control;
	int done;

	assert(fd >= 0);
	assert(flags != 0);
	assert(client);
	assert(client->handle == fd);

	assert(client->server);
	assert(client->server->control);
	control = client->server->control;
	
	// read data from the socket.
	assert(control->readbuf);
	assert(BUF_LENGTH(control->readbuf) == 0 && BUF_MAX(control->readbuf) > 0 && BUF_DATA(control->readbuf) != NULL);
	res = read(fd, BUF_DATA(control->readbuf), BUF_MAX(control->readbuf));
	if (res > 0) {

		if (control->verbose > 1) 
			fprintf(stderr, "read %d bytes. (max=%d)\n", res, BUF_MAX(control->readbuf));
	
		// got some data.
		assert(res <= BUF_MAX(control->readbuf));
		BUF_LENGTH(control->readbuf) = res;
	
		// if we got the max of the buffer, then we should increase the size of the buffer.
		if (res == BUF_MAX(control->readbuf)) {
			expbuf_shrink(control->readbuf, DEFAULT_BUFSIZE);	// give the buffer some extra kb.
			assert(BUF_MAX(control->readbuf) > BUF_LENGTH(control->readbuf));
		}
	}
	else {
		// the connection was closed, or there was an error.
		fprintf(stderr, "connection closed while reading.\n");

		// free the client resources.
		client_free(client);
		client = NULL;
		
		assert(BUF_LENGTH(control->readbuf) == 0);
		return;
	}

	// process the data received, and remove what was processed, from the buffer.
	assert(0);


	assert(BUF_LENGTH(client->server->control->readbuf) == 0);
}



//-----------------------------------------------------------------------------
// print some info to the user, so that they can know what the parameters do.
static void usage(void) {
	printf(PACKAGE " " VERSION "\n");
	printf("-l <ip_addr:port>  interface to listen on, default is INDRR_ANY\n");
	printf("-c <num>           max simultaneous connections, default is 1024\n");
	printf("-s <path>          storage path\n");
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


//-----------------------------------------------------------------------------
// Main... process command line parameters, and then setup our listening 
// sockets and event loop.
int main(int argc, char **argv) 
{
	control_t *control  = NULL;

///============================================================================
/// Initialization.
///============================================================================

	// create the 'control' object that will be passed to all the handlers so
	// that they have access to the information that they require.
	control = (control_t *) malloc(sizeof(control_t));
	init_control(control);

	parse_params(control, argc, argv);
	
	
	// daemonize
	assert(0);
	
	// create our event base which will be the pivot point for pretty much everything.
	assert(control->evbase == NULL);
	control->evbase = event_base_new();
	assert(control->evbase);

	// initialise signal handlers.
	assert(control);
	assert(control->evbase);
	assert(control->sigint_event == NULL);
	assert(control->sighup_event == NULL);
	control->sigint_event = evsignal_new(control->evbase, SIGINT, sigint_handler, control);
	control->sighup_event = evsignal_new(control->evbase, SIGHUP, sighup_handler, control);
	event_add(control->sigint_event, NULL);
	event_add(control->sighup_event, NULL);


	assert(control);
	assert(control->risp == NULL);
	control->risp = risp_init();
	assert(control->risp != NULL);
	risp_add_invalid(control->risp, cmdInvalid);
// 	risp_add_command(control->risp, HTTP_CMD_CLEAR,        &cmdClear);
// 	risp_add_command(control->risp, HTTP_CMD_FILE,         &cmdFile);
// 	risp_add_command(control->risp, HTTP_CMD_CONTENT_TYPE, &cmdContentType);
// 	risp_add_command(control->risp, HTTP_CMD_REPLY,        &cmdReply);


	
	
	
	// initialise the servers that we listen on.
	init_servers(control);
	

///============================================================================
/// Main Event Loop.
///============================================================================

	// enter the processing loop.  This function will not return until there is
	// nothing more to do and the service has shutdown.  Therefore everything
	// needs to be setup and running before this point.  Once inside the
	// rq_process function, everything is initiated by the RQ event system.
	assert(control != NULL);
	assert(control->evbase);
	event_base_loop(control->evbase, 0);

///============================================================================
/// Shutdown
///============================================================================

	assert(control);
	assert(control->evbase);
	event_base_free(control->evbase);
	control->evbase = NULL;

	// cleanup the servers objects.
	cleanup_servers(control);

	// make sure signal handlers have been cleared.
	assert(control);
	assert(control->sigint_event == NULL);
	assert(control->sighup_event == NULL);

	assert(control);
	assert(control->risp);
	risp_shutdown(control->risp);
	control->risp = NULL;

	// we are done, cleanup what is left in the control structure.
	cleanup_control(control);
	free(control);

	return 0;
}



//-----------------------------------------------------------------------------
// stash-create-namespace
//	Add a namespace to the server.   Will be able to add a namespace to a 
//	server that is running, or directly to the filesystem if the server is not 
//	running.
//-----------------------------------------------------------------------------



// includes
#include "stash-common.h"
#include <stash.h>

#include <assert.h>
#include <errno.h>
#include <expbuf.h>
#include <rispbuf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>



#define PACKAGE			"stash-create-namespace"
#define VERSION			"0.01"


//-----------------------------------------------------------------------------
// print some info to the user, so that they can know what the parameters do.
static void usage(void) {
	printf(PACKAGE " " VERSION "\n");
	printf("Required params:\n");
	printf(" -n <namespace>     namespace\n");
	printf("\n");
	printf("Direct file method:\n");
	printf(" -d <path>          storage path\n");
	printf("\n");
	printf("Connect to running instance method:\n");
	printf(" -H <host:port>     Hostname of the running instance.\n");
	printf(" -U <username>      Admin username\n");
	printf(" -P <password>      Admin password\n");
	printf("\n");
	printf("Misc. Options:\n");
	printf(" -v                 verbose\n");
	printf(" -h                 print this help and exit\n");
	return;
}



//-----------------------------------------------------------------------------
// Main... process command line parameters, and if we have enough information, then create an empty stash.
int main(int argc, char **argv) 
{
	int c;
	int verbose = 0;
	storage_t *storage;
	int result = 0;

	char *basedir = NULL;
	char *namespace = NULL;
	char *host = NULL;
	char *username = NULL;
	char *password = NULL;
	
	
	assert(argc >= 0);
	assert(argv);
	
	// process arguments
	/// Need to check the options in here, there're possibly ones that we dont need.
	while ((c = getopt(argc, argv, "hvd:n:H:U:P:")) != -1) {
		switch (c) {
			case 'h':
				usage();
				exit(0);
			case 'v':
				verbose++;
				break;
			case 'd':
				assert(basedir == NULL);
				basedir = optarg;
				break;
			case 'n':
				assert(namespace == NULL);
				namespace = optarg;
				break;
			case 'H':
				assert(host == NULL);
				host = optarg;
				break;
			case 'U':
				assert(username == NULL);
				username = optarg;
				break;
			case 'P':
				assert(password == NULL);
				password = optarg;
				break;
				
			default:
				fprintf(stderr, "Illegal argument \"%c\"\n", c);
				exit(1);
				
		}
	}
	
	if (namespace == NULL) {
		fprintf(stderr, "missing required parameter: -n\n");
		exit(1);
	}
	
	// make sure basedir parameter was supplied.
	if (basedir == NULL && host == NULL) {
		fprintf(stderr, "missing required option, either -d or -H\n");
		exit(1);
	}
	else if (basedir && host) {
		fprintf(stderr, "cannot specify both a directory and a host.\n");
		exit(1);
	}
	
	if (basedir) {
		// we are using a basedir direct method.  For this we will need to use 
		// the stash_storage functionality (that is part of the libstash 
		// library).
		
		storage = storage_init(NULL);
		assert(storage);
		
		// process the main meta file;
		assert(basedir);
		storage_lock_master(storage, basedir);
		storage_process(storage, basedir, KEEP_OPEN);
		
		// if the namespace is available, then create it.
		if (storage_namespace_avail(storage, namespace) == 0) {
			fprintf(stderr, "Namespace '%s' is already in use.\n", namespace);
			result = 1;
		}
		else {		
			storage_create_namespace(storage, NULL_USER_ID, namespace);
			if (verbose) {
				printf("Namespsace '%s' created.\n", namespace);
				assert(result == 0);
			}
		}

		storage_unlock_master(storage, basedir);

		// cleanup the storage 
		storage_free(storage);
		storage = NULL;		
	}
	else {
		// network version.
		assert(0);
	}
	
	return(result);
}



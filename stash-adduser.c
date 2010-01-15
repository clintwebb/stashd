//-----------------------------------------------------------------------------
// stash-adduser
//	Tool to add a user to the stash.  It will be able to add a user directly to 
//	the stash files if it is not currently loaded, or it can connect and add a 
//	user through the admin interface (requires an existing user with admin 
//	privs).
//-----------------------------------------------------------------------------


// includes
#include "stash-common.h"
#include <stash.h>

#include <assert.h>
#include <expbuf.h>
#include <risp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>



#define PACKAGE						"stash-adduser"
#define VERSION						"0.10"



//-----------------------------------------------------------------------------
// global variables.

short int verbose = 0;
char *basedir = NULL;
char *host = NULL;
int port = 13600;
char *username = NULL;
char *password = NULL;
char *newuser = NULL;
char *newpass = NULL;





//-----------------------------------------------------------------------------
// print some info to the user, so that they can know what the parameters do.
static void usage(void) {
	printf(PACKAGE " " VERSION "\n");
	printf("Required params:\n");
	printf(" -u <username>      new username\n");
	printf(" -p <password>      new password\n");
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
	storage_t *storage;
	int result;
	const char *newuser = NULL;
	const char *newpass = NULL;
	const char *host = NULL;
	const char *username = NULL;
	const char *password = NULL;
	userid_t uid;
	
	
	assert(argc >= 0);
	assert(argv);
	
	// process arguments
	/// Need to check the options in here, there're possibly ones that we dont need.
	while ((c = getopt(argc, argv, "hvd:u:p:")) != -1) {
		switch (c) {
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'v':
				verbose++;
				break;
			case 'd':
				basedir = optarg;
				break;
			case 'u':
				newuser = optarg;
				break;
			case 'p':
				newpass = optarg;
				break;

			case 'H':
				host = optarg;
				break;
			case 'U':
				username = optarg;
				break;
			case 'P':
				password = optarg;
				break;
				
			default:
				fprintf(stderr, "Illegal argument \"%c\"\n", c);
				exit(1);
				
		}
	}
	
	// check that our required params are there:
	if (basedir == NULL && host == NULL) {
		fprintf(stderr, "missing required option, either -d or -H\n");
		exit(1);
	}
	else if (basedir && host) {
		fprintf(stderr, "cannot specify both a directory and a host.\n");
		exit(1);
	}
	else if (newuser == NULL) {
		fprintf(stderr, "missing required parameter: -u\n");
		exit(1);
	}
	
	if (basedir) {
		// we are using a basedir direct method.  For this we will need to use 
		// the stash_storage functionality (that is part of the libstash 
		// library).
		
		result = 0;
		
		storage = storage_init(NULL);
		assert(storage);
		
		// process the main meta file;
		assert(basedir);
		storage_lock_master(storage, basedir);
		storage_process(storage, basedir, KEEP_OPEN, IGNORE_DATA);
		
		// if the namespace is available, then create it.
		if (storage_username_avail(storage, newuser) == 0) {
			fprintf(stderr, "Username '%s' is already in use.\n", newuser);
			result = 1;
		}
		else {		
			uid = storage_create_username(storage, NULL_USER_ID, newuser);
			assert(uid > 0);
			if (newpass) {
				storage_set_password(storage, NULL_USER_ID, uid, newpass);
			}

			if (verbose) {
				printf("Username '%s' created.\n", newuser);
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



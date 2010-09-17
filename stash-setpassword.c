//-----------------------------------------------------------------------------
// stash-setpassword
//	Tool to change the password of an existing user.  If the user is not the 
//	same one as is loggin in, then the user must have the ADDUSER right.
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



#define PACKAGE						"stash-setpassword"
#define VERSION						"0.10"



//-----------------------------------------------------------------------------
// global variables.

short int verbose = 0;





//-----------------------------------------------------------------------------
// print some info to the user, so that they can know what the parameters do.
static void usage(void) {
	printf(PACKAGE " " VERSION "\n");
	printf("Params:\n");
	printf(" -u <username>      username\n");
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
	storage_t *storage = NULL;
	stash_t *stash = NULL;
	int result;
	const char *basedir = NULL;
	const char *newuser = NULL;
	const char *newpass = NULL;
	const char *host = NULL;
	const char *username = NULL;
	const char *password = NULL;
	user_t *user;
	stash_result_t res;
	
	
	assert(argc >= 0);
	assert(argv);
	
	// process arguments
	/// Need to check the options in here, there're possibly ones that we dont need.
	while ((c = getopt(argc, argv, "hvd:u:p:H:U:P:")) != -1) {
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
	else if (newpass == NULL) {
		fprintf(stderr, "missing required parameter: -p\n");
		exit(1);
	}
	else if (newuser == NULL) {
		fprintf(stderr, "missing required parameter: -u\n");
		exit(1);
	}
	
	result = 0;
	
	if (basedir) {
		// we are using a basedir direct method.  For this we will need to use 
		// the stash_storage functionality (that is part of the libstash 
		// library).
		
		storage = storage_init(NULL);
		assert(storage);
		
		// process the main meta file;
		assert(basedir);
		storage_lock_master(storage, basedir);
		storage_process(storage, basedir, KEEP_OPEN, IGNORE_DATA);
		
		// if the namespace is available, then create it.
		assert(newuser);
		user = storage_getuser(storage, NULL_USER_ID, newuser);
		if (user == NULL) {
			fprintf(stderr, "Username '%s' does not exist.\n", newuser);
			result = 1;
		}
		else {
			assert(user->uid > 0);
			
			storage_set_password(storage, NULL_USER_ID, user->uid, newpass);

			if (verbose) {
				printf("Password for user '%s' changed.\n", newuser);
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
		
		stash = stash_init(NULL);
		assert(stash);
		
		// add our username and password to the authority... in future 
		// versions, private and public keys may be used instead.
		assert(username);
		assert(password);
		stash_authority(stash, username, password);

		// add our known host to the server list.
		assert(host);
		stash_addserver(stash, host, 10);
		
		// connect to the database... check error code.
		// although it is not necessary to connect now, because if we dont, 
		// the first operation we do will attempt to connect if we are not 
		// already connected.  However, it is useful right now to attempt to 
		// connect so that we can report the error back to the user.  Easier 
		// to do it here and it doesn't cost anything.
		res = stash_connect(stash);
		if (res != 0) {
			fprintf(stderr, "Unable to connect: %04X:%s\n", res, stash_err_text(res));
		}
		else {

			res = stash_set_password(stash, 0, newuser, newpass);
			if (res != STASH_ERR_OK) {
				switch(res) {
					case STASH_ERR_OK:
						if (verbose) { printf("Password set for user '%s'.\n", newuser); }
						break;
					
					case STASH_ERR_USERNOTEXIST:
						fprintf(stderr, "Username '%s' does not exist.\n", newuser);
						break;
					case STASH_ERR_INSUFFICIENTRIGHTS:
						fprintf(stderr, "Insufficient rights to change passwords.\n");
						break;
					default:
						fprintf(stderr, "Unexpected error: %04X:%s\n", res, stash_err_text(res));
						break;
				}
				result = 1;
			}
		}
		
		// cleanup the storage 
		stash_free(stash);
		stash = NULL;		
	}

	assert(stash == NULL);
	assert(storage == NULL);
	
	return(result);
}



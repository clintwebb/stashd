//-----------------------------------------------------------------------------
// stash-create-table
//	Tool to create a table.  Does not provide support for manipulating the 
//	files directly.  Must go through a server.
//-----------------------------------------------------------------------------


// includes
#include <stash.h>

#include <assert.h>
#include <expbuf.h>
#include <risp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>



#define PACKAGE						"stash-create-table"
#define VERSION						"0.10"



//-----------------------------------------------------------------------------
// global variables.

short int verbose = 0;





//-----------------------------------------------------------------------------
// print some info to the user, so that they can know what the parameters do.
static void usage(void) {
	printf(PACKAGE " " VERSION "\n");
	printf("Params:\n");
	printf(" -n <namespace>  namespace table will be created in.\n");
	printf(" -t <table>      new table name\n");
	printf(" -s              strict mode (optional)\n");
	printf(" -o              overwrite mode (optional)\n");
	printf(" -u              unique mode (optional)\n");
	printf("\n");
	printf("Connection params:\n");
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
	stash_t *stash = NULL;
	int result = 1;
	const char *table = NULL;
	const char *namespace = NULL;
	const char *host = NULL;
	const char *username = NULL;
	const char *password = NULL;
	int option_map = 0;
	stash_result_t res;
	stash_nsid_t nsid;
	stash_tableid_t tid;
	
	assert(argc >= 0);
	assert(argv);
	
	// process arguments
	/// Need to check the options in here, there're possibly ones that we dont need.
	while ((c = getopt(argc, argv, "hvd:t:H:U:P:n:suo")) != -1) {
		switch (c) {
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
				break;
				
			case 'v': verbose++; 							break;
			case 't': table = optarg;						break;
			case 'n': namespace = optarg;					break;
			case 's': option_map |= STASH_TABOPT_STRICT;	break;
			case 'u': option_map |= STASH_TABOPT_UNIQUE;	break;
			case 'o': option_map |= STASH_TABOPT_OVERWRITE;	break;
			
			case 'H': host = optarg;		break;
			case 'U': username = optarg;	break;
			case 'P': password = optarg;	break;
				
			default:
				fprintf(stderr, "Illegal argument \"%c\"\n", c);
				exit(1);
				
		}
	}
	
	// check that our required params are there:
	if (host == NULL) {
		fprintf(stderr, "missing required option: -H <host>\n");
		exit(1);
	}
	else if (username == NULL || password == NULL) {
		fprintf(stderr, "missing required option: -U <username> -P <password>\n");
		exit(1);
	}
	else if (namespace == NULL) {
		fprintf(stderr, "missing required parameter: -n <namespace>\n");
		exit(1);
	}
	else if (table == NULL) {
		fprintf(stderr, "missing required parameter: -t <table>\n");
		exit(1);
	}
	
	result = 0;
	
		
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

		// get the namespaceID, because we will be using for the request.
		assert(namespace);
		nsid = 0;
		res = stash_get_namespace_id(stash, namespace, &nsid);
		if (res != STASH_ERR_OK) { fprintf(stderr, "error: %d:'%s'\n", res, stash_err_text(res)); }
		else {
			
			assert(nsid > 0);
			
			// attempt to create the table.
			tid = 0;
			res = stash_create_table(stash, nsid, table, option_map, &tid);
			if (res != STASH_ERR_OK) { fprintf(stderr, "error: %d:'%s'\n", res, stash_err_text(res)); }
			else {
				assert(tid > 0);
				result = 0;
				
				if (verbose) {
					printf("Table '%s' created.\n", table);
				}
				assert(result == 0);
			}
		}
	}
	
	// cleanup the storage 
	stash_free(stash);
	stash = NULL;		
	
	return(result);
}



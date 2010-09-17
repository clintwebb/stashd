//-----------------------------------------------------------------------------
// stash-grant
//	Tool to add a grant for a user on the stash.  It can be used in direct file 
//	mode (while the service is not running), or in network mode.   In network 
//	mode, it will need to be authenticated like any other client, and must have 
//	the rights to supply the grant.
//
//	Grants are reciprocal.  This means that whatever rights a user has, can be 
//	given to other users.  A user cannot supply a grant that it doeasn't 
//	already have.
//
//	New databases will therefore need at least one administrator username added 
//	to the database when it is created, or it will be rather useless when it is 
//	running.
//
//	There are no built-in accounts.  All users that will use or access the 
//	database need to be created and appropriate rights assigned.
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



#define PACKAGE						"stash-grant"
#define VERSION						"0.10"



//-----------------------------------------------------------------------------
// global variables.

short int verbose = 0;





//-----------------------------------------------------------------------------
// print some info to the user, so that they can know what the parameters do.
static void usage(void) {
	printf(PACKAGE " " VERSION "\n");
	printf("Main params:\n");
	printf(" -u <username>      username to receive the grant\n");
	printf(" -n <namespace>     namespace\n");
	printf(" -t <table>         table\n");
	printf(" -r <right>         from the following:\n");
	printf("                       ADDUSER\n");
	printf("                       CREATE\n");
	printf("                       DROP\n");
	printf("                       SET\n");
	printf("                       UPDATE\n");
	printf("                       DELETE\n");
	printf("                       QUERY\n");
	printf("                       LOCK\n");
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
	printf("\n");
	printf("Only one right can be set at a time.\n");
	return;
}





//-----------------------------------------------------------------------------
// Main... process command line parameters, and if we have enough information, then create an empty stash.
int main(int argc, char **argv) 
{
	int c;
	storage_t *storage;
	int result;
	user_t *user = NULL;
	namespace_t *ns = NULL;
	table_t *table = NULL;
	stash_t *stash;
	stash_nsid_t nsid;
	stash_tableid_t tid;
	stash_userid_t uid;
	stash_result_t res;

	struct {
		const char *basedir;
		struct {
			const char *host;
			const char *username;
			const char *password;
		} conn;
		
		const char *namespace;
		const char *table;
		const char *user;
		
		unsigned short rights;
	} params;
	
	params.basedir = NULL;
	params.conn.host = NULL;
	params.conn.username = NULL;
	params.conn.password = NULL;
	params.namespace = NULL;
	params.table = NULL;
	params.user = NULL;
	params.rights = 0;
	
	assert(argc >= 0);
	assert(argv);
	
	// process arguments
	/// Need to check the options in here, there're possibly ones that we dont need.
	while ((c = getopt(argc, argv, "H:U:P:hvd:u:p:n:t:r:")) != -1) {
		switch (c) {
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'v':
				verbose++;
				break;
			case 'd':
				params.basedir = optarg;
				break;
			case 'u':
				params.user = optarg;
				break;
			case 'n':
				params.namespace = optarg;
				break;
			case 't':
				params.table = optarg;
				break;
			case 'r':
				if (strcasecmp(optarg, "ADDUSER") == 0) 
					params.rights |= STASH_RIGHT_ADDUSER;
				else if (strcasecmp(optarg, "CREATE") == 0) 
					params.rights |= STASH_RIGHT_CREATE;
				else if (strcasecmp(optarg, "DROP") == 0) 
					params.rights |= STASH_RIGHT_DROP;
				else if (strcasecmp(optarg, "SET") == 0) 
					params.rights |= STASH_RIGHT_SET;
				else if (strcasecmp(optarg, "UPDATE") == 0) 
					params.rights |= STASH_RIGHT_UPDATE;
				else if (strcasecmp(optarg, "DELETE") == 0) 
					params.rights |= STASH_RIGHT_DELETE;
				else if (strcasecmp(optarg, "QUERY") == 0) 
					params.rights |= STASH_RIGHT_QUERY;
				else if (strcasecmp(optarg, "LOCK") == 0) 
					params.rights |= STASH_RIGHT_LOCK;
				else {
					fprintf(stderr, "Invalid right selected: %s\n", optarg);
					exit(1);
				}
				
				break;

			case 'H':
				params.conn.host = optarg;
				break;
			case 'U':
				params.conn.username = optarg;
				break;
			case 'P':
				params.conn.password = optarg;
				break;
				
			default:
				fprintf(stderr, "Illegal argument \"%c\"\n", c);
				exit(1);
		}
	}
	
	// check that our required params are there:
	if (params.basedir == NULL && params.conn.host == NULL) {
		fprintf(stderr, "missing required option, either -d or -H\n");
		exit(1);
	}
	else if (params.basedir && params.conn.host) {
		fprintf(stderr, "cannot specify both a directory and a host.\n");
		exit(1);
	}
	else if (params.user == NULL) {
		fprintf(stderr, "missing required parameter: -u\nMust provide a user that we are granting a right to.\n");
		exit(1);
	}
	
	// determine what 'right' was specified.
	if (params.rights == 0) {
		fprintf(stderr, "invalid right provided.\n");
		exit(1);
	}
	
	
	if (params.basedir) {
		// we are using a basedir direct method.  For this we will need to use 
		// the stash_storage functionality (that is part of the libstash 
		// library).
		
		result = 0;
		
		storage = storage_init(NULL);
		assert(storage);
		
		// process the main meta file;
		assert(params.basedir);
		storage_lock_master(storage, params.basedir);
		storage_process(storage, params.basedir, KEEP_OPEN, IGNORE_DATA);
		
		// 
		user = storage_getuser(storage, NULL_USER_ID, params.user);
		if (user == NULL) {
			fprintf(stderr, "Username '%s' does not exist.\n", params.user);
			result = 1;
		}
		else {
			
			if (params.namespace) {
				ns = storage_getnamespace(storage, 0, params.namespace);
				if (ns == NULL) {
					fprintf(stderr, "Namespace '%s' does not exist.\n", params.namespace);
					result = 1;
				}
				else {
					if (params.table) {
						table = storage_gettable(storage, ns, 0, params.table);
						if (table == NULL) {
							fprintf(stderr, "Table '%s:%s' does not exist.\n", params.namespace, params.table);
							result = 1;
						}
					}
				}
			}
			
			if (result == 0) {
				assert(user->uid > 0);
				assert(user->username);
				assert(params.rights > 0);
				storage_grant(storage, NULL_USER_ID, user, ns, table, params.rights);
				
				if (verbose) {
					printf("Rights for user '%s' granted.\n", params.user);
				}
				assert(result == 0);
			}
		}
		
		storage_unlock_master(storage, params.basedir);
		
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
		assert(params.conn.username);
		assert(params.conn.password);
		stash_authority(stash, params.conn.username, params.conn.password);
		
		// add our known host to the server list.
		assert(params.conn.host);
		stash_addserver(stash, params.conn.host, 10);
		
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
			nsid = 0;
			tid = 0;
			res = STASH_ERR_OK;
			
			if (params.namespace) {
				res = stash_get_namespace_id(stash, params.namespace, &nsid);
				if (res != STASH_ERR_OK) { fprintf(stderr, "error parsing namespace: %d:'%s'\n", res, stash_err_text(res)); }
			}

			if (params.table) {
				assert(nsid > 0);
				res = stash_get_table_id(stash, nsid, params.table, &tid);
				if (res != STASH_ERR_OK) { fprintf(stderr, "error parsing table: %d:'%s'\n", res, stash_err_text(res)); }
			}
			
			if (params.user) {
				res = stash_get_user_id(stash, params.user, &uid);
				if (res != STASH_ERR_OK) { fprintf(stderr, "error parsing username: %d:'%s'\n", res, stash_err_text(res)); }
			}
			
			// attempt to set the grant
			if (res == STASH_ERR_OK) { 
				
				res = stash_grant(stash, uid, nsid, tid, params.rights);
				if (res != STASH_ERR_OK) { fprintf(stderr, "error setting grant: %d:'%s'\n", res, stash_err_text(res)); }
				else {
					result = 0;
					
					if (verbose) {
						assert(table->name);
						printf("Table '%s' created.\n", table->name);
					}
					assert(result == 0);
				}
			}
		}
		
		// cleanup the storage 
		stash_free(stash);
		stash = NULL;		
		
	}
	
	return(result);
}



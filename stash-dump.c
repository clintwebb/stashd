//-----------------------------------------------------------------------------
// stash-adduser
//	Tool to add a user to the stash.  It will be able to add a user directly to 
//	the stash files if it is not currently loaded, or it can connect and add a 
//	user through the admin interface (requires an existing user with admin 
//	privs).
//-----------------------------------------------------------------------------


// includes

#include "stash-common.h"

#include <assert.h>
#include <expbuf.h>
#include <risp.h>
#include <stash.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>



#define PACKAGE						"stash-dump"
#define VERSION						"0.10"



//-----------------------------------------------------------------------------
// global variables.

short int verbose = 0;

typedef struct {
	risp_t *risp_top;
	risp_t *risp_op;
	risp_t *risp_payload;
	risp_t *risp_data;
} master_t;





//-----------------------------------------------------------------------------
// print some info to the user, so that they can know what the parameters do.
static void usage(void) {
	printf(PACKAGE " " VERSION "\n");
	printf("Direct file method:\n");
	printf(" -f <filename>      File to dump\n");
	printf("\n");
	printf("Misc. Options:\n");
	printf(" -v                 verbose\n");
	printf(" -h                 print this help and exit\n");
	return;
}


//-----------------------------------------------------------------------------
static void cmdClear(master_t *master)
{
	assert(master);

	printf("Clear.\n");
	
	// clear the saved data.
	risp_clear_all(master->risp_top);
}


//-----------------------------------------------------------------------------
static void cmdFileSeq(master_t *master, risp_int_t value)
{
	assert(master);

	printf("File Sequence: %d\n", value);
}


static void cmdNextVolume(master_t *master)
{
	assert(master);
	
	printf("Next Volume.\n");
}
	

static void cmdOperation(master_t *master, risp_length_t length, void *data) 
{
	
	risp_length_t processed;
	risp_length_t plen;
	risp_data_t *pdata;
	int cnt;
	
	assert(master);
	assert(length > 0);
	assert(data);
	
	// we have data, that we need to put through the risp_op parser.  It will 
	// return some transaction details, and a payload.
	assert(master->risp_op);
	risp_clear_all(master->risp_op);
	processed = risp_process(master->risp_op, NULL, length, data);
	assert(processed == length);
	
// 	if ( risp_isset(storage->risp_op, STASH_CMD_USER_ID) != 0) {
// 		storage->opdata.user_id = risp_getvalue(storage->risp_op, STASH_CMD_USER_ID);
// 	}
	
// 	if ( risp_isset(storage->risp_op, STASH_CMD_DATE) != 0) {
// 		storage->opdata.date = risp_getvalue(storage->risp_op, STASH_CMD_DATE);
// 	}
	
// 	if ( risp_isset(storage->risp_op, STASH_CMD_TIME) != 0) {
// 		storage->opdata.time = risp_getvalue(storage->risp_op, STASH_CMD_TIME);
// 	}
	
	assert ( risp_isset(master->risp_op, STASH_CMD_PAYLOAD) != 0);
	plen = risp_getlength(master->risp_op, STASH_CMD_PAYLOAD);
	pdata = risp_getdata(master->risp_op, STASH_CMD_PAYLOAD);
	
	assert(pdata);
	assert(plen > 0);
	
	// now that we have everything setup ready to process the information, we 
	// need to parse the payload.  THe payload RISP interface will have 
	// callbacks for all the operational commands, so whatever needs to be 
	// done will be handled internally.  When the parse function has finished, 
	// there is nothing else for us to do.
	risp_clear_all(master->risp_payload);
	processed = risp_process(master->risp_payload, master, plen, pdata);
	assert(processed == plen);
	
	
	// need to somehow identify if the payload is something other than what we 
	// expect so that we can report that there is at least something there.
	for (cnt=0; cnt<256; cnt++) {
		if (master->risp_payload->commands[cnt].handler == NULL) {
			if (master->risp_payload->commands[cnt].set) {
				printf("Unexpected operation: %d\n", cnt);
			}
		}
	}
}

static void cmdCreateUser(master_t *master, risp_length_t length, void *data)
{
	char *newuser;
	userid_t uid;
	risp_length_t processed;
	
	assert(master);
	assert(length > 0);
	assert(data);
	
	assert(master->risp_data);
	risp_clear_all(master->risp_data);
	processed = risp_process(master->risp_data, NULL, length, data);
	assert(processed == length);
	
	assert(risp_isset(master->risp_data, STASH_CMD_USERNAME) != 0);
	assert(risp_isset(master->risp_data, STASH_CMD_USER_ID) != 0);
	
	newuser = risp_getstring(master->risp_data, STASH_CMD_USERNAME);
	uid = risp_getvalue(master->risp_data, STASH_CMD_USER_ID);
	
	assert(newuser);
	assert(uid > 0);
	printf("New User: [uid:%d]='%s'\n", uid, newuser);
}


static void cmdCreateNamespace(master_t *master, risp_length_t length, void *data)
{
	char *newuser;
	nsid_t id;
	risp_length_t processed;
	
	assert(master);
	assert(length > 0);
	assert(data);
	
	assert(master->risp_data);
	risp_clear_all(master->risp_data);
	processed = risp_process(master->risp_data, NULL, length, data);
	assert(processed == length);
	
	assert(risp_isset(master->risp_data, STASH_CMD_NAMESPACE) != 0);
	assert(risp_isset(master->risp_data, STASH_CMD_NAMESPACE_ID) != 0);
	
	newuser = risp_getstring(master->risp_data, STASH_CMD_NAMESPACE);
	id = risp_getvalue(master->risp_data, STASH_CMD_NAMESPACE_ID);
	
	assert(newuser);
	assert(id > 0);
	printf("New Namespace: [nsid:%d]='%s'\n", id, newuser);
}


static void cmdSetPassword(master_t *master, risp_length_t length, void *data)
{
	userid_t id;
	risp_length_t processed;
	
	assert(master);
	assert(length > 0);
	assert(data);
	
	assert(master->risp_data);
	risp_clear_all(master->risp_data);
	processed = risp_process(master->risp_data, NULL, length, data);
	assert(processed == length);
	
	assert(risp_isset(master->risp_data, STASH_CMD_PASSWORD) != 0);
	assert(risp_isset(master->risp_data, STASH_CMD_USER_ID) != 0);
	
	id = risp_getvalue(master->risp_data, STASH_CMD_USER_ID);
	
	assert(id > 0);
	printf("Password set: [uid:%d]\n", id);
}


static void cmdGrant(master_t *master, risp_length_t length, void *data)
{
	userid_t uid = 0;
	nsid_t nsid = 0;
	tableid_t tid = 0;
	
	risp_length_t processed;
	
	assert(master);
	assert(length > 0);
	assert(data);
	
	assert(master->risp_data);
	risp_clear_all(master->risp_data);
	processed = risp_process(master->risp_data, NULL, length, data);
	assert(processed == length);
	
	// get the userid.
	assert(risp_isset(master->risp_data, STASH_CMD_USER_ID) != 0);
	uid = risp_getvalue(master->risp_data, STASH_CMD_USER_ID);
	assert(uid > 0);
	
	// if we have a namespace, get it.
	if (risp_isset(master->risp_data, STASH_CMD_NAMESPACE_ID) != 0) {
		nsid = risp_getvalue(master->risp_data, STASH_CMD_NAMESPACE_ID);
		assert(nsid > 0);
		
		if (risp_isset(master->risp_data, STASH_CMD_TABLE_ID) != 0) {
			tid = risp_getvalue(master->risp_data, STASH_CMD_TABLE_ID);
			assert(tid > 0);
			
			printf("Grant: [uid:%d, nsid:%d, tid:%d]", uid, nsid, tid);
		}
		else {
			printf("Grant: [uid:%d, nsid:%d]", uid, nsid);
		}
	}
	else {
		printf("Grant: [uid:%d]", uid);
	}

	
	
	if (risp_isset(master->risp_data, STASH_CMD_RIGHT_ADDUSER) != 0) {
		printf(" ADDUSER");
	}
	
	if (risp_isset(master->risp_data, STASH_CMD_RIGHT_CREATE) != 0) {
		printf(" CREATE");
	}
	
	if (risp_isset(master->risp_data, STASH_CMD_RIGHT_DROP) != 0) {
		printf(" DROP");
	}
	
	if (risp_isset(master->risp_data, STASH_CMD_RIGHT_SET) != 0) {
		printf(" SET");
	}
	
	if (risp_isset(master->risp_data, STASH_CMD_RIGHT_UPDATE) != 0) {
		printf(" UPDATE");
	}
	
	if (risp_isset(master->risp_data, STASH_CMD_RIGHT_DELETE) != 0) {
		printf(" DELETE");
	}
	
	if (risp_isset(master->risp_data, STASH_CMD_RIGHT_QUERY) != 0) {
		printf(" QUERY");
	}
	
	if (risp_isset(master->risp_data, STASH_CMD_RIGHT_LOCK) != 0) {
		printf(" LOCK");
	}
	
	printf("\n");
}



static void cmdCreateTable(master_t *master, risp_length_t length, void *data)
{
	nsid_t nsid = 0;
	tableid_t tid = 0;
	char *tablename;
	
	risp_length_t processed;
	
	assert(master);
	assert(length > 0);
	assert(data);
	
	assert(master->risp_data);
	risp_clear_all(master->risp_data);
	processed = risp_process(master->risp_data, NULL, length, data);
	assert(processed == length);
	
	
	// if we have a namespace, get it.
	assert(risp_isset(master->risp_data, STASH_CMD_NAMESPACE_ID));
	nsid = risp_getvalue(master->risp_data, STASH_CMD_NAMESPACE_ID);
	assert(nsid > 0);
		
	assert(risp_isset(master->risp_data, STASH_CMD_TABLE_ID));
	tid = risp_getvalue(master->risp_data, STASH_CMD_TABLE_ID);
	assert(tid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_TABLE));
	tablename = risp_getstring(master->risp_data, STASH_CMD_TABLE);
	assert(tablename);
		
	printf("Create Table: [nsid:%d, tid:%d] '%s'", nsid, tid, tablename);
	
	if (risp_isset(master->risp_data, STASH_CMD_STRICT) != 0)    { printf(" STRICT"); }
	if (risp_isset(master->risp_data, STASH_CMD_UNIQUE) != 0)    { printf(" UNIQUE"); }
	if (risp_isset(master->risp_data, STASH_CMD_OVERWRITE) != 0) { printf(" OVERWRITE"); }
	
	printf("\n");
}


static void cmdCreateKey(master_t *master, risp_length_t length, void *data)
{
	nsid_t nsid = 0;
	tableid_t tid = 0;
	keyid_t kid = 0;
	char *keyname;
	
	risp_length_t processed;
	
	assert(master);
	assert(length > 0);
	assert(data);
	
	assert(master->risp_data);
	risp_clear_all(master->risp_data);
	processed = risp_process(master->risp_data, NULL, length, data);
	assert(processed == length);
	
	
	// if we have a namespace, get it.
	assert(risp_isset(master->risp_data, STASH_CMD_NAMESPACE_ID));
	nsid = risp_getvalue(master->risp_data, STASH_CMD_NAMESPACE_ID);
	assert(nsid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_TABLE_ID));
	tid = risp_getvalue(master->risp_data, STASH_CMD_TABLE_ID);
	assert(tid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_KEY_ID));
	kid = risp_getvalue(master->risp_data, STASH_CMD_KEY_ID);
	assert(kid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_KEY));
	keyname = risp_getstring(master->risp_data, STASH_CMD_KEY);
	assert(keyname);
	
	printf("Create Key: [nsid:%d, tid:%d, kid:%d] '%s'\n", nsid, tid, kid, keyname);
}


static void cmdCreateName(master_t *master, risp_length_t length, void *data)
{
	nsid_t nsid = 0;
	tableid_t tid = 0;
	nameid_t nid = 0;
	char *rowname;
	
	risp_length_t processed;
	
	assert(master && length > 0 && data);
	
	assert(master->risp_data);
	risp_clear_all(master->risp_data);
	processed = risp_process(master->risp_data, NULL, length, data);
	assert(processed == length);
	
	
	// if we have a namespace, get it.
	assert(risp_isset(master->risp_data, STASH_CMD_NAMESPACE_ID));
	nsid = risp_getvalue(master->risp_data, STASH_CMD_NAMESPACE_ID);
	assert(nsid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_TABLE_ID));
	tid = risp_getvalue(master->risp_data, STASH_CMD_TABLE_ID);
	assert(tid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_NAME_ID));
	nid = risp_getvalue(master->risp_data, STASH_CMD_NAME_ID);
	assert(nid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_NAME));
	rowname = risp_getstring(master->risp_data, STASH_CMD_NAME);
	assert(rowname);
	
	printf("Create Name: [nsid:%d, tid:%d, nid:%d] '%s'\n", nsid, tid, nid, rowname);
}


static void cmdCreateRow(master_t *master, risp_length_t length, void *data)
{
	nsid_t nsid = 0;
	tableid_t tid = 0;
	nameid_t nid = 0;
	rowid_t rid = 0;
	
	risp_length_t processed;
	
	assert(master && length > 0 && data);
	
	assert(master->risp_data);
	risp_clear_all(master->risp_data);
	processed = risp_process(master->risp_data, NULL, length, data);
	assert(processed == length);
	
	assert(risp_isset(master->risp_data, STASH_CMD_ROW_ID));
	rid = risp_getvalue(master->risp_data, STASH_CMD_ROW_ID);
	assert(rid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_NAMESPACE_ID));
	nsid = risp_getvalue(master->risp_data, STASH_CMD_NAMESPACE_ID);
	assert(nsid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_TABLE_ID));
	tid = risp_getvalue(master->risp_data, STASH_CMD_TABLE_ID);
	assert(tid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_NAME_ID));
	nid = risp_getvalue(master->risp_data, STASH_CMD_NAME_ID);
	assert(nid > 0);
	
	printf("Create Row: [nsid:%d, tid:%d, nid:%d, rid:%d]\n", nsid, tid, nid, rid);
}


static void cmdSet(master_t *master, risp_length_t length, void *data)
{
	nsid_t nsid = 0;
	tableid_t tid = 0;
	rowid_t rid = 0;
	keyid_t kid = 0;
	risp_length_t val_len;
	
	risp_length_t processed;
	
	assert(master && length > 0 && data);
	
	assert(master->risp_data);
	risp_clear_all(master->risp_data);
	processed = risp_process(master->risp_data, NULL, length, data);
	assert(processed == length);
	
	assert(risp_isset(master->risp_data, STASH_CMD_ROW_ID));
	rid = risp_getvalue(master->risp_data, STASH_CMD_ROW_ID);
	assert(rid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_NAMESPACE_ID));
	nsid = risp_getvalue(master->risp_data, STASH_CMD_NAMESPACE_ID);
	assert(nsid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_TABLE_ID));
	tid = risp_getvalue(master->risp_data, STASH_CMD_TABLE_ID);
	assert(tid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_KEY_ID));
	kid = risp_getvalue(master->risp_data, STASH_CMD_KEY_ID);
	assert(kid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_VALUE));
	val_len = risp_getlength(master->risp_data, STASH_CMD_VALUE);
	assert(val_len > 0);
	
	printf("Set Attribute: [nsid:%d, tid:%d, rid:%d, kid:%d, val-len:%d]\n", nsid, tid, rid, kid, val_len);
}


static void cmdDelete(master_t *master, risp_length_t length, void *data)
{
	nsid_t nsid = 0;
	tableid_t tid = 0;
	rowid_t rid = 0;
	keyid_t kid = 0;
	
	risp_length_t processed;
	
	assert(master && length > 0 && data);
	
	assert(master->risp_data);
	risp_clear_all(master->risp_data);
	processed = risp_process(master->risp_data, NULL, length, data);
	assert(processed == length);
	
	assert(risp_isset(master->risp_data, STASH_CMD_ROW_ID));
	rid = risp_getvalue(master->risp_data, STASH_CMD_ROW_ID);
	assert(rid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_NAMESPACE_ID));
	nsid = risp_getvalue(master->risp_data, STASH_CMD_NAMESPACE_ID);
	assert(nsid > 0);
	
	assert(risp_isset(master->risp_data, STASH_CMD_TABLE_ID));
	tid = risp_getvalue(master->risp_data, STASH_CMD_TABLE_ID);
	assert(tid > 0);
	
	if(risp_isset(master->risp_data, STASH_CMD_KEY_ID)) {
		kid = risp_getvalue(master->risp_data, STASH_CMD_KEY_ID);
		assert(kid > 0);
	}
	
	printf("Delete: [nsid:%d, tid:%d, rid:%d, kid:%d]\n", nsid, tid, rid, kid);
}




//-----------------------------------------------------------------------------
// Main... process command line parameters, and if we have enough information, then create an empty stash.
int main(int argc, char **argv) 
{
	int c;
	master_t master;
	storage_t *storage;
	
	const char *filename = NULL;
	
	assert(argc >= 0);
	assert(argv);
	
	// initialise the master structure that we will be passing through the risp process.
	master.risp_top = NULL;
	master.risp_op = NULL;
	master.risp_payload = NULL;
	master.risp_data = NULL;
	
	
	// process arguments
	/// Need to check the options in here, there're possibly ones that we dont need.
	while ((c = getopt(argc, argv, "hvf:")) != -1) {
		switch (c) {
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'v':
				verbose++;
				break;
			case 'f':
				filename = optarg;
				break;
				
			default:
				fprintf(stderr, "Illegal argument \"%c\"\n", c);
				exit(1);
		}
	}
	
	// check that our required params are there:
	if (filename == NULL) {
		fprintf(stderr, "requires: -f <filename>\n");
		exit(1);
	}

	// create the top-level risp interface.
	master.risp_top = risp_init(NULL);
	assert(master.risp_top != NULL);
	risp_add_command(master.risp_top, STASH_CMD_CLEAR,         &cmdClear);
	risp_add_command(master.risp_top, STASH_CMD_FILE_SEQ,      &cmdFileSeq);
	risp_add_command(master.risp_top, STASH_CMD_OPERATION,     &cmdOperation);
	risp_add_command(master.risp_top, STASH_CMD_NEXT_VOLUME,   &cmdNextVolume);

	master.risp_op = risp_init(NULL);
	assert(master.risp_op);
	
	master.risp_payload = risp_init(NULL);
	assert(master.risp_payload);
	risp_add_command(master.risp_payload, STASH_CMD_CREATE_USER,      &cmdCreateUser);
	risp_add_command(master.risp_payload, STASH_CMD_CREATE_NAMESPACE, &cmdCreateNamespace);
	risp_add_command(master.risp_payload, STASH_CMD_SET_PASSWORD,     &cmdSetPassword);
	risp_add_command(master.risp_payload, STASH_CMD_GRANT,            &cmdGrant);
	risp_add_command(master.risp_payload, STASH_CMD_CREATE_TABLE,     &cmdCreateTable);
	risp_add_command(master.risp_payload, STASH_CMD_CREATE_KEY,       &cmdCreateKey);
	risp_add_command(master.risp_payload, STASH_CMD_CREATE_NAME,      &cmdCreateName);
	risp_add_command(master.risp_payload, STASH_CMD_CREATE_ROW,       &cmdCreateRow);
	risp_add_command(master.risp_payload, STASH_CMD_SET,              &cmdSet);
	risp_add_command(master.risp_payload, STASH_CMD_DELETE,           &cmdDelete);
	
	
	// 	risp_add_command(master.risp_payload, STASH_CMD_DROP_USER,       &cmdDropUser);
	
	master.risp_data = risp_init(NULL);
	assert(master.risp_data);
	
	storage = storage_init(NULL);
	assert(storage);
		
	if (storage_lock_file(storage, filename) == 0) {
		fprintf(stderr, "Unable to open file, it appears to be locked.\n");
		exit(1);
	}
	else {
		
		// we were able to lock the file, so we can continue.   From this point on, we cannot exit without unlocking the file.
		
		// TODO: We should intercept the signals at this point to ensure that the lock gets released.
		
		// process the main meta file;
		storage_process_file(storage, filename, master.risp_top, &master);
		
		storage_unlock_file(storage, filename);
		
	}

	// cleanup the risp interface.
	assert(master.risp_top);
	risp_shutdown(master.risp_top);
	master.risp_top = NULL;
	
	assert(master.risp_op);
	risp_shutdown(master.risp_op);
	master.risp_op = NULL;
	
	assert(master.risp_payload);
	risp_shutdown(master.risp_payload);
	master.risp_payload = NULL;
	
	assert(master.risp_data);
	risp_shutdown(master.risp_data);
	master.risp_data = NULL;
	

	assert(storage);
	storage_free(storage);
	storage = NULL;

	assert(master.risp_top == NULL);
	
	return 0;
}



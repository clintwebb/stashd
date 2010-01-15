// stash-common.o

#include "stash-common.h"
#include <stash.h>

#include <assert.h>
#include <expbuf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>


#if (EXPBUF_VERSION < 0x00010200)
#error "Needs libexpbuf v1.02 or higher"
#endif


#if (RISP_VERSION < 0x00020200)
#error "Requires librisp v2.02 or higher"
#endif



#define MAX_PATH_LEN	2048


//-----------------------------------------------------------------------------
// before processing an operation, we should clear the op-data to default 
// values.  We do not clear the trans_hi value because it will only be provided 
// when it cycles up.  Therefore, we want to keep the trans_hi as it is.
static void clearOpData(storage_t *storage)
{
	assert(storage);
	
	storage->opdata.trans.lo = 0;
	storage->opdata.user_id = 0;
	storage->opdata.date = 0;
	storage->opdata.time = 0;
}

static void cmdFileSeq(storage_t *storage, risp_int_t value)
{
	assert(storage);
	assert(value >= 0);
	
	// if we get this, then we are obviously loading in a file.  We need to verify that this is the correct sequence we are expecting.
	assert(value == storage->curr_seq);	
}

//-----------------------------------------------------------------------------
// this command indicates that there is no more data to process from this file, 
// and that there is another file to open.  It should open the next file in the 
// sequence, and we already know what the current file is.  THerefore, we dont 
// need to provide the sequence number we are expecting.
static void cmdNextVolume(storage_t *storage) 
{
	assert(storage);
	
	// increment the value.
	assert(0);
}


static void cmdOperation(storage_t *storage, risp_length_t length, void *data)
{
	risp_length_t processed;
	risp_length_t plen;
	char *pdata;
	
	assert(storage);
	assert(length > 0);
	assert(data);
	
	clearOpData(storage);
	
	// we have data, that we need to put through the risp_op parser.  It will 
	// return some transaction details, and a payload.
	assert(storage->risp_op);
	risp_clear_all(storage->risp_op);
	processed = risp_process(storage->risp_op, NULL, length, data);
	assert(processed == length);
	
	// create an op-data object that we will put this data in.  It will be 
	// attached to some stored info, or discarded, but at this point, we dont 
	// yet know what we need to do with it.
	if ( risp_isset(storage->risp_op, STASH_CMD_TRANS_HI) != 0) {
		storage->opdata.trans.hi = risp_getvalue(storage->risp_op, STASH_CMD_TRANS_HI);
	}

	if ( risp_isset(storage->risp_op, STASH_CMD_TRANS_LO) != 0) {
		storage->opdata.trans.lo = risp_getvalue(storage->risp_op, STASH_CMD_TRANS_LO);
	}

	if ( risp_isset(storage->risp_op, STASH_CMD_USER_ID) != 0) {
		storage->opdata.user_id = risp_getvalue(storage->risp_op, STASH_CMD_USER_ID);
	}

	if ( risp_isset(storage->risp_op, STASH_CMD_DATE) != 0) {
		storage->opdata.date = risp_getvalue(storage->risp_op, STASH_CMD_DATE);
	}

	if ( risp_isset(storage->risp_op, STASH_CMD_TIME) != 0) {
		storage->opdata.time = risp_getvalue(storage->risp_op, STASH_CMD_TIME);
	}

	assert ( risp_isset(storage->risp_op, STASH_CMD_PAYLOAD) != 0);
	plen = risp_getlength(storage->risp_op, STASH_CMD_PAYLOAD);
	pdata = risp_getdata(storage->risp_op, STASH_CMD_PAYLOAD);

	assert(pdata);
	assert(plen > 0);

	// we have a new transactionID, so we can update our current value. and 
	// increment it.  If we roll-over then we increment the 'hi' value too.
	storage->next_trans = storage->opdata.trans;
	storage->next_trans.lo ++;
	if (storage->next_trans.lo == 0) {
		storage->next_trans.hi ++;
	}
	
	// now that we have everything setup ready to process the information, we 
	// need to parse the payload.  THe payload RISP interface will have 
	// callbacks for all the operational commands, so whatever needs to be 
	// done will be handled internally.  When the parse function has finished, 
	// there is nothing else for us to do.
	risp_clear_all(storage->risp_payload);
	processed = risp_process(storage->risp_payload, storage, plen, pdata);
	assert(processed == plen);
}


static void cmdCreateNamespace(storage_t *storage, risp_length_t length, void *data)
{
	char *namespace;
	nsid_t nsid;
	namespace_t *ns;
	risp_length_t processed;
	
	assert(storage);
	assert(length > 0);
	assert(data);
	
	assert(storage->risp_data);
	risp_clear_all(storage->risp_data);
	processed = risp_process(storage->risp_data, NULL, length, data);
	assert(processed == length);
	
	
	assert(risp_isset(storage->risp_data, STASH_CMD_NAMESPACE) != 0);
	assert(risp_isset(storage->risp_data, STASH_CMD_NAMESPACE_ID) != 0);
	namespace = risp_getstring(storage->risp_data, STASH_CMD_NAMESPACE);
	nsid = risp_getvalue(storage->risp_data, STASH_CMD_NAMESPACE_ID);
	assert(namespace);
	assert(nsid > 0);
	
	/// create namespace
	ns = malloc(sizeof(namespace_t));
	assert(ns);
	
	assert(nsid >= storage->next_ns_id);
	ns->id = nsid;
	storage->next_ns_id = nsid + 1;
	assert(storage->next_ns_id > nsid);
	
	assert(namespace);
	ns->name = strdup(namespace);
	assert(ns->name);
	
	ns->tables = ll_init(NULL);
	assert(ns->tables);
	
	// add the new namepsace to the namespace list.
	assert(storage->namespaces);
	ll_push_head(storage->namespaces, ns);
}


static void cmdCreateUsername(storage_t *storage, risp_length_t length, void *data)
{
	char *newuser;
	userid_t uid;
	user_t *user;
	risp_length_t processed;
	
	assert(storage);
	assert(length > 0);
	assert(data);
	
	assert(storage->risp_data);
	risp_clear_all(storage->risp_data);
	processed = risp_process(storage->risp_data, NULL, length, data);
	assert(processed == length);
	
	assert(risp_isset(storage->risp_data, STASH_CMD_USERNAME) != 0);
	assert(risp_isset(storage->risp_data, STASH_CMD_USER_ID) != 0);
	
	newuser = risp_getstring(storage->risp_data, STASH_CMD_USERNAME);
	uid = risp_getvalue(storage->risp_data, STASH_CMD_USER_ID);
	
	assert(newuser);
	assert(uid > 0);
	assert(uid >= storage->next_user_id);
	
	/// create user object
	user = malloc(sizeof(user_t));
	assert(user);
	
	user->uid = uid;
	
	assert(newuser);
	user->username = strdup(newuser);
	assert(user->username);
	
	user->password = NULL;
	
	user->rights = ll_init(NULL);
	assert(user->rights);
	
	assert(uid >= storage->next_user_id);
	storage->next_user_id = uid + 1;
	assert(storage->next_user_id > uid);
	
	// add the new user object to the users list.
	assert(storage->users);
	ll_push_head(storage->users, user);
}


static void cmdSetPassword(storage_t *storage, risp_length_t length, void *data)
{
	char *newpass = NULL;
	userid_t uid;
	user_t *user;
	risp_length_t processed;
	
	assert(storage);
	assert(length > 0);
	assert(data);
	
	assert(storage->risp_data);
	risp_clear_all(storage->risp_data);
	processed = risp_process(storage->risp_data, NULL, length, data);
	assert(processed == length);
	
	assert(risp_isset(storage->risp_data, STASH_CMD_USER_ID) != 0);
	uid = risp_getvalue(storage->risp_data, STASH_CMD_USER_ID);
	assert(uid > 0);
	
	if (risp_isset(storage->risp_data, STASH_CMD_PASSWORD) != 0) {
		newpass = risp_getstring(storage->risp_data, STASH_CMD_PASSWORD);
	}

	/// get user object
	user = storage_getuser(storage, uid, NULL);
	assert(user);
	assert(user->uid = uid);
	assert(user->username);
	
	if (newpass) {
		user->password = strdup(newpass);
		assert(user->password);
	}
	else {
		user->password = NULL;
	}
}


static void cmdGrant(storage_t *storage, risp_length_t length, void *data)
{
	userid_t uid;
	user_t *user;
	nsid_t nsid;
	namespace_t *ns;
	tableid_t tid;
	table_t *table;
	unsigned short rights_map = 0;
	right_t *tmp, *right;
	
	
	risp_length_t processed;
	
	assert(storage);
	assert(length > 0);
	assert(data);
	
	assert(storage->risp_data);
	risp_clear_all(storage->risp_data);
	processed = risp_process(storage->risp_data, NULL, length, data);
	assert(processed == length);

	// get the userid.
	assert(risp_isset(storage->risp_data, STASH_CMD_USER_ID) != 0);
	uid = risp_getvalue(storage->risp_data, STASH_CMD_USER_ID);
	assert(uid > 0);
	user = storage_getuser(storage, uid, NULL);
	assert(user);
	
	// if we have a namespace, get it.
	ns = NULL;
	table = NULL;
	if (risp_isset(storage->risp_data, STASH_CMD_NAMESPACE_ID) != 0) {
		nsid = risp_getvalue(storage->risp_data, STASH_CMD_NAMESPACE_ID);
		assert(nsid > 0);
		ns = storage_getnamespace(storage, nsid, NULL);
		assert(ns);
		
		if (risp_isset(storage->risp_data, STASH_CMD_TABLE_ID) != 0) {
			tid = risp_getvalue(storage->risp_data, STASH_CMD_TABLE_ID);
			assert(tid > 0);
			table = storage_gettable(storage, ns, tid, NULL);
			assert(table);
		}
	}

	assert(rights_map == 0);
	
	if (risp_isset(storage->risp_data, STASH_CMD_RIGHT_ADDUSER) != 0) {
		rights_map |= STASH_RIGHT_ADDUSER;
	}

	if (risp_isset(storage->risp_data, STASH_CMD_RIGHT_CREATE) != 0) {
		rights_map |= STASH_RIGHT_CREATE;
	}

	if (risp_isset(storage->risp_data, STASH_CMD_RIGHT_DROP) != 0) {
		rights_map |= STASH_RIGHT_DROP;
	}

	if (risp_isset(storage->risp_data, STASH_CMD_RIGHT_SET) != 0) {
		rights_map |= STASH_RIGHT_SET;
	}

	if (risp_isset(storage->risp_data, STASH_CMD_RIGHT_UPDATE) != 0) {
		rights_map |= STASH_RIGHT_UPDATE;
	}

	if (risp_isset(storage->risp_data, STASH_CMD_RIGHT_DELETE) != 0) {
		rights_map |= STASH_RIGHT_DELETE;
	}
	
	if (risp_isset(storage->risp_data, STASH_CMD_RIGHT_QUERY) != 0) {
		rights_map |= STASH_RIGHT_QUERY;
	}
	
	if (risp_isset(storage->risp_data, STASH_CMD_RIGHT_LOCK) != 0) {
		rights_map |= STASH_RIGHT_LOCK;
	}
	
	assert(rights_map != 0);

	/// the user has a rights list.  See if we can find this combination in 
	/// the rights list already.
	
	// the rights for a user are kept in a linked list.  We need to go through 
	// the linked list to see if this user/namespace/table combo already 
	// exists.  If it does, then OR the new rights to it.
	right = NULL;
	assert(user->rights);
	ll_start(user->rights);
	while (right == NULL && (tmp = ll_next(user->rights))) {
		if (tmp->ns == ns && tmp->table == table) {
			right = tmp;
			assert(right->rights_map != 0);
		}
	}
	ll_finish(user->rights);
	
	if (right) {
		// found the right.
		right->rights_map |= rights_map;
	}
	else {
		// right isn't there... 
		right = malloc(sizeof(right_t));
		right->ns = ns;
		right->table = table;
		right->rights_map = rights_map;
		ll_push_tail(user->rights, right);
	}
}




// free the table resources.  Before this is called, all related information should have been purged, such as grants and locks.
static void free_table(table_t *table) 
{
	assert(table);
	assert(table->tid > 0);
	assert(table->name);
	free(table->name);
	table->name = NULL;	
	assert(table->ns);
	table->ns = NULL;
}


//-----------------------------------------------------------------------------
// clean out a namespace... either because the namespace has been deleted, or 
// the system is shutting down.
static void free_namespace(namespace_t *ns)
{
	table_t *table;
	
	assert(ns);
	assert(ns->id > 0);
	
	assert(ns->tables);
	while ((table = ll_pop_head(ns->tables))) {
		assert(table->tid > 0);
		free_table(table);
		free(table);
	}
	ll_free(ns->tables);
	ns->tables = NULL;
	
	// delete the contents of the namespace.
	assert(ns->name);
	free(ns->name);
	ns->name = NULL;	
}

// we are deleting something, possibly a namespace, table, name or key.   We have a payload that we parse and then we look at the values that are in there to determine what needs to be created.
static void cmdDelete(storage_t *storage, risp_length_t length, void *data)
{
	risp_length_t processed;
	
	assert(storage);
	assert(length > 0);
	assert(data);
	
	assert(storage->risp_data);
	risp_clear_all(storage->risp_data);
	processed = risp_process(storage->risp_data, NULL, length, data);
	assert(processed == length);
	
	// now delete whatever is being deleted.
	assert(0);
}




// Initialise a storage object (or create one if none is provided).
storage_t * storage_init(storage_t *st)
{
	storage_t *storage;
	
	if (st == NULL) {
		storage = malloc(sizeof(storage_t));
		storage->internally_created = 1;
	}
	else {
		storage = st;
		storage->internally_created = 0;
	}
	
	storage->locked_files = ll_init(NULL);
	assert(storage->locked_files);
	
	storage->loaddata = IGNORE_DATA;

	storage->opdata.trans.hi = 0;
	clearOpData(storage);
	
	// create the RISP processor.
	storage->risp_top = risp_init(NULL);
	assert(storage->risp_top);
	risp_add_command(storage->risp_top, STASH_CMD_OPERATION,     &cmdOperation);
	risp_add_command(storage->risp_top, STASH_CMD_FILE_SEQ,      &cmdFileSeq);
	risp_add_command(storage->risp_top, STASH_CMD_NEXT_VOLUME,   &cmdNextVolume);
	
	// the following risp objects do not have any commands in it.  It 
	// receives the data component from a command payload and parses them.  
	// The data is then retrieved from the object as needed.  It should be 
	// cleared before and possibly after use.
	
	storage->risp_op = risp_init(NULL);
	assert(storage->risp_op);
	
	storage->risp_payload = risp_init(NULL);
	assert(storage->risp_payload);
	risp_add_command(storage->risp_payload, STASH_CMD_CREATE_NAMESPACE,   &cmdCreateNamespace);
	risp_add_command(storage->risp_payload, STASH_CMD_CREATE_USER,        &cmdCreateUsername);
	risp_add_command(storage->risp_payload, STASH_CMD_SET_PASSWORD,       &cmdSetPassword);
	risp_add_command(storage->risp_payload, STASH_CMD_GRANT,              &cmdGrant);
	
	// 	risp_add_command(storage->risp_payload, STASH_CMD_DELETE,     &cmdDelete);
	
	storage->risp_data = risp_init(NULL);
	assert(storage->risp_data);

	
	storage->next_user_id = 1;
	storage->users = ll_init(NULL);	// user_t
	assert(storage->users);
	
	storage->next_ns_id = 1;
	storage->namespaces = ll_init(NULL);
	assert(storage->namespaces);
	
	storage->curr_seq = 0;
	storage->next_seq = 0;
	
	
	storage->next_trans.hi = 0;
	storage->next_trans.lo = 1;
	
	storage->file_handle = -1;
	storage->file_size = 0;
	
	storage->update_callback = NULL;
	storage->update_usrptr = NULL;
	
	return(storage);
}

static void free_user(user_t *user)
{
	assert(user);
	assert(user->uid > 0);
	
	assert(user->username);
	free(user->username);
	user->username = NULL;
	
	if (user->password) {
		free(user->password);
		user->password = NULL;
	}
}



// release resources that were allocated for the storage object.  If the object was created internally, then free it too.
void storage_free(storage_t *storage) 
{
	char *lockfile;
	namespace_t *namespace;
	user_t *user;
	
	assert(storage);
	
	// if we have the file open, we need to close it.
	if (storage->file_handle >= 0) {
		flock(storage->file_handle, LOCK_UN);
		close(storage->file_handle);
	}
	
	assert(storage->users);
	while ((user = ll_pop_head(storage->users))) {
		free_user(user);
		free(user);
	}
	ll_free(storage->users);
	storage->users = NULL;
	
	assert(storage->namespaces);
	while ((namespace = ll_pop_head(storage->namespaces))) {
		// delete the namespace
		free_namespace(namespace);
		free(namespace);
	}
	ll_free(storage->namespaces);
	storage->namespaces = NULL;
	
	// we need to clear out all the RISP parsing interfaces.
	assert(storage->risp_data);
	risp_shutdown(storage->risp_data);
	storage->risp_data = NULL;

	assert(storage->risp_payload);
	risp_shutdown(storage->risp_payload);
	storage->risp_payload = NULL;
	
	assert(storage->risp_op);
	risp_shutdown(storage->risp_op);
	storage->risp_op = NULL;
	
	assert(storage->risp_top);
	risp_shutdown(storage->risp_top);
	storage->risp_top = NULL;
	
	// if we have any locked files, then we will need to unlock them.  For now though, we should fire an assert, because if we get this far and haven't unlocked the files, then it indicates a logic flaw that should be examined.
	assert(storage->locked_files);
	while ((lockfile = ll_pop_head(storage->locked_files))) {
		assert(0);
		// need to delete the lock file if it is there.
	}
	ll_free(storage->locked_files);
	storage->locked_files = NULL;
	
	if (storage->internally_created == 1) {
		free(storage);
	}
}




int storage_lock_file(storage_t *storage, const char *filename)
{
	char *lockname;
	FILE *fp;
	
	assert(storage);
	assert(filename);
	
	// build lock filename.
	lockname = malloc(strlen(filename) + 6);
	sprintf(lockname, "%s.lock", filename);
	
	// check to see if lock file exists.
	fp = fopen(lockname, "r");
	if (fp != NULL) {
		fclose(fp);
		free(lockname);
		return(0);
	}
	else {
		fp = fopen(lockname, "w");
		assert(fp);
		fclose(fp);
		
		// add the lock to the list in storage so that 
		ll_push_head(storage->locked_files, lockname);
		
		return(1);
	}
}



void storage_unlock_file(storage_t *storage, const char *filename)
{
	char *lockname;
	char *entry;
	
	assert(storage);
	assert(filename);
	
	// build lock filename.
	lockname = malloc(strlen(filename) + 6);
	sprintf(lockname, "%s.lock", filename);
	
	
	unlink(lockname);
	
	// find the entry in our link-list and remove it.
	assert(storage->locked_files);
	ll_start(storage->locked_files);
	while ((entry = ll_next(storage->locked_files))) {
		if (strcmp(lockname, entry) == 0) {
			ll_remove(storage->locked_files, entry);
		}
	}
	ll_finish(storage->locked_files);
	
}

int storage_lock_master(storage_t *storage, const char *basedir)
{
	int result, n;
	char filename[MAX_PATH_LEN];
	
	n = snprintf(filename, MAX_PATH_LEN, "%s/master", basedir);
	assert(n < MAX_PATH_LEN);
	result = storage_lock_file(storage, filename);
	return (result);
}
void storage_unlock_master(storage_t *storage, const char *basedir)
{
	int n;
	char filename[MAX_PATH_LEN];
	
	n = snprintf(filename, MAX_PATH_LEN, "%s/master", basedir);
	assert(n < MAX_PATH_LEN);
	storage_unlock_file(storage, filename);
}



//-----------------------------------------------------------------------------
// this function is used to load in the contents of the file, and parse it 
// through the risp processor.  Nothing more complicated than that.
void storage_process_file(storage_t *storage, const char *filename, risp_t *risp, void *usrdata)
{
	int handle;
	expbuf_t overflow;
	char buffer[INIT_BUF_SIZE];
	int done;
	ssize_t len;
	risp_length_t processed;
	
	assert(storage);
	assert(filename);
	assert(risp);
	
	// open the file (for reading).
	handle = open(filename, O_RDONLY);
	if (handle) {
		
		storage->file_size = 0;
		
		// create the buffers.
		expbuf_init(&overflow, INIT_BUF_SIZE);
		
		// lock the file.
		flock(handle, LOCK_SH);
		
		// while data is available.
		done = 0;
		while (done == 0) {
			
			// read data in to the buffer.
			len = read(handle, buffer, sizeof(buffer));
			if (len < 0) {
				// there was an error....
				assert(0);
				done = 1;
			}
			else if (len == 0) {
				// we didn't get anything back, we should exit.
				done = 1;
			}
			else {
				storage->file_size += len;
				
				// we got some data, need to add it to the overflow and then attempt to process it.
				expbuf_add(&overflow, buffer, len);
				
				// process the data.
				processed = risp_process(risp, usrdata, BUF_LENGTH(&overflow), BUF_DATA(&overflow));
				expbuf_purge(&overflow, processed);
			}
		}
		
		// unlock the file.
		flock(handle, LOCK_UN);
		
		// close the file.
		close(handle);
		
		// there should not be any unprocessed data in the buffer.
		assert(BUF_LENGTH(&overflow) == 0);
		
		// release the buffer.
		expbuf_free(&overflow);
	}	
}


void storage_process(storage_t *storage, const char *path, __storage_keepopen_e keep_open, __storage_loaddata_e load_data)
{
	char fullpath[MAX_PATH_LEN];
	int n;
	
	assert(storage);
	assert(path);

	// make sure that the storage object is empty.
	assert(ll_count(storage->namespaces) == 0);

	storage->loaddata = load_data;
	
	// the file loop.
	storage->next_seq = 0;
	storage->curr_seq = storage->next_seq - 1;
	while (storage->next_seq > storage->curr_seq) {
		
		storage->curr_seq = storage->next_seq;

		n = snprintf(fullpath, MAX_PATH_LEN, "%s/%08d.stash", path, storage->curr_seq);
		assert(n < MAX_PATH_LEN);

		storage_process_file(storage, fullpath, storage->risp_top, storage);
	}
	
	// if we are supposed to keep the database open, then we need to open it now.
	if (keep_open == KEEP_OPEN) {
		n = snprintf(fullpath, MAX_PATH_LEN, "%s/%08d.stash", path, storage->next_seq);
		assert(storage->file_handle < 0);
		
		// open the file (for reading).
		storage->file_handle = open(fullpath, O_WRONLY | O_APPEND);
		if (storage->file_handle) {	
			// lock the file.
			flock(storage->file_handle, LOCK_EX);
		}
	}
}


int storage_namespace_avail(storage_t *storage, const char *namespace)
{
	int result = 1;
	namespace_t *ns;
	
	assert(storage);
	assert(namespace);
	
	assert(storage->namespaces);
	ll_start(storage->namespaces);
	while (result == 1 && (ns = ll_next(storage->namespaces))) {
		// check the name of the namespace to see if it is the one we are looking for.  if so, then set result to 0.
		assert(ns->name);
		assert(ns->id > 0);
		
		if (strcmp(ns->name, namespace) == 0) {
			// we found the namespace we are looking for, therefore it is not available.
			result = 0;
		}
	}
	ll_finish(storage->namespaces);
	
	return(result);
}


// return 0 if the username is already in use.  Return 1 if it is available.
int storage_username_avail(storage_t *storage, const char *username)
{
	int result = 1;
	user_t *user;
	
	assert(storage);
	assert(username);
	
	assert(storage->users);
	ll_start(storage->users);
	while (result == 1 && (user = ll_next(storage->users))) {
		// check the name of the namespace to see if it is the one we are looking for.  if so, then set result to 0.
		assert(user->username);
		assert(user->uid > 0);
		
		if (strcmp(user->username, username) == 0) {
			// we found the namespace we are looking for, therefore it is not available.
			result = 0;
		}
	}
	ll_finish(storage->users);
	
	return(result);
}


//-----------------------------------------------------------------------------
// this will add the buffer as a payload to an operation.  It will add it to 
// the file, parse the stream locally, and if set, call the callback to notify 
// network clients (slave servers) of the change.
static void saveOperation(storage_t *storage, expbuf_t *buf, userid_t userid)
{
	expbuf_t buf_op;
	expbuf_t buf_top;
	int n;
	
	assert(storage);
	assert(buf);
	assert(userid >= 0);
	
	assert(BUF_LENGTH(buf) > 0);

	
	// build operation
	expbuf_init(&buf_op, 0);
	addCmdLargeInt(&buf_op, STASH_CMD_TRANS_HI, storage->next_trans.hi);
	addCmdLargeInt(&buf_op, STASH_CMD_TRANS_LO, storage->next_trans.lo);
	if (userid > 0) {
		addCmdLargeInt(&buf_op, STASH_CMD_USER_ID, userid);
	}
// 	STASH_CMD_DATE <int32>
// 	STASH_CMD_TIME <int32>
	addCmdLargeStr(&buf_op, STASH_CMD_PAYLOAD, BUF_LENGTH(buf), BUF_DATA(buf));
	
	expbuf_init(&buf_top, 0);
	addCmdLargeStr(&buf_top, STASH_CMD_OPERATION, BUF_LENGTH(&buf_op), BUF_DATA(&buf_op));
	
	// add to file queue
	// at this point, we should have a file handle open, and ready for writing.
	assert(storage->file_handle >= 0);
	
	// write the data to the file.
	n = write(storage->file_handle, BUF_DATA(&buf_top), BUF_LENGTH(&buf_top));
	assert(n == BUF_LENGTH(&buf_top));
	
	// increment our file-size counter.
	storage->file_size += n;
	
	// if we are over our file-size limit, then close the file and create a new one.
	if (storage->file_size >= MAX_FILESIZE) { 
		assert(0);
	}

	// parse the operation internally.
	cmdOperation(storage, BUF_LENGTH(&buf_op), BUF_DATA(&buf_op));
	
	// if update-callback is set, call callback function (for syncing network nodes).
	if (storage->update_callback) {
		assert(0);
	}
	
	expbuf_free(&buf_top);
	expbuf_free(&buf_op);
}



// create the transaction for the create operation.
nsid_t storage_create_namespace(storage_t *storage, userid_t requestor, const char *namespace)
{
	expbuf_t buf_data;
	expbuf_t buf_create;
	int slen;
	nsid_t id = 0;
	
	assert(storage);
	assert(namespace);
	assert(requestor >= 0);
	
	slen = strlen(namespace);
	assert(slen > 0 && slen < 256);
	
	// id of the namespace that we are creating.  When the operation is 
	// processed, it will increment the next value.
	id = storage->next_ns_id;
	
	// build the data buffer
	expbuf_init(&buf_data, 32);
	assert(id > 0);
	addCmdInt(&buf_data, STASH_CMD_NAMESPACE_ID, id);
	addCmdShortStr(&buf_data, STASH_CMD_NAMESPACE, slen, namespace);
	
	// build the 'create' buffer.
	expbuf_init(&buf_create, 0);
	addCmdStr(&buf_create, STASH_CMD_CREATE_NAMESPACE, BUF_LENGTH(&buf_data), BUF_DATA(&buf_data));
	
	// call the new operation function, which will queeue the data to be sent to the transaction log, and also to be read back in so that our internal systems are updated.
	saveOperation(storage, &buf_create, requestor);
	
	expbuf_free(&buf_create);
	expbuf_free(&buf_data);
	
	assert(id > 0);
	return(id);
}


userid_t storage_create_username(storage_t *storage, userid_t requestor, const char *newuser)
{
	expbuf_t buf_data;
	expbuf_t buf_create;
	int slen;
	userid_t uid;
	
	assert(storage);
	assert(requestor >= 0);
	assert(newuser);
	
	slen = strlen(newuser);
	assert(slen > 0 && slen < 256);
	
	uid = storage->next_user_id;
	
	// build the data buffer
	expbuf_init(&buf_data, 32);
	assert(uid > 0);
	addCmdLargeInt(&buf_data, STASH_CMD_USER_ID, uid);
	addCmdShortStr(&buf_data, STASH_CMD_USERNAME, slen, newuser);
	
	// build the 'create' buffer.
	expbuf_init(&buf_create, 0);
	addCmdStr(&buf_create, STASH_CMD_CREATE_USER, BUF_LENGTH(&buf_data), BUF_DATA(&buf_data));
	
	// call the new operation function, which will queeue the data to be sent to the transaction log, and also to be read back in so that our internal systems are updated.
	saveOperation(storage, &buf_create, requestor);
	
	expbuf_free(&buf_create);
	expbuf_free(&buf_data);
	
	assert(uid > 0);
	return(uid);
}


// go thru the users list and find the uid we are looking for.   Provide either the uid, or the username.  If we dont know the uid, then use 0 or NULL_USER_ID.  If we dont know the username, use NULL.  
user_t * storage_getuser(storage_t *storage, userid_t uid, const char *username)
{
	user_t *user;
	user_t *tmp;
	
	assert(storage);
	assert((uid == 0 && username) || (username == NULL && uid > 0) || (username && uid > 0));
	
	user = NULL;
	assert(storage->users);
	ll_start(storage->users);
	while (user == NULL && (tmp = ll_next(storage->users))) {
		if ((uid > 0 && tmp->uid == uid) || (username && strcmp(tmp->username, username) == 0)) {
			// we found the user we are looking for, so move it to the top of 
			// the list, and then return it.
			ll_move_head(storage->users, tmp);
			user = tmp;
		}
	}
	ll_finish(storage->users);
	
	return(user);
}

namespace_t * storage_getnamespace(storage_t *storage, nsid_t nsid, const char *namespace)
{
	namespace_t *ns;
	namespace_t *tmp;
	
	assert(storage);
	assert((nsid == 0 && namespace) || (nsid > 0 && namespace == NULL) || (nsid > 0 && namespace));
	
	ns = NULL;
	assert(storage->namespaces);
	ll_start(storage->namespaces);
	while (ns == NULL && (tmp = ll_next(storage->namespaces))) {
		if ((nsid > 0 && tmp->id == nsid) || (namespace && strcmp(tmp->name, namespace) == 0)) {
			// we found the user we are looking for, so move it to the top of 
			// the list, and then return it.
			ll_move_head(storage->namespaces, tmp);
			ns = tmp;
			assert(ns->id > 0);
			assert(ns->name);
			assert(ns->tables);
		}
	}
	ll_finish(storage->namespaces);
	
	return(ns);
}

table_t * storage_gettable(storage_t *storage, namespace_t *ns, tableid_t tid, const char *table)
{
	table_t *tab;
	table_t *tmp;
	
	assert(storage);
	assert((tid == 0 && table) || (tid > 0 && table == NULL) || (tid > 0 && table));
	assert(ns);
	
	tab = NULL;
	assert(ns->tables);
	ll_start(ns->tables);
	while (tab == NULL && (tmp = ll_next(ns->tables))) {
		if ((tid > 0 && tmp->tid == tid) || (table && strcmp(tmp->name, table) == 0)) {
			// we found the user we are looking for, so move it to the top of 
			// the list, and then return it.
			ll_move_head(ns->tables, tmp);
			tab = tmp;
			assert(tab->tid > 0);
			assert(tab->name);
			assert(ns->tables);
		}
	}
	ll_finish(storage->namespaces);
	
	return(tab);
}



void storage_set_password(storage_t *storage, userid_t requestor, userid_t uid, const char *newpass)
{
	expbuf_t buf_data;
	expbuf_t buf_create;
	int slen;
	user_t *user;
	
	assert(storage);
	assert(requestor >= 0);
	assert(uid > 0);
	assert(newpass);
	
	slen = strlen(newpass);
	assert(slen > 0 && slen < 256);
	
	// need to go thru the list of users to make sure that this userid is valid.
	user = storage_getuser(storage, uid, NULL);
	assert(user);
	assert(user->username);
	
	// build the data buffer
	expbuf_init(&buf_data, 32);
	assert(uid > 0);
	addCmdLargeInt(&buf_data, STASH_CMD_USER_ID, uid);
	addCmdShortStr(&buf_data, STASH_CMD_PASSWORD, slen, newpass);
	
	// build the 'create' buffer.
	expbuf_init(&buf_create, 0);
	addCmdStr(&buf_create, STASH_CMD_SET_PASSWORD, BUF_LENGTH(&buf_data), BUF_DATA(&buf_data));
	
	// call the new operation function, which will queeue the data to be sent to the transaction log, and also to be read back in so that our internal systems are updated.
	saveOperation(storage, &buf_create, requestor);
	
	expbuf_free(&buf_create);
	expbuf_free(&buf_data);
}


// returns 0 if failed, returns non-zero if unable to set the grant.
// at this point we do not attempt to validate the grant, or even that the grant doesnt already exist.   If the grant already exists at this level, then 
void storage_grant(storage_t *storage, userid_t requestor, user_t *user, namespace_t *ns, table_t *table, unsigned short rights_map)
{
	expbuf_t buf_data;
	expbuf_t buf_create;
	
	assert(storage);
	assert(requestor == NULL_USER_ID || requestor > 0);
	assert(user);
	assert((ns == NULL && table == NULL) || (ns));
	assert(rights_map != 0);
	
	// need to go thru the list of users to make sure that this userid is valid.
	
	// build the data buffer
	expbuf_init(&buf_data, 32);
	assert(user->uid > 0);
	addCmdLargeInt(&buf_data, STASH_CMD_USER_ID, user->uid);
	
	if (ns) {
		addCmdLargeInt(&buf_data, STASH_CMD_NAMESPACE_ID, ns->id);
		
		if (table) {
			addCmdLargeInt(&buf_data, STASH_CMD_TABLE_ID, table->tid);
		}
	}

	if (rights_map & STASH_RIGHT_ADDUSER)	addCmd(&buf_data, STASH_CMD_RIGHT_ADDUSER);
	if (rights_map & STASH_RIGHT_CREATE)	addCmd(&buf_data, STASH_CMD_RIGHT_CREATE);
	if (rights_map & STASH_RIGHT_DROP)		addCmd(&buf_data, STASH_CMD_RIGHT_DROP);
	if (rights_map & STASH_RIGHT_SET)		addCmd(&buf_data, STASH_CMD_RIGHT_SET);
	if (rights_map & STASH_RIGHT_UPDATE)	addCmd(&buf_data, STASH_CMD_RIGHT_UPDATE);
	if (rights_map & STASH_RIGHT_DELETE)	addCmd(&buf_data, STASH_CMD_RIGHT_DELETE);
	if (rights_map & STASH_RIGHT_QUERY)		addCmd(&buf_data, STASH_CMD_RIGHT_QUERY);
	if (rights_map & STASH_RIGHT_LOCK)		addCmd(&buf_data, STASH_CMD_RIGHT_LOCK);

	// build the 'create' buffer.
	expbuf_init(&buf_create, 0);
	addCmdStr(&buf_create, STASH_CMD_GRANT, BUF_LENGTH(&buf_data), BUF_DATA(&buf_data));
	
	// call the new operation function, which will queeue the data to be sent 
	// to the transaction log, and also to be read back in so that our internal 
	// systems are updated.
	saveOperation(storage, &buf_create, requestor);
	
	expbuf_free(&buf_create);
	expbuf_free(&buf_data);
}


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


#if (EXPBUF_VERSION < 0x00010300)
#error "Needs libexpbuf v1.03 or higher"
#endif


#if (RISP_VERSION < 0x00020500)
#error "Requires librisp v2.05 or higher"
#endif



#define MAX_PATH_LEN 2048


//-----------------------------------------------------------------------------
// before processing an operation, we should clear the op-data to default 
// values.  We do not clear the trans_hi value because it will only be provided 
// when it cycles up.  Therefore, we want to keep the trans_hi as it is.
static void clearOpData(storage_t *storage)
{
	assert(storage);
	
	storage->opdata.trans.lo = 0;
	storage->opdata.user_id = 0;
	storage->opdata.datetime = 0;
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
	risp_data_t *pdata;
	
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
	if ( risp_isset(storage->risp_op, STASH_CMD_TRANS_HI)) {
		storage->opdata.trans.hi = risp_getvalue(storage->risp_op, STASH_CMD_TRANS_HI);
	}

	if ( risp_isset(storage->risp_op, STASH_CMD_TRANS_LO)) {
		storage->opdata.trans.lo = risp_getvalue(storage->risp_op, STASH_CMD_TRANS_LO);
	}

	if ( risp_isset(storage->risp_op, STASH_CMD_USER_ID)) {
		storage->opdata.user_id = risp_getvalue(storage->risp_op, STASH_CMD_USER_ID);
	}

	if ( risp_isset(storage->risp_op, STASH_CMD_DATETIME)) {
		storage->opdata.datetime = risp_getvalue(storage->risp_op, STASH_CMD_DATETIME);
	}

	assert(risp_isset(storage->risp_op, STASH_CMD_PAYLOAD));
	plen = risp_getlength(storage->risp_op, STASH_CMD_PAYLOAD);
	pdata = risp_getdata(storage->risp_op, STASH_CMD_PAYLOAD);

	assert(pdata);
	assert(plen > 0);

	// we have a new transactionID, so we can update our current value. and 
	// increment it.  If we roll-over then we increment the 'hi' value too.
	storage->next_trans = storage->opdata.trans;
	storage->next_trans.lo ++;
	if (storage->next_trans.lo <= 0) {
		storage->next_trans.hi ++;
		storage->next_trans.lo = 0;
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
	ns->next_id = 1;
	
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


static void cmdCreateTable(storage_t *storage, risp_length_t length, void *data)
{
	nsid_t nsid;
	namespace_t *ns;
	const char *tablename;
	tableid_t tid;
	table_t *table;
	risp_length_t processed;
	
	assert(storage);
	assert(length > 0);
	assert(data);
	
	assert(storage->risp_data);
	risp_clear_all(storage->risp_data);
	processed = risp_process(storage->risp_data, NULL, length, data);
	assert(processed == length);
	
	ns = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_NAMESPACE_ID));
	nsid = risp_getvalue(storage->risp_data, STASH_CMD_NAMESPACE_ID);
	assert(nsid > 0);
	ns = storage_getnamespace(storage, nsid, NULL);
	assert(ns);

	table = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_TABLE_ID));
	tid = risp_getvalue(storage->risp_data, STASH_CMD_TABLE_ID);
	assert(tid > 0);
	
	assert(tid >= ns->next_id);
	ns->next_id = tid + 1;
	
	assert(risp_isset(storage->risp_data, STASH_CMD_TABLE));
	tablename = risp_getstring(storage->risp_data, STASH_CMD_TABLE);
	assert(tablename);
	
	table = malloc(sizeof(table_t));
	assert(table);
	
	table->tid = tid;
	table->name = strdup(tablename);
	table->ns = ns;
	
	table->rows = ll_init(NULL);
	assert(table->rows);
	table->next_rid = 1;
	
	table->names = ll_init(NULL);
	assert(table->names);
	table->next_nid = 1;
	
	table->option_strict = 0;
	table->option_unique = 0;
	table->option_overwrite = 0;
	
	table->keys = ll_init(NULL);
	assert(table->keys);
	table->next_kid = 1;
	
	if (risp_isset(storage->risp_data, STASH_CMD_STRICT)) { table->option_strict = 1; }
	if (risp_isset(storage->risp_data, STASH_CMD_UNIQUE)) { table->option_unique = 1; }
	if (risp_isset(storage->risp_data, STASH_CMD_OVERWRITE)) { table->option_overwrite = 1; }
	
	// now we need to push the table onto the tables list.
	assert(ns->tables);
	ll_push_head(ns->tables, table);
}


static void cmdCreateName(storage_t *storage, risp_length_t length, void *data)
{
	namespace_t *ns;
	table_t *table;
	nameid_t nid;
	name_t *name;
	const char *namestr;
	risp_length_t processed;
	
	assert(storage);
	assert(length > 0);
	assert(data);
	
	assert(storage->risp_data);
	risp_clear_all(storage->risp_data);
	processed = risp_process(storage->risp_data, NULL, length, data);
	assert(processed == length);
	
	ns = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_NAMESPACE_ID));
	ns = storage_getnamespace(storage, risp_getvalue(storage->risp_data, STASH_CMD_NAMESPACE_ID), NULL);
	assert(ns);
	
	table = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_TABLE_ID));
	table = storage_gettable(storage, ns, risp_getvalue(storage->risp_data, STASH_CMD_TABLE_ID), NULL);
	assert(table);

// 	STASH_CMD_CREATE_NAME <>
// 		STASH_CMD_NAMESPACE_ID <int32>
// 		STASH_CMD_TABLE_ID <int32>
// 		STASH_CMD_NAME_ID <int32>
// 		STASH_CMD_NAME <string>
// 		STASH_CMD_TRANSIENT
	
	assert(risp_isset(storage->risp_data, STASH_CMD_NAME_ID));
	nid = risp_getvalue(storage->risp_data, STASH_CMD_NAME_ID);
	assert(nid >= table->next_nid);
	table->next_nid = nid + 1;
	
	assert(risp_isset(storage->risp_data, STASH_CMD_NAME));
	namestr = risp_getstring(storage->risp_data, STASH_CMD_NAME);
	assert(namestr);
	
	name = malloc(sizeof(name_t));
	assert(name);

	name->nid = nid;
	name->name = strdup(namestr);
	name->table = table;

	name->i_rowlist = ll_init(NULL);
	assert(name->i_rowlist);
	
	name->option_transient = 0;
	
	if (risp_isset(storage->risp_data, STASH_CMD_TRANSIENT)) { name->option_transient = 1; }
	
	// now we need to push the table onto the tables list.
	assert(table->names);
	ll_push_head(table->names, name);
}


static void cmdCreateKey(storage_t *storage, risp_length_t length, void *data)
{
	namespace_t *ns;
	table_t *table;
	keyid_t kid;
	skey_t *key;
	const char *keyname;
	risp_length_t processed;
	
	assert(storage);
	assert(length > 0);
	assert(data);
	
	assert(storage->risp_data);
	risp_clear_all(storage->risp_data);
	processed = risp_process(storage->risp_data, NULL, length, data);
	assert(processed == length);
	
	ns = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_NAMESPACE_ID));
	ns = storage_getnamespace(storage, risp_getvalue(storage->risp_data, STASH_CMD_NAMESPACE_ID), NULL);
	assert(ns);
	
	table = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_TABLE_ID));
	table = storage_gettable(storage, ns, risp_getvalue(storage->risp_data, STASH_CMD_TABLE_ID), NULL);
	assert(table);
	
	assert(risp_isset(storage->risp_data, STASH_CMD_KEY_ID));
	kid = risp_getvalue(storage->risp_data, STASH_CMD_KEY_ID);
	assert(kid >= table->next_kid);
	table->next_kid = kid + 1;
	
	assert(risp_isset(storage->risp_data, STASH_CMD_KEY));
	keyname = risp_getstring(storage->risp_data, STASH_CMD_KEY);
	assert(keyname);
	
	key = malloc(sizeof(skey_t));
	assert(key);
	
	key->kid = kid;
	key->name = strdup(keyname);
	key->table = table;
	
	key->i_attrlist = ll_init(NULL);
	assert(key->i_attrlist);
	
	key->auto_value = 1;
	
	// now we need to push the table onto the tables list.
	assert(table->keys);
	ll_push_head(table->keys, key);
}

// 	STASH_CMD_CREATE_ROW <>
// 		STASH_CMD_NAMESPACE_ID <int32>
// 		STASH_CMD_TABLE_ID <int32>
// 		STASH_CMD_NAME_ID <int32>
// 		STASH_CMD_EXPIRES <int32>     [optional]
static void cmdCreateRow(storage_t *storage, risp_length_t length, void *data)
{
	namespace_t *ns;
	table_t     *table;
	name_t      *name;
	rowid_t      rid;
	row_t       *row;
	risp_length_t processed;
	struct timeval tv;
	
	assert(storage && length > 0 && data);
	
	assert(storage->risp_data);
	risp_clear_all(storage->risp_data);
	processed = risp_process(storage->risp_data, NULL, length, data);
	assert(processed == length);
	
	ns = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_NAMESPACE_ID));
	ns = storage_getnamespace(storage, risp_getvalue(storage->risp_data, STASH_CMD_NAMESPACE_ID), NULL);
	assert(ns);
	
	table = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_TABLE_ID));
	table = storage_gettable(storage, ns, risp_getvalue(storage->risp_data, STASH_CMD_TABLE_ID), NULL);
	assert(table);

	name = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_NAME_ID));
	name = storage_getname(table, risp_getvalue(storage->risp_data, STASH_CMD_NAME_ID), NULL);
	assert(table);
	
	assert(risp_isset(storage->risp_data, STASH_CMD_ROW_ID));
	rid = risp_getvalue(storage->risp_data, STASH_CMD_ROW_ID);
	assert(rid >= table->next_rid);
	table->next_rid = rid + 1;
	
	row = calloc(1, sizeof(*row));
	assert(row);
	
	row->rid = rid;
	row->table = table;
	row->name = name;
	
	row->attrlist = ll_init(NULL);
	assert(row->attrlist);

	row->expires = 0;
	if (risp_isset(storage->risp_data, STASH_CMD_EXPIRES)) {
		// need to know the current time, and the time this operation was created.  Figured out the difference.
		gettimeofday(&tv, NULL);
		row->expires = tv.tv_sec + risp_getvalue(storage->risp_data, STASH_CMD_EXPIRES);
		
		// Since we are adding a row, even if it has expired, we still need to 
		// add it to the system in case there are other operations that are 
		// done on it (which would also have expired, but we have to load them 
		// still).
	}
	
	// add the row to the names list.
	assert(name);
	assert(name->i_rowlist);
	ll_push_head(name->i_rowlist, row);
	
	// now we need to push the row onto the rows list.
	assert(table->rows);
	ll_push_head(table->rows, row);
}


// 	STASH_CMD_SET <>
// 		STASH_CMD_NAMESPACE_ID <int32>
// 		STASH_CMD_TABLE_ID <int32>
// 		STASH_CMD_ROW_ID <int32>
// 		STASH_CMD_EXPIRES <int32>     [optional]
// 		STASH_CMD_KEY_ID <int32>
// 		STASH_CMD_VALUE <>
static void cmdSet(storage_t *storage, risp_length_t length, void *data)
{
	namespace_t *ns;
	table_t     *table;
	row_t       *row;
	skey_t      *key;
	value_t     *value;
	attr_t      *attr;
	risp_length_t processed;
	struct timeval tv;
	int expires;
	
	assert(storage && length > 0 && data);
	
	assert(storage->risp_data);
	risp_clear_all(storage->risp_data);
	processed = risp_process(storage->risp_data, NULL, length, data);
	assert(processed == length);
	
	ns = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_NAMESPACE_ID));
	ns = storage_getnamespace(storage, risp_getvalue(storage->risp_data, STASH_CMD_NAMESPACE_ID), NULL);
	assert(ns);
	
	table = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_TABLE_ID));
	table = storage_gettable(storage, ns, risp_getvalue(storage->risp_data, STASH_CMD_TABLE_ID), NULL);
	assert(table);
	
	row = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_ROW_ID));
	row = storage_getrow(storage, table, risp_getvalue(storage->risp_data, STASH_CMD_ROW_ID));
	assert(row);

	key = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_KEY_ID));
	key = storage_getkey(table, risp_getvalue(storage->risp_data, STASH_CMD_KEY_ID), NULL);
	assert(key);

	expires = 0;
	if (risp_isset(storage->risp_data, STASH_CMD_EXPIRES)) {
		// need to know the current time, and the time this operation was created.  Figured out the difference.
		gettimeofday(&tv, NULL);
		expires = tv.tv_sec + risp_getvalue(storage->risp_data, STASH_CMD_EXPIRES);
	}
	
	// need to get the value out.
	assert(risp_isset(storage->risp_data, STASH_CMD_VALUE));
	value = stash_parse_value(risp_getdata(storage->risp_data, STASH_CMD_VALUE), risp_getlength(storage->risp_data, STASH_CMD_VALUE));
	assert(value);
	assert(value->valtype != STASH_VALTYPE_AUTO);
	
	// now that we have all the data, we need to get the existing attribute for this key, from the row, if it exists.  If it doesn't exist, then we will need to create one.
	attr = NULL;
	attr = storage_getattr(row, key);
	
	if (attr) {
		// the attribute already exists.  So we need to replace it.
		assert(attr->value);
		assert(attr->row == row);
		assert(attr->key == key);
		
		stash_free_value(attr->value);
		attr->value = value;
		attr->expires = expires;
	}
	else {
		// that attribute didn't already exist, so we need to create one.
		attr = calloc(1, sizeof(*attr));
		assert(attr);
		attr->row = row;
		attr->key = key;
		attr->value = value;
		attr->expires = expires;
		
		// now we need to push the attribute onto the rows list.
		assert(row->attrlist);
		ll_push_head(row->attrlist, attr);
		
		// need to also push the attribute to to the key index.
		assert(key->i_attrlist);
		ll_push_head(key->i_attrlist, attr);
	}
}



static void cmdSetExpiry(storage_t *storage, risp_length_t length, void *data)
{
	namespace_t *ns;
	table_t     *table;
	row_t       *row;
	skey_t      *key;
	attr_t      *attr;
	risp_length_t processed;
	int expires;
	struct timeval tv;
	
	assert(storage && length > 0 && data);
	
	assert(storage->risp_data);
	risp_clear_all(storage->risp_data);
	processed = risp_process(storage->risp_data, NULL, length, data);
	assert(processed == length);
	
	ns = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_NAMESPACE_ID));
	ns = storage_getnamespace(storage, risp_getvalue(storage->risp_data, STASH_CMD_NAMESPACE_ID), NULL);
	assert(ns);
	
	table = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_TABLE_ID));
	table = storage_gettable(storage, ns, risp_getvalue(storage->risp_data, STASH_CMD_TABLE_ID), NULL);
	assert(table);
	
	row = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_ROW_ID));
	row = storage_getrow(storage, table, risp_getvalue(storage->risp_data, STASH_CMD_ROW_ID));
	assert(row);
	
	key = NULL;
	attr = NULL;
	if (risp_isset(storage->risp_data, STASH_CMD_KEY_ID)) {
		key = storage_getkey(table, risp_getvalue(storage->risp_data, STASH_CMD_KEY_ID), NULL);
		assert(key);
		// now that we have all the data, we need to get the existing attribute for this key, from the row, if it exists.  If it doesn't exist, then we will need to create one.
		attr = storage_getattr(row, key);
		assert(attr);
	}
	
	expires = 0;
	assert(risp_isset(storage->risp_data, STASH_CMD_EXPIRES));
	// need to know the current time, and the time this operation was created.  Figured out the difference.
	gettimeofday(&tv, NULL);
	expires = tv.tv_sec + risp_getvalue(storage->risp_data, STASH_CMD_EXPIRES);
	
	if (attr) {
		// the attribute already exists.  So we need to replace it.
		assert(attr->value);
		assert(attr->row == row);
		assert(attr->key == key);
		attr->expires = expires;
	}
	else {
		// that attribute didn't exist (or wasn't specified), so we need to expire the row instead.
		row->expires = expires;
	}
}

// free the resources inside the attribate object.  It will also remove this 
// attribute from the key index.
static void free_attr(attr_t *attr) 
{
	assert(attr);
	
	assert(attr->row);
	assert(attr->key);
	
	// free the value.
	assert(attr->value);
	stash_free_value(attr->value);
	
	
	// remove the attribute from the keylist.  The keylist is an index, and so 
	// we are just removing the index entries.
	assert(attr);
	assert(attr->key);
	assert(attr->key->i_attrlist);
	assert(ll_count(attr->key->i_attrlist) >= 0);
	
	// if we are deleting the table, then the index would have already been emptied.  Otherwise, we need to remove the attribute from the index.
	if (ll_count(attr->key->i_attrlist) > 0) {
		ll_remove(attr->key->i_attrlist, attr);
	}
	
	attr->key = NULL;
}

// free the resources allocated for a row, including all of its attributes.  We need to remove the 
static void free_row(row_t *row)
{
	attr_t *attr;
	
	assert(row);
	assert(row->rid > 0);
	assert(row->table);
	assert(row->attrlist);
	while ((attr = ll_pop_head(row->attrlist))) {
		
		assert(attr->row == row);
		assert(attr->key);
		
		free_attr(attr);
		free(attr);
	}
	row->attrlist = ll_free(row->attrlist);
	assert(row->attrlist == NULL);
	
	// remove the row from the names list.
	assert(row->name);
	assert(row->name->i_rowlist);
	ll_remove(row->name->i_rowlist, row);
}


static void cmdDelete(storage_t *storage, risp_length_t length, void *data)
{
	namespace_t *ns;
	table_t     *table;
	row_t       *row;
	skey_t      *key;
	attr_t      *attr;
	risp_length_t processed;
	keyid_t      keyid;
	
	assert(storage && length > 0 && data);
	
	assert(storage->risp_data);
	risp_clear_all(storage->risp_data);
	processed = risp_process(storage->risp_data, NULL, length, data);
	assert(processed == length);
	
	ns = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_NAMESPACE_ID));
	ns = storage_getnamespace(storage, risp_getvalue(storage->risp_data, STASH_CMD_NAMESPACE_ID), NULL);
	assert(ns);
	
	table = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_TABLE_ID));
	table = storage_gettable(storage, ns, risp_getvalue(storage->risp_data, STASH_CMD_TABLE_ID), NULL);
	assert(table);
	
	row = NULL;
	assert(risp_isset(storage->risp_data, STASH_CMD_ROW_ID));
	row = storage_getrow(storage, table, risp_getvalue(storage->risp_data, STASH_CMD_ROW_ID));
	assert(row);
	
	keyid = 0;
	key = NULL;
	attr = NULL;
	if (risp_isset(storage->risp_data, STASH_CMD_KEY_ID)) {
		keyid = risp_getvalue(storage->risp_data, STASH_CMD_KEY_ID);
		assert(keyid >= 0);
		
		if (keyid > 0) {
			key = storage_getkey(table, keyid, NULL);
			assert(key);
			
			// now that we have all the data, we need to get the existing 
			// attribute for this key, from the row, if it exists. 
			attr = storage_getattr(row, key);
			assert(attr);
			assert(attr->key == key);
		}
	}
	
	assert(row->attrlist);
	if (attr && ll_count(row->attrlist) > 1) {
		/// we are deleting only an attribute within a row, and there is at 
		/// least one more attribute in the row.
		
		// remove the attribute from the row.
		assert(row->attrlist);
		ll_remove(row->attrlist, attr);
		
		// free the resources of the attribute (which also removes it from the key index).
		free_attr(attr);
		free(attr);
	}
	else {
		/// we are deleting an entire row (either directly, or because the 
		/// attribute we are deleting is the only one left... 
		
		// remove the row from the tables row-list.
		assert(table->rows);
		ll_remove(table->rows, row);
		
		// free the row's resources which will also free the attributes.
		free_row(row);
		free(row);
	}
}




static void free_key(skey_t *key)
{
	assert(key);
	
	assert(key->kid > 0);
	assert(key->table);
	
	assert(key->name);
	free(key->name);
	key->name = NULL;
	
	assert(key->i_attrlist);
	while (ll_pop_head(key->i_attrlist));
	key->i_attrlist = ll_free(key->i_attrlist);
	assert(key->i_attrlist == NULL);
}



static void free_name(name_t *name)
{
	assert(name);
	
	assert(name->nid > 0);
	assert(name->table);
	assert(name->name);
	free(name->name);

	assert(name->i_rowlist);
	while (ll_pop_head(name->i_rowlist));
	name->i_rowlist = ll_free(name->i_rowlist);
	assert(name->i_rowlist == NULL);
}


// free the table resources.  Before this is called, all related information should have been purged, such as grants and locks.
static void free_table(table_t *table) 
{
	row_t *row;
	name_t *name;
	skey_t *key;
	
	assert(table);
	
	assert(table->next_nid > 0);
	
	// free the indexes first, because it improves the speed of shutdown.

	assert(table->keys);
	ll_start(table->keys);
	while ((key = ll_next(table->keys))) {
		assert(key->i_attrlist);
		while ((ll_pop_head(key->i_attrlist)));
	}
	ll_finish(table->keys);
		
	
	// go through the list from the tail, because that is the most optimal.
	assert(table->rows);
	while ((row = ll_pop_tail(table->rows))) {
		free_row(row);
		free(row);
	}
	table->rows = ll_free(table->rows);
	assert(table->rows == NULL);

	assert(table->keys);
	while ((key = ll_pop_head(table->keys))) {
		free_key(key);
		free(key);
	}
	table->keys = ll_free(table->keys);
	assert(table->keys == NULL);
	
	// since all the rows have been deleted, the only names that should be left 
	// here are the ones that were marked permenant when they were created.
	assert(table->names);
	while ((name = ll_pop_head(table->names))) {
		free_name(name);
		free(name);
	}
	table->names = ll_free(table->names);
	assert(table->names == NULL);
	
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
	ns->tables = ll_free(ns->tables);
	assert(ns->tables == NULL);
	
	// delete the contents of the namespace.
	assert(ns->name);
	free(ns->name);
	ns->name = NULL;	
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
	
	/// Payload commands
	storage->risp_payload = risp_init(NULL);
	assert(storage->risp_payload);
	risp_add_command(storage->risp_payload, STASH_CMD_CREATE_NAMESPACE,   &cmdCreateNamespace);
	risp_add_command(storage->risp_payload, STASH_CMD_CREATE_USER,        &cmdCreateUsername);
	risp_add_command(storage->risp_payload, STASH_CMD_SET_PASSWORD,       &cmdSetPassword);
	risp_add_command(storage->risp_payload, STASH_CMD_GRANT,              &cmdGrant);
	risp_add_command(storage->risp_payload, STASH_CMD_CREATE_TABLE,       &cmdCreateTable);
	risp_add_command(storage->risp_payload, STASH_CMD_CREATE_NAME,        &cmdCreateName);
	risp_add_command(storage->risp_payload, STASH_CMD_CREATE_KEY,         &cmdCreateKey);
	risp_add_command(storage->risp_payload, STASH_CMD_CREATE_ROW,         &cmdCreateRow);
	risp_add_command(storage->risp_payload, STASH_CMD_SET,                &cmdSet);
	risp_add_command(storage->risp_payload, STASH_CMD_SET_EXPIRY,         &cmdSetExpiry);
	risp_add_command(storage->risp_payload, STASH_CMD_DELETE,             &cmdDelete);
	
	
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
	
	storage->buf_op = expbuf_init(NULL, 0);
	assert(storage->buf_op);
	assert(storage->buf_op->internally_created == 1);	
	
	storage->buf_top = expbuf_init(NULL, 0);
	assert(storage->buf_top);
	
	storage->buf_create = expbuf_init(NULL, 0);
	assert(storage->buf_create);
	
	storage->buf_data = expbuf_init(NULL, 0);
	assert(storage->buf_data);
	
	storage->buf_value = expbuf_init(NULL, 0);
	assert(storage->buf_value);

	storage->evbase = NULL;
	storage->write_event = NULL;
	storage->writebuf = expbuf_init(NULL, 0);
	assert(storage->writebuf);
	
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
	
	// at this point, if the write event existed, it should have already been processed.
	storage->evbase = NULL;
	assert(storage->write_event == NULL);
	assert(storage->writebuf);
	assert(BUF_LENGTH(storage->writebuf) == 0);
	storage->writebuf = expbuf_free(storage->writebuf);
	assert(storage->writebuf == NULL);
	
	assert(storage->buf_value);
	assert(BUF_LENGTH(storage->buf_value) == 0);
	storage->buf_value = expbuf_free(storage->buf_value);
	assert(storage->buf_value == NULL);
	
	assert(storage->buf_top);
	assert(BUF_LENGTH(storage->buf_top) == 0);
	storage->buf_top = expbuf_free(storage->buf_top);
	assert(storage->buf_top == NULL);
	
	assert(storage->buf_op);
	assert(BUF_LENGTH(storage->buf_op) == 0);
	assert(storage->buf_op->internally_created == 1);
	storage->buf_op = expbuf_free(storage->buf_op);
	assert(storage->buf_op == NULL);
	
	assert(storage->buf_create);
	assert(BUF_LENGTH(storage->buf_create) == 0);
	storage->buf_create = expbuf_free(storage->buf_create);
	assert(storage->buf_create == NULL);

	assert(storage->buf_data);
	assert(BUF_LENGTH(storage->buf_data) == 0);
	storage->buf_data = expbuf_free(storage->buf_data);
	assert(storage->buf_data == NULL);
	
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
	storage->users = ll_free(storage->users);
	assert(storage->users == NULL);
	
	assert(storage->namespaces);
	while ((namespace = ll_pop_head(storage->namespaces))) {
		// delete the namespace
		free_namespace(namespace);
		free(namespace);
	}
	storage->namespaces = ll_free(storage->namespaces);
	assert(storage->namespaces == NULL);
	
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
	storage->locked_files = ll_free(storage->locked_files);
	assert(storage->locked_files == NULL);
	
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
	expbuf_t *overflow;
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
		overflow = expbuf_init(NULL, INIT_BUF_SIZE);
		
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
				expbuf_add(overflow, buffer, len);
				
				// process the data.
				processed = risp_process(risp, usrdata, BUF_LENGTH(overflow), BUF_DATA(overflow));
				if (processed > 0) {
					expbuf_purge(overflow, processed);
				}
			}
		}
		
		// unlock the file.
		flock(handle, LOCK_UN);
		
		// close the file.
		close(handle);
		
		// there should not be any unprocessed data in the buffer.
		assert(BUF_LENGTH(overflow) == 0);
		
		// release the buffer.
		overflow = expbuf_free(overflow);
		assert(overflow == NULL);
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


static void write_callback(const int fd, const short which, void *arg)
{
	storage_t *storage = arg;
	int n;
	
	assert(which == EV_TIMEOUT);
	assert(fd < 0);
	assert(arg);
	
	assert(storage->file_handle > 0);
	assert(storage->write_event);
	
	assert(BUF_LENGTH(storage->buf_top) == 0);
	
	// write it out, and then increment our file-size counter.
	n = write(storage->file_handle, BUF_DATA(storage->writebuf), BUF_LENGTH(storage->writebuf));
	assert(n == BUF_LENGTH(storage->writebuf));
	storage->file_size += n;
	expbuf_purge(storage->writebuf, n);
	
	printf("wrote %d\n", n);
	
	// if we are over our file-size limit, then close the file and create a new one.
	if (storage->file_size >= MAX_FILESIZE) { 
		assert(0);
	}
	
	event_free(storage->write_event);
	storage->write_event = NULL;
}

static void addTimeCmd(expbuf_t *buf, risp_command_t cmd)
{
	struct timeval tv;
	
	assert(buf && cmd > 0 && cmd < 256);
	gettimeofday(&tv, NULL);
	rispbuf_addInt(buf, cmd, tv.tv_sec); 
}



//-----------------------------------------------------------------------------
// this will add the buffer as a payload to an operation.  It will add it to 
// the file, parse the stream locally, and if set, call the callback to notify 
// network clients (slave servers) of the change.
static void saveOperation(storage_t *storage, risp_command_t cmd, expbuf_t *buf, userid_t userid)
{
	int n;
	
	assert(storage);
	assert(buf);
	assert(userid >= 0);
	
	assert(BUF_LENGTH(buf) > 0);

	assert(storage->buf_create);
	assert(BUF_LENGTH(storage->buf_create) == 0);
	assert(cmd >= 160 && cmd <= 255);
	rispbuf_addBuffer(storage->buf_create, cmd, buf); 
	assert(BUF_LENGTH(storage->buf_create) > 0);
	
	// build operation
	assert(storage->buf_op);
	assert(BUF_LENGTH(storage->buf_op) == 0);
	rispbuf_addInt(storage->buf_op, STASH_CMD_TRANS_HI, storage->next_trans.hi);
	rispbuf_addInt(storage->buf_op, STASH_CMD_TRANS_LO, storage->next_trans.lo);
	if (userid > 0) {
		rispbuf_addInt(storage->buf_op, STASH_CMD_USER_ID, userid);
	}

	// add the datetime stamp
	addTimeCmd(storage->buf_op, STASH_CMD_DATETIME);

	rispbuf_addBuffer(storage->buf_op, STASH_CMD_PAYLOAD, storage->buf_create);
	expbuf_clear(storage->buf_create);
	
	assert(storage->buf_top);
	assert(BUF_LENGTH(storage->buf_top) == 0);
	assert(BUF_LENGTH(storage->buf_op) > 0);
	rispbuf_addBuffer(storage->buf_top, STASH_CMD_OPERATION, storage->buf_op);
	assert(BUF_LENGTH(storage->buf_top) > 0);
	
	// add to file queue
	// at this point, we should have a file handle open, and ready for writing.
	assert(storage->file_handle >= 0);
	
	// write the data to the file.
	if (storage->evbase) {
		// add the data to the write buffer.
		expbuf_addbuf(storage->writebuf, storage->buf_top);
		if (storage->write_event == NULL) {
			// the timeout event has not already been created, so we create it.
			struct timeval t = {1,0};
			storage->write_event = evtimer_new(storage->evbase, write_callback, storage);
			assert(storage->write_event);
			evtimer_add(storage->write_event, &t);
		}
	}
	else {
		// write it out, and then increment our file-size counter.
		n = write(storage->file_handle, BUF_DATA(storage->buf_top), BUF_LENGTH(storage->buf_top));
		assert(n == BUF_LENGTH(storage->buf_top));
		storage->file_size += n;
	
		// if we are over our file-size limit, then close the file and create a new one.
		if (storage->file_size >= MAX_FILESIZE) { 
			assert(0);
		}
	}
	
	// parse the operation internally.
	cmdOperation(storage, BUF_LENGTH(storage->buf_op), BUF_DATA(storage->buf_op));
	expbuf_clear(storage->buf_op);
	
	// if update-callback is set, call callback function (for syncing network nodes).
	if (storage->update_callback) {
		assert(0);
	}
	
	expbuf_clear(storage->buf_top);
}



// create the transaction for the create operation.
namespace_t * storage_create_namespace(storage_t *storage, userid_t requestor, const char *namespace)
{
	int slen;
	nsid_t id = 0;
	namespace_t *ns;
	
	assert(storage);
	assert(namespace);
	assert(requestor >= 0);
	
	slen = strlen(namespace);
	assert(slen > 0 && slen < 256);
	
	// id of the namespace that we are creating.  When the operation is 
	// processed, it will increment the next value.
	id = storage->next_ns_id;
	
	assert(storage->buf_data);
	assert(BUF_LENGTH(storage->buf_data) == 0);
	
	// build the data buffer
	assert(id > 0);
	rispbuf_addInt(storage->buf_data, STASH_CMD_NAMESPACE_ID, id);
	rispbuf_addStr(storage->buf_data, STASH_CMD_NAMESPACE, slen, namespace);
	
	// call the new operation function, which will queeue the data to be sent to the transaction log, and also to be read back in so that our internal systems are updated.
	assert(BUF_LENGTH(storage->buf_data) > 0);
	saveOperation(storage, STASH_CMD_CREATE_NAMESPACE, storage->buf_data, requestor);
	expbuf_clear(storage->buf_data);
	
	ns = storage_getnamespace(storage, id, NULL);
	assert(ns);
	return(ns);
}


user_t * storage_create_username(storage_t *storage, userid_t requestor, const char *newuser)
{
	int slen;
	userid_t uid;
	user_t *user;
	
	assert(storage);
	assert(requestor >= 0);
	assert(newuser);
	
	slen = strlen(newuser);
	assert(slen > 0 && slen < 256);
	
	uid = storage->next_user_id;
	
	// build the data buffer
	assert(storage->buf_data);
	assert(BUF_LENGTH(storage->buf_data) == 0);
	assert(uid > 0);
	rispbuf_addInt(storage->buf_data, STASH_CMD_USER_ID, uid);
	rispbuf_addStr(storage->buf_data, STASH_CMD_USERNAME, slen, newuser);
		
	// call the new operation function, which will queeue the data to be sent to the transaction log, and also to be read back in so that our internal systems are updated.
	assert(BUF_LENGTH(storage->buf_data) > 0);
	saveOperation(storage, STASH_CMD_CREATE_USER, storage->buf_data, requestor);
	expbuf_clear(storage->buf_data);
	
	user = storage_getuser(storage, uid, NULL);
	assert(user);
	return(user);
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
	ll_finish(ns->tables);
	
	return(tab);
}



void storage_set_password(storage_t *storage, userid_t requestor, userid_t uid, const char *newpass)
{
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
	assert(storage->buf_data);
	assert(BUF_LENGTH(storage->buf_data) == 0);

	assert(uid > 0);
	rispbuf_addInt(storage->buf_data, STASH_CMD_USER_ID, uid);
	rispbuf_addStr(storage->buf_data, STASH_CMD_PASSWORD, slen, newpass);
	
	// call the new operation function, which will queeue the data to be sent to the transaction log, and also to be read back in so that our internal systems are updated.
	saveOperation(storage, STASH_CMD_SET_PASSWORD, storage->buf_data, requestor);
	expbuf_clear(storage->buf_data);
}


// returns 0 if failed, returns non-zero if unable to set the grant.
// at this point we do not attempt to validate the grant, or even that the grant doesnt already exist.   If the grant already exists at this level, then 
void storage_grant(storage_t *storage, userid_t requestor, user_t *user, namespace_t *ns, table_t *table, unsigned short rights_map)
{
	assert(storage);
	assert(requestor == NULL_USER_ID || requestor > 0);
	assert(user);
	assert((ns == NULL && table == NULL) || (ns));
	assert(rights_map != 0);
	
	// need to go thru the list of users to make sure that this userid is valid.
	

	assert(storage->buf_data);
	assert(BUF_LENGTH(storage->buf_data) == 0);

	assert(user->uid > 0);
	rispbuf_addInt(storage->buf_data, STASH_CMD_USER_ID, user->uid);
	
	if (ns) {
		rispbuf_addInt(storage->buf_data, STASH_CMD_NAMESPACE_ID, ns->id);
		
		if (table) {
			rispbuf_addInt(storage->buf_data, STASH_CMD_TABLE_ID, table->tid);
		}
	}

	if (rights_map & STASH_RIGHT_ADDUSER)	rispbuf_addCmd(storage->buf_data, STASH_CMD_RIGHT_ADDUSER);
	if (rights_map & STASH_RIGHT_CREATE)	rispbuf_addCmd(storage->buf_data, STASH_CMD_RIGHT_CREATE);
	if (rights_map & STASH_RIGHT_DROP)		rispbuf_addCmd(storage->buf_data, STASH_CMD_RIGHT_DROP);
	if (rights_map & STASH_RIGHT_SET)		rispbuf_addCmd(storage->buf_data, STASH_CMD_RIGHT_SET);
	if (rights_map & STASH_RIGHT_UPDATE)	rispbuf_addCmd(storage->buf_data, STASH_CMD_RIGHT_UPDATE);
	if (rights_map & STASH_RIGHT_DELETE)	rispbuf_addCmd(storage->buf_data, STASH_CMD_RIGHT_DELETE);
	if (rights_map & STASH_RIGHT_QUERY)		rispbuf_addCmd(storage->buf_data, STASH_CMD_RIGHT_QUERY);
	if (rights_map & STASH_RIGHT_LOCK)		rispbuf_addCmd(storage->buf_data, STASH_CMD_RIGHT_LOCK);

	// call the new operation function, which will queeue the data to be sent 
	// to the transaction log, and also to be read back in so that our internal 
	// systems are updated.
	saveOperation(storage, STASH_CMD_GRANT, storage->buf_data, requestor);
	expbuf_clear(storage->buf_data);
}


int storage_check_rights(user_t *user, namespace_t *namespace, table_t *table, int rightmap)
{
	right_t *tmp;
	right_t *right;
	
	assert(user);
	assert(rightmap != 0);
	assert((table && namespace) || (namespace && table == NULL) || (namespace == NULL && table == NULL));
	
	if ((rightmap & STASH_RIGHT_ADDUSER) == STASH_RIGHT_ADDUSER) {
		assert(rightmap == STASH_RIGHT_ADDUSER);
		assert(namespace == NULL);
		assert(table == NULL);
	}
	
	right = NULL;
	assert(user->rights);
	ll_start(user->rights);
	while (right == NULL && (tmp = ll_next(user->rights))) {
		if (tmp->ns == namespace && tmp->table == table) {
			right = tmp;
			assert(right->rights_map != 0);
		}
	}
	ll_finish(user->rights);
	
	
	// we look for specific rights granted.  Rights to a namespace does not 
	// automatically give you rights to a table.
	if (right == NULL) {
		return 0;
	}
	else {
		if ((right->rights_map & rightmap) == rightmap) {
			return 1;
		}
		else {
			return 0;
		}
	}
}


table_t * storage_create_table(storage_t *storage, user_t *requestor, namespace_t *ns, const char *tablename, unsigned short options_map)
{
	tableid_t tid;
	table_t *table;
	
	assert(storage);
	assert(requestor);
	assert(requestor->uid > 0);
	assert(tablename);
	
	// build the data buffer
	assert(storage->buf_data);
	assert(BUF_LENGTH(storage->buf_data) == 0);

	assert(ns->id > 0);
	assert(ns->next_id > 0);
	tid = ns->next_id;
	rispbuf_addInt(storage->buf_data, STASH_CMD_NAMESPACE_ID, ns->id);
	rispbuf_addInt(storage->buf_data, STASH_CMD_TABLE_ID, ns->next_id);
	rispbuf_addStr(storage->buf_data, STASH_CMD_TABLE, strlen(tablename), tablename);
	
	if (options_map & STASH_TABOPT_STRICT)	  rispbuf_addCmd(storage->buf_data, STASH_CMD_STRICT);
	if (options_map & STASH_TABOPT_UNIQUE)	  rispbuf_addCmd(storage->buf_data, STASH_CMD_UNIQUE);
	if (options_map & STASH_TABOPT_OVERWRITE) rispbuf_addCmd(storage->buf_data, STASH_CMD_OVERWRITE);
	
	// call the new operation function, which will queeue the data to be sent 
	// to the transaction log, and also to be read back in so that our internal 
	// systems are updated.
	saveOperation(storage, STASH_CMD_CREATE_TABLE, storage->buf_data, requestor->uid);
	expbuf_clear(storage->buf_data);
	
	assert(ns->next_id > tid);
	assert(tid > 0);
	
	// we need to return the table object.  Since it was just added to storage, should be at the top of the list.
	table = storage_gettable(storage, ns, tid, NULL);
	assert(table);
	return(table);
}


//-----------------------------------------------------------------------------
// given the table object, will return the row object of a particular rowid.  
// If the row doesnt exist, will return a NULL.
row_t * storage_getrow(storage_t *storage, table_t *table, rowid_t rid)
{
	row_t *row;
	row_t *tmp;
	
	assert(storage);
	assert(table);
	
	assert(rid > 0);
	if (rid <= 0) { return(NULL); }
	
	// go thru the list of rows from the table object.
	assert(table->rows);
	row = NULL;
	ll_start(table->rows);
	while (row == NULL && (tmp = ll_next(table->rows))) {
		assert(tmp->rid > 0);
		if (tmp->rid == rid) {
			// we've found the row we are looking for.
			row = tmp;
			
			// move the row to the top of the list, so that most active rows are at the top.
			ll_move_head(table->rows, tmp);
		}
	}
	ll_finish(table->rows);
	
	return(row);
}


//-----------------------------------------------------------------------------
// 
skey_t * storage_getkey(table_t *table, keyid_t kid, const char *keyname)
{
	skey_t *key;
	skey_t *tmp;
	
	assert(table);
	assert((kid == 0 && keyname) || (kid > 0 && keyname == NULL));
	if (kid == 0 && keyname == NULL) { return(NULL); }
	
	// go thru the list of rows from the table object.
	assert(table->keys);
	key = NULL;
	ll_start(table->keys);
	while (key == NULL && (tmp = ll_next(table->keys))) {
		assert(tmp->kid > 0);
		assert(tmp->name);
		if ((kid > 0 && tmp->kid == kid) || (keyname && strcmp(tmp->name, keyname) == 0)) {
			// we've found the row we are looking for.
			key = tmp;
			
			// move the row to the top of the list, so that most active rows are at the top.
			ll_move_head(table->keys, tmp);
		}
	}
	ll_finish(table->keys);
	
	return(key);
}



name_t * storage_getname(table_t *table, nameid_t nid, const char *namestr)
{
	name_t *name;
	name_t *tmp;
	
	assert(table);
	assert((nid == 0 && namestr) || (nid > 0 && namestr == NULL));
	if (nid == 0 && namestr == NULL) { return(NULL); }
	
	// go thru the list of names from the table object.
	assert(table->names);
	name = NULL;
	ll_start(table->names);
	while (name == NULL && (tmp = ll_next(table->names))) {
		assert(tmp->nid > 0);
		if (tmp->nid == nid || strcmp(tmp->name, namestr) == 0) {
			// we've found the name we are looking for.
			name = tmp;
			
			// move the name to the top of the list, so that most active names are at the top.
			ll_move_head(table->names, tmp);
		}
	}
	ll_finish(table->names);
	
	return(name);
}



name_t * storage_create_name(storage_t *storage, user_t *requestor, table_t *table, const char *namestr, unsigned short options_map)
{
	name_t *name;
	nameid_t nid;
	
	assert(storage);
	assert(requestor);
	assert(requestor->uid > 0);
	assert(table);
	assert(namestr);
	assert(options_map <= STASH_NAMEOPT_TRANSIENT);
	
	// build the data buffer
	assert(storage->buf_data);
	assert(BUF_LENGTH(storage->buf_data) == 0);
	
	assert(table->tid > 0);
	assert(table->next_nid > 0);
	nid = table->next_nid;
	
	assert(table->ns);
	assert(table->ns->id > 0);
	rispbuf_addInt(storage->buf_data, STASH_CMD_NAMESPACE_ID, table->ns->id);
	rispbuf_addInt(storage->buf_data, STASH_CMD_TABLE_ID, table->tid);
	rispbuf_addInt(storage->buf_data, STASH_CMD_NAME_ID, nid);
	rispbuf_addStr(storage->buf_data, STASH_CMD_NAME, strlen(namestr), namestr);
	
	if (options_map & STASH_NAMEOPT_TRANSIENT)	  rispbuf_addCmd(storage->buf_data, STASH_CMD_TRANSIENT);
	
	// call the new operation function, which will queeue the data to be sent 
	// to the transaction log, and also to be read back in so that our internal 
	// systems are updated.
	saveOperation(storage, STASH_CMD_CREATE_NAME, storage->buf_data, requestor->uid);
	expbuf_clear(storage->buf_data);
	
	assert(table->next_nid > nid);
	assert(nid > 0);
	
	// we need to return the table object.  Since it was just added to storage, should be at the top of the list.
	name = storage_getname(table, nid, NULL);
	assert(name);
	return(name);
}


row_t * storage_create_row(storage_t *storage, user_t *requestor, table_t *table, name_t *name, int expires)
{
	row_t *row;
	rowid_t rid;
	
	assert(storage && requestor && requestor->uid > 0 && expires >= 0);
	
	// build the data buffer
	assert(storage->buf_data);
	assert(BUF_LENGTH(storage->buf_data) == 0);
	
	assert(table);
	assert(table->tid > 0);
	assert(table->next_rid > 0);
	rid = table->next_rid;

	assert(name);
	assert(name->nid);
	
	assert(table->ns);
	assert(table->ns->id > 0);
	rispbuf_addInt(storage->buf_data, STASH_CMD_NAMESPACE_ID, table->ns->id);
	rispbuf_addInt(storage->buf_data, STASH_CMD_TABLE_ID, table->tid);
	rispbuf_addInt(storage->buf_data, STASH_CMD_NAME_ID, name->nid);
	rispbuf_addInt(storage->buf_data, STASH_CMD_ROW_ID, rid);
	
	if (expires > 0) {
		rispbuf_addInt(storage->buf_data, STASH_CMD_EXPIRES, expires);
	}
	
	// call the new operation function, which will queeue the data to be sent 
	// to the transaction log, and also to be read back in so that our internal 
	// systems are updated.
	saveOperation(storage, STASH_CMD_CREATE_ROW, storage->buf_data, requestor->uid);
	expbuf_clear(storage->buf_data);
	
	assert(table->next_rid > rid);
	assert(rid > 0);
	
	// we need to return the table object.  Since it was just added to storage, should be at the top of the list.
	row = storage_getrow(storage, table, rid);
	assert(row);
	return(row);
}


skey_t * storage_create_key(storage_t *storage, user_t *requestor, table_t *table, const char *keyname)
{
	skey_t *key;
	keyid_t kid;
	
	assert(storage);
	assert(requestor);
	assert(requestor->uid > 0);
	assert(table);
	assert(keyname);
	
	// build the data buffer
	assert(storage->buf_data);
	assert(BUF_LENGTH(storage->buf_data) == 0);
	
	assert(table->tid > 0);
	assert(table->next_kid > 0);
	kid = table->next_kid;
	
	assert(table->ns);
	assert(table->ns->id > 0);
	rispbuf_addInt(storage->buf_data, STASH_CMD_NAMESPACE_ID, table->ns->id);
	rispbuf_addInt(storage->buf_data, STASH_CMD_TABLE_ID, table->tid);
	rispbuf_addInt(storage->buf_data, STASH_CMD_KEY_ID, kid);
	rispbuf_addStr(storage->buf_data, STASH_CMD_KEY, strlen(keyname), keyname);
	
	// call the new operation function, which will queeue the data to be sent 
	// to the transaction log, and also to be read back in so that our internal 
	// systems are updated.
	saveOperation(storage, STASH_CMD_CREATE_KEY, storage->buf_data, requestor->uid);
	expbuf_clear(storage->buf_data);
	
	assert(table->next_kid > kid);
	assert(kid > 0);
		
	// we need to return the table object.  Since it was just added to storage, should be at the top of the list.
	key = storage_getkey(table, kid, NULL);
	assert(key);
	return(key);
}





attr_t * storage_setattr(storage_t *storage, user_t *requestor, row_t *row, skey_t *key, value_t *value, int expires)
{
	attr_t *attr = NULL;
	
	assert(storage && requestor && row && key && value && expires >= 0);

	// generate the stream-code and submit it.
	// build the data buffer
	assert(storage->buf_data);
	assert(BUF_LENGTH(storage->buf_data) == 0);
	
	assert(row);
	assert(row->rid > 0);
	assert(key);
	assert(key->kid);
	
	assert(row->table);
	assert(row->table->ns);
	assert(row->table->ns->id > 0);
	
	rispbuf_addInt(storage->buf_data, STASH_CMD_NAMESPACE_ID, row->table->ns->id);
	rispbuf_addInt(storage->buf_data, STASH_CMD_TABLE_ID, row->table->tid);
	rispbuf_addInt(storage->buf_data, STASH_CMD_ROW_ID, row->rid);
	rispbuf_addInt(storage->buf_data, STASH_CMD_KEY_ID, key->kid);
	if (expires > 0) {
		rispbuf_addInt(storage->buf_data, STASH_CMD_EXPIRES, expires);
	}
	
	// if the value is AUTO we need to determine the next AUTO value for this key, and use it.
	if (value->valtype == STASH_VALTYPE_AUTO) {
		
// 		printf("common: auto:%d\n", key->auto_value);
		
		assert(key);
		assert(key->auto_value > 0);
		assert(value->value.number = key->auto_value);
		value->valtype = STASH_VALTYPE_INT;
		key->auto_value ++;
		assert(key->auto_value > 0);
	}
	
	
	assert(storage->buf_value);
	stash_build_value(storage->buf_value, value);
	assert(BUF_LENGTH(storage->buf_value) > 0);
	rispbuf_addBuffer(storage->buf_data, STASH_CMD_VALUE, storage->buf_value);
	expbuf_clear(storage->buf_value);
	
	// call the new operation function, which will queeue the data to be sent 
	// to the transaction log, and also to be read back in so that our internal 
	// systems are updated.
	saveOperation(storage, STASH_CMD_SET, storage->buf_data, requestor->uid);
	expbuf_clear(storage->buf_data);
	
	attr = storage_getattr(row, key);
	assert(attr);
	return(attr);
}


// go thru the attributes for the row, looking for one that is using this key.
attr_t * storage_getattr(row_t *row, skey_t *key)
{
	attr_t *attr = NULL;
	attr_t *tmp;
	
	assert(row && key);
	
	assert(row->attrlist);
	ll_start(row->attrlist);
	while (attr == NULL && (tmp = ll_next(row->attrlist))) {
		assert(tmp->row == row);
		if (key == tmp->key) {
			attr = tmp;
			ll_move_head(row->attrlist, tmp);
		}
	}
	ll_finish(row->attrlist);

	return(attr);
}


void storage_set_evbase(storage_t *storage, struct event_base *evbase)
{
	assert(storage && evbase);
	assert(storage->evbase == NULL);
	storage->evbase = evbase;
}


// will compare the attributes of the row against hte condition.  If condition 
// is true, then it will return a 1.  Otherwise it will return a 0.
static int compare_cond(row_t *row, stash_cond_t *condition)
{
	int result = 0;
	attr_t *attr;
	
	assert(row && condition);
	
	if (condition->condtype == STASH_CONDTYPE_EQUALS) {
		
		assert(condition->key_ptr);
		attr = storage_getattr(row, condition->key_ptr);
		if (attr) {
			assert(attr->row == row);
			assert(attr->key == condition->key_ptr);
			assert(attr->value);
			assert(condition->value);
			
			if (attr->value->valtype == condition->value->valtype) {
				if (attr->value->valtype == STASH_VALTYPE_INT) {
					if (attr->value->value.number == condition->value->value.number) {
						result = 1;
					}
				}
				else {
					// we really need to be able to compare the other types.
					assert(0);
				}
			}
		}
	}
	else if (condition->condtype == STASH_CONDTYPE_GT) {
		
		assert(condition->key_ptr);
		attr = storage_getattr(row, condition->key_ptr);
		if (attr) {
			assert(attr->row == row);
			assert(attr->key == condition->key_ptr);
			assert(attr->value);
			assert(condition->value);
			
			if (attr->value->valtype == condition->value->valtype) {
				if (attr->value->valtype == STASH_VALTYPE_INT) {
					if (attr->value->value.number > condition->value->value.number) {
						result = 1;
					}
				}
				else {
					// we really need to be able to compare the other types.
					assert(0);
				}
			}
		}
	}
	else if (condition->condtype == STASH_CONDTYPE_NAME) {
		
		// it is possible for there to be a condition on a name that doesnt 
		// exist.  Which will of course generate a fail when compared against 
		// the row->name.
		assert(row->name);
		if (condition->name_ptr == row->name) {
			result = 1;
		} 
	}
	else if (condition->condtype == STASH_CONDTYPE_AND) {
		assert(condition->ca);
		assert(condition->cb);
		
		if (compare_cond(row, condition->ca) == 1 && compare_cond(row, condition->ca) == 1) {
			result = 1;
		}
	}
	else if (condition->condtype == STASH_CONDTYPE_OR) {
		assert(condition->ca);
		assert(condition->cb);
		
		if (compare_cond(row, condition->ca) == 1 || compare_cond(row, condition->ca) == 1) {
			result = 1;
		}
	}
	else if (condition->condtype == STASH_CONDTYPE_NOT) {
		assert(condition->ca);
		assert(condition->cb == NULL);
		
		if (compare_cond(row, condition->ca) == 0) {
			result = 1;
		}
	}
	else if (condition->condtype == STASH_CONDTYPE_EXISTS) {
		if (condition->key_ptr) {
			attr = storage_getattr(row, condition->key_ptr);
			if (attr) {
				assert(attr->row == row);
				assert(attr->key == condition->key_ptr);
				assert(attr->value);
				assert(condition->value == NULL);
				
				result = 1;
			}
		}
	}
	else {
		assert(0);
	}
	
	return(result);
}

list_t * storage_query(storage_t *storage, table_t *table, stash_cond_t *condition)
{
	list_t *rows;
	row_t *row;
	
	assert(storage && table);
	assert(table->rows);
	
	rows = ll_init(NULL);
	assert(rows);
	
	// go thru all the rows in the table.
	ll_start(table->rows);
	while ((row = ll_next(table->rows))) {
		assert(row->table == table);
		
		// compare the row against the condition structure.
		if (condition == NULL || (condition && compare_cond(row, condition))) {
			ll_push_head(rows, row);
		}
	}
	ll_finish(table->rows);
		
	return(rows);
}



void storage_set_expiry(storage_t *storage, userid_t requestor, row_t *row, attr_t *attr, stash_expiry_t expires)
{
	assert(storage && requestor > 0 && row && expires > 0);
	
	// generate the stream-code and submit it.
	// build the data buffer
	assert(storage->buf_data);
	assert(BUF_LENGTH(storage->buf_data) == 0);
	
	assert(row->rid > 0);
	assert(row->table);
	assert(row->table->ns);
	assert(row->table->ns->id > 0);
	
	rispbuf_addInt(storage->buf_data, STASH_CMD_NAMESPACE_ID, row->table->ns->id);
	rispbuf_addInt(storage->buf_data, STASH_CMD_TABLE_ID, row->table->tid);
	rispbuf_addInt(storage->buf_data, STASH_CMD_ROW_ID, row->rid);
	if (attr) {
		assert(attr->row == row);
		assert(attr->key);
		assert(attr->key->kid > 0);
		rispbuf_addInt(storage->buf_data, STASH_CMD_KEY_ID, attr->key->kid);
	}
	rispbuf_addInt(storage->buf_data, STASH_CMD_EXPIRES, expires);
	
	// call the new operation function, which will queeue the data to be sent 
	// to the transaction log, and also to be read back in so that our internal 
	// systems are updated.
	saveOperation(storage, STASH_CMD_SET_EXPIRY, storage->buf_data, requestor);
	expbuf_clear(storage->buf_data);
}

void storage_delete(storage_t *storage, user_t *requestor, row_t *row, skey_t *key)
{
	assert(storage && requestor > 0 && row);
	
	assert(storage->buf_data);
	assert(BUF_LENGTH(storage->buf_data) == 0);
	
	assert(row->rid > 0);
	assert(row->table);
	assert(row->table->ns);
	assert(row->table->ns->id > 0);
	
	rispbuf_addInt(storage->buf_data, STASH_CMD_NAMESPACE_ID, row->table->ns->id);
	rispbuf_addInt(storage->buf_data, STASH_CMD_TABLE_ID, row->table->tid);
	rispbuf_addInt(storage->buf_data, STASH_CMD_ROW_ID, row->rid);
	if (key) {
		assert(key->kid > 0);
		rispbuf_addInt(storage->buf_data, STASH_CMD_KEY_ID, key->kid);
	}
	
	// call the new operation function, which will queeue the data to be sent 
	// to the transaction log, and also to be read back in so that our internal 
	// systems are updated.
	saveOperation(storage, STASH_CMD_DELETE, storage->buf_data, requestor->uid);
	expbuf_clear(storage->buf_data);
}

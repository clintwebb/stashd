#ifndef _STASH_COMMON_H
#define _STASH_COMMON_H

#include "event-compat.h"
#include <stash.h>
#include <linklist.h>
#include <risp.h>




#if (LIBSTASH_VERSION < 0x00000100)
#error "Requires libstash v0.01 or higher."
#endif


#if (LIBLINKLIST_VERSION < 0x00008000)
#error "Needs liblinklist v0.80 or higher"
#endif

#if (RISP_VERSION < 0x00020000)
#error "Needs librisp v2.00.00 or higher"
#endif



#define INIT_BUF_SIZE (1024*32)
#ifndef MAX_PATH_LEN
	#define MAX_PATH_LEN  2048
#endif




// when accessing the data files directly, and adding transactions, we have to 
// provide a userID of 0.  To make the code more readable, use NULL_USER_ID 
// instead of 0, which is less obvious.
#define NULL_USER_ID 0



typedef stash_nsid_t    nsid_t;
typedef stash_userid_t  userid_t;
typedef stash_tableid_t tableid_t;
typedef stash_rowid_t   rowid_t;
typedef stash_nameid_t  nameid_t;
typedef stash_keyid_t   keyid_t;

typedef stash_value_t   value_t;

typedef struct {
	unsigned int hi;
	unsigned int lo;
} transid_t;

typedef struct {
	nsid_t id;
	char *name;
	list_t *tables;	// table_t
	tableid_t next_id;
} namespace_t;

typedef struct {
	tableid_t tid;
	char *name;
	namespace_t *ns;
	
	list_t *rows;	// row_t
	rowid_t next_rid;
	
	list_t *names;  // name_t
	nameid_t next_nid;
	
	list_t *keys;
	keyid_t next_kid;
	
	short option_strict;
	short option_unique;
	short option_overwrite;
} table_t;

typedef struct {
	nameid_t nid;
	char *name;
	table_t *table;
	list_t *i_rowlist;	// row_t - list of rows that use this name.
	short option_transient;
} name_t;

typedef struct {
	rowid_t  rid;
	name_t  *name;
	table_t *table;	// parent table that this row belongs to.
	list_t  *attrlist;
	int      expires;
} row_t;

typedef struct {
	keyid_t kid;
	table_t *table;
	char *name;
	list_t *i_attrlist;
	int auto_value;
} skey_t;

typedef struct {
	row_t *row;
	skey_t *key;
	value_t *value;
	int expires;
} attr_t;

typedef struct {
	namespace_t *ns;
	table_t *table;
	unsigned int rights_map;
} right_t;

typedef struct {
	userid_t uid;
	char *username;
	char *password;
	list_t *rights;  // right_t
} user_t;


typedef enum {
	LOAD_DATA,
	IGNORE_DATA
} __storage_loaddata_e;





//-----------------------------------------------------------------------------
// storage struct is used to load a transaction file.  It doesnt really keep 
// data internally, but is a bridging interface.  It is responsible for locking 
// the file, opening and then reading it in and parsing it through a regular 
// RISP parser.  Then closing and unlocking the file.   The risp process will 
// keep track of the important bits that it cares about.
typedef struct {
	list_t *locked_files;
	__storage_loaddata_e loaddata;

	int curr_seq;
	int next_seq;

	int file_handle;
	int file_size;
	
	expbuf_t *buf_op;
	expbuf_t *buf_top;
	expbuf_t *buf_create;
	expbuf_t *buf_data;
	expbuf_t *buf_value;
	
	risp_t *risp_top;
	risp_t *risp_op;
	risp_t *risp_payload;
	risp_t *risp_data;

	// current highest transaction ID.
	transid_t next_trans;
	
	// opdata is the operation header data from transactions that are read in 
	// from a file, or from an update stream.
	struct {
		transid_t trans;
		userid_t user_id;
		unsigned long datetime;
	} opdata;
	
	list_t *namespaces;	// namespace_t
	nsid_t next_ns_id;
	
	list_t *users;	// user_t
	userid_t next_user_id;
	
	// if set, this callback function will be called whenever new operations 
	// are added to the stream.  It is supposed to be used to stream out data 
	// to the other nodes.
	void (*update_callback)(char *data, int length, void *usrptr);
	void *update_usrptr;

	struct event_base *evbase;
	struct event *write_event;
	expbuf_t *writebuf;
	
	short int internally_created;
	
	int maxsplit;
	char *basepath;
} storage_t;


storage_t * storage_init(storage_t *st);
void storage_free(storage_t *storage);


int storage_lock_file(storage_t *storage, const char *filename);
void storage_unlock_file(storage_t *storage, const char *filename);

int storage_lock_master(storage_t *storage, const char *basedir);
void storage_unlock_master(storage_t *storage, const char *basedir);

void storage_setlimit(storage_t *storage, int maxsplit);

void storage_process_file(storage_t *storage, const char *filename, risp_t *risp, void *usrdata);

typedef enum {
	KEEP_CLOSED, 
	KEEP_OPEN
} __storage_keepopen_e;

void storage_process(storage_t *storage, const char *path, __storage_keepopen_e keep_open, __storage_loaddata_e load_data);

int storage_namespace_avail(storage_t *storage, const char *namespace);
int storage_username_avail(storage_t *storage, const char *username);
void storage_set_password(storage_t *storage, userid_t requestor, userid_t uid, const char *newpass);

user_t      * storage_getuser(storage_t *storage, userid_t uid, const char *username);
namespace_t * storage_getnamespace(storage_t *storage, nsid_t nsid, const char *namespace);
table_t     * storage_gettable(storage_t *storage, namespace_t *ns, tableid_t tid, const char *table);
row_t       * storage_getrow(storage_t *storage, table_t *table, rowid_t rid);
name_t      * storage_getname(table_t *table, nameid_t nid, const char *namestr);
skey_t      * storage_getkey(table_t *table, keyid_t kid, const char *keyname);

void storage_grant(storage_t *storage, userid_t requestor, user_t *user, namespace_t *ns, table_t *table, unsigned short rights_map);
int  storage_check_rights(user_t *user, namespace_t *namespace, table_t *table, int rightmap);

user_t      * storage_create_username(storage_t *storage, userid_t requestor, const char *newuser);
namespace_t * storage_create_namespace(storage_t *storage, userid_t userid, const char *namespace);
table_t     * storage_create_table(storage_t *storage, user_t *requestor, namespace_t *ns, const char *tablename, unsigned short options_map);
name_t      * storage_create_name(storage_t *storage, user_t *requestor, table_t *table, const char *namestr, unsigned short options_map);
row_t       * storage_create_row(storage_t *storage, user_t *requestor, table_t *table, name_t *name, int expires);
skey_t      * storage_create_key(storage_t *storage, user_t *requestor, table_t *table, const char *keyname);

void storage_set_expiry(storage_t *storage, userid_t requestor, row_t *row, attr_t *attr, stash_expiry_t expires);
void storage_delete(storage_t *storage, user_t *requestor, row_t *row, skey_t *key);

attr_t * storage_setattr(storage_t *storage, user_t *requestor, row_t *row, skey_t *key, value_t *value, int expires);
attr_t * storage_getattr(row_t *row, skey_t *key);

void storage_set_evbase(storage_t *storage, struct event_base *evbase);

list_t * storage_query(storage_t *storage, table_t *table, stash_cond_t *condition);



#endif

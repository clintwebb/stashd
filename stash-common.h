#ifndef _STASH_COMMON_H
#define _STASH_COMMON_H

#include <linklist.h>
#include <risp.h>




#if (LIBLINKLIST_VERSION < 0x00008000)
#error "Needs liblinklist v0.80 or higher"
#endif

#if (RISP_VERSION < 0x00020000)
#error "Needs librisp v2.00.00 or higher"
#endif



#define INIT_BUF_SIZE 1024
#ifndef MAX_PATH_LEN
	#define MAX_PATH_LEN  2048
#endif


#define MAX_FILESIZE 2000000


// when accessing the data files directly, and adding transactions, we have to 
// provide a userID of 0.  To make the code more readable, use NULL_USER_ID 
// instead of 0, which is less obvious.
#define NULL_USER_ID 0



typedef int nsid_t;
typedef int userid_t;
typedef int tableid_t;
typedef int rowid_t;

typedef struct {
	unsigned int hi;
	unsigned int lo;
} transid_t;

typedef struct {
	nsid_t id;
	char *name;
	list_t *tables;	// table_t
} namespace_t;

typedef struct {
	tableid_t tid;
	char *name;
	namespace_t *ns;
	list_t *rows;	// row_t
} table_t;

typedef struct {
	rowid_t rid;
	table_t *table;	// parent table that this row belongs to.
} row_t;

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


// grant rights -- bitmask
#define STASH_RIGHT_ADDUSER    (1)
#define STASH_RIGHT_CREATE     (2)
#define STASH_RIGHT_DROP       (4)
#define STASH_RIGHT_SET        (8)
#define STASH_RIGHT_UPDATE     (16)
#define STASH_RIGHT_DELETE     (32)
#define STASH_RIGHT_QUERY      (64)
#define STASH_RIGHT_LOCK       (128)



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
		unsigned int date;
		unsigned int time;
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
	
	short int internally_created;
} storage_t;


storage_t * storage_init(storage_t *st);
void storage_free(storage_t *storage);


int storage_lock_file(storage_t *storage, const char *filename);
void storage_unlock_file(storage_t *storage, const char *filename);

int storage_lock_master(storage_t *storage, const char *basedir);
void storage_unlock_master(storage_t *storage, const char *basedir);

void storage_process_file(storage_t *storage, const char *filename, risp_t *risp, void *usrdata);

typedef enum {
	KEEP_CLOSED, 
	KEEP_OPEN
} __storage_keepopen_e;

void storage_process(storage_t *storage, const char *path, __storage_keepopen_e keep_open, __storage_loaddata_e load_data);

int storage_namespace_avail(storage_t *storage, const char *namespace);
nsid_t storage_create_namespace(storage_t *storage, userid_t userid, const char *namespace);

int storage_username_avail(storage_t *storage, const char *username);
userid_t storage_create_username(storage_t *storage, userid_t requestor, const char *newuser);
void storage_set_password(storage_t *storage, userid_t requestor, userid_t uid, const char *newpass);

user_t * storage_getuser(storage_t *storage, userid_t uid, const char *username);
namespace_t * storage_getnamespace(storage_t *storage, nsid_t nsid, const char *namespace);
table_t * storage_gettable(storage_t *storage, namespace_t *ns, tableid_t tid, const char *table);

void storage_grant(storage_t *storage, userid_t requestor, user_t *user, namespace_t *ns, table_t *table, unsigned short rights_map);

#endif

//-----------------------------------------------------------------------------
// stash-testplan
//	This simple tool is used to examine the performance of a system that will 
//	be running a stash instance.
//
//	It will use a newly created stash instance, and will add users, add 
//	namespaces, add tables, add data and read data, modify data, delete data.  
//	Once done, the database should be just as empty as it was when started 
//	(although all the transactions would still be there).
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



#define PACKAGE						"stash-testplan"
#define VERSION						"0.10"



//-----------------------------------------------------------------------------
// global variables.

short int verbose = 0;
int max_loop = 50000;




//-----------------------------------------------------------------------------
// print some info to the user, so that they can know what the parameters do.
static void usage(void) {
	printf(PACKAGE " " VERSION "\n");
	printf("Required params:\n");
	printf(" -u <username>      new username\n");
	printf(" -p <password>      new password\n");
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


static stash_tableid_t test_createtable(stash_t *stash, const char *newtable)
{
	stash_result_t res;
	stash_tableid_t tid;
	stash_nsid_t nsid;

	assert(stash && newtable);
	
	res = stash_create_table(stash, newtable, 0, &tid);
	if (res != STASH_ERR_OK) {
		printf("Unable to create table '%s'.\n", newtable);
		assert(tid == 0);
	}
	else {
		printf("Table '%s' created.\n", newtable);
		assert(tid > 0);
		
		nsid = 0;
		stash_get_namespace_id(stash, "test", &nsid);
		assert(nsid > 0);
		
		// grant rights to the table.
		res = stash_grant(stash, 0, nsid, tid, STASH_RIGHT_CREATE | STASH_RIGHT_SET | STASH_RIGHT_UPDATE | STASH_RIGHT_DELETE | STASH_RIGHT_QUERY);
		if (res != STASH_ERR_OK) {
			printf("Unable to set rights on table. %d:'%s'\n", res, stash_err_text(res));
		}
		else {
			printf("table created.\n");
		}
	}
	
	return(tid);
}


static void test_insert(stash_t *stash, stash_tableid_t tid)
{
	stash_attrlist_t *alist;
	int cnt;
	stash_reply_t *reply;
	stash_keyid_t key_name, key_id, key_total;
	struct timeval tv;
	int tm_set, tm_query;
	stash_cond_t *cond;
	
	assert(stash && tid > 0);
	
	key_name  = stash_get_key_id(stash, tid, "name");
	key_id    = stash_get_key_id(stash, tid, "id");
	key_total = stash_get_key_id(stash, tid, "total");
	assert(key_name > 0);
	assert(key_id > 0);
	assert(key_total > 0);

	alist = stash_init_alist(stash);
	assert(alist);

	stash_set_attr(alist, key_name,  __value_str("fred"), 0);
	stash_set_attr(alist, key_id,    __value_auto(), 0);
	stash_set_attr(alist, key_total, __bind_int(&cnt), 0);
	
	gettimeofday(&tv, NULL);
	tm_set = tv.tv_sec;
	for (cnt=0; cnt < max_loop; cnt++) {

		// now we want to set a bunch of records.
		reply = stash_create_row(stash, tid, NULL_NAMEID, "rowentry", alist, 0);
		assert(reply);
		if (reply->resultcode != STASH_ERR_OK) {
			printf("Unable to create row '%d', %d:'%s'.\n", cnt, reply->resultcode, stash_err_text(reply->resultcode));
			sleep(1);
		}
// 		else {
// 			printf("row %d created.\n", cnt);
// 		}
		stash_return_reply(reply);
	}
	gettimeofday(&tv, NULL);
	printf("Time for Setting: %d\n", (int) (tv.tv_sec - tm_set));

	stash_free_alist(stash, alist);
	
	
	printf("created %d records.\n", max_loop);
	
	gettimeofday(&tv, NULL);
	tm_query = tv.tv_sec;
	
	cond = __cond_name(0, "rowentry");
	reply = stash_query(stash, tid, 0, cond);
	if (reply->resultcode != STASH_ERR_OK) {
		printf("Unable to query row '%d', %d:'%s'.\n", cnt, reply->resultcode, stash_err_text(reply->resultcode));
		sleep(1);
	}
	else {
		while (stash_nextrow(reply)) {
// 			printf("row retrieved id=%d, total=%d\n", stash_getint(reply, key_id), stash_getint(reply, key_total));
		}
	}
	stash_cond_free(cond);
	stash_return_reply(reply);
	
	gettimeofday(&tv, NULL);
	printf("Time for Query: %d\n", (int) (tv.tv_sec - tm_query));
}



static void test_expiry(stash_t *stash, stash_tableid_t tid)
{
	stash_attrlist_t *alist;
	stash_reply_t *reply;
	stash_keyid_t key_name, key_code, key_tmp;
	const char *name, *tmp;
	int sec;
	stash_cond_t *cond;
	
	assert(stash && tid > 0);

	printf("\n\nTesting expiry\n");
	
	key_name  = stash_get_key_id(stash, tid, "name");
	key_code  = stash_get_key_id(stash, tid, "code");
	key_tmp   = stash_get_key_id(stash, tid, "tmp");
	assert(key_name > 0);
	assert(key_code > 0);
	assert(key_tmp > 0);
			
	alist = stash_init_alist(stash);
	assert(alist);
	
	stash_set_attr(alist, key_name, __value_str("franky bear"), 0);
	stash_set_attr(alist, key_code, __value_int(1024), 0);
	stash_set_attr(alist, key_tmp,  __value_str("balony"), 5);
	
	// now we want to set a bunch of records.
	reply = stash_create_row(stash, tid, NULL_NAMEID, "rowentry", alist, 10);
	assert(reply);
	if (reply->resultcode != STASH_ERR_OK) {
		printf("Unable to create row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
		sleep(1);
	}
	else {
		printf("row created.\n");
	}
	stash_return_reply(reply);
	stash_free_alist(stash, alist);

	cond = __cond_key_equals(key_code, __value_int(1024));
	
	for (sec=0; sec<20; sec++) {
		reply = stash_query(stash, tid, 1, cond);
		if (reply->resultcode != STASH_ERR_OK) {
			printf("Unable to query row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
			sleep(1);
			sec = 20;
		}
		else {
			while (stash_nextrow(reply)) {
				name = stash_getstr(reply, key_name);
				tmp = stash_getstr(reply, key_tmp);
				
				printf("Sec:%d, Name:'%s', tmp:'%s'\n", sec, name, tmp);
				sleep(1);
			}
		}
	}
	
	stash_cond_free(cond);
}



static void test_auto(stash_t *stash, stash_tableid_t tid)
{
	stash_attrlist_t *alist;
	stash_reply_t *reply;
	stash_keyid_t key_name, key_code, key_sid;
	int i;
	
	assert(stash && tid > 0);
	
	printf("\n\nTesting auto incrementing values\n");
	
	key_name  = stash_get_key_id(stash, tid, "name");
	key_code  = stash_get_key_id(stash, tid, "code");
	key_sid   = stash_get_key_id(stash, tid, "sid");
	assert(key_name > 0);
	assert(key_code > 0);
	assert(key_sid > 0);
	
	alist = stash_init_alist(stash);
	assert(alist);
	
	stash_set_attr(alist, key_name, __value_str("franky bear"), 0);
	stash_set_attr(alist, key_code, __value_int(1024), 0);
	stash_set_attr(alist, key_sid,  __value_auto(), 0);

	for (i=0; i<5; i++) {
		// now we want to set a bunch of records.
		reply = stash_create_row(stash, tid, NULL_NAMEID, "autorow", alist, 10);
		assert(reply);
		if (reply->resultcode != STASH_ERR_OK) {
			printf("Unable to create row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
			sleep(1);
		}
		else {
			if (stash_nextrow(reply)) {
				printf("row created.  sid=%d\n", stash_getint(reply, key_sid));
			}
			else {
				printf("No row data\n");
			}
		}
		stash_return_reply(reply);
	}
	stash_free_alist(stash, alist);
}




static void test_set(stash_t *stash, stash_tableid_t tid)
{
	stash_attrlist_t *alist;
	stash_reply_t *reply;
	stash_keyid_t key_name, key_code, key_sid;
	int i;
	stash_rowid_t rowid = 0;
	stash_cond_t *cond;
	
	assert(stash && tid > 0);
	
	printf("\n\nTesting multi-set\n");
	
	key_name  = stash_get_key_id(stash, tid, "name");
	key_code  = stash_get_key_id(stash, tid, "code");
	key_sid   = stash_get_key_id(stash, tid, "sid");
	assert(key_name > 0);
	assert(key_code > 0);
	assert(key_sid > 0);
	
	
	for (i=0; i<5; i++) {
		
		// set the initial attributes.
		alist = stash_init_alist(stash);
		assert(alist);
		
		stash_set_attr(alist, key_name, __value_str("franky bear"), 0);
		stash_set_attr(alist, key_sid,  __value_auto(), 0);
		
		// now we want to set a bunch of records.
		reply = stash_create_row(stash, tid, NULL_NAMEID, "multiset", alist, 0);
		assert(reply);
		if (reply->resultcode != STASH_ERR_OK) {
			printf("Unable to create row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
			sleep(1);
		}
		else if (stash_nextrow(reply)) {
			rowid = stash_rowid(reply);
			printf("row created. rowid=%d, sid=%d\n", rowid, stash_getint(reply, key_sid));
		}
		stash_return_reply(reply);
		stash_free_alist(stash, alist);

		
		// now set another attribute.
		alist = stash_init_alist(stash);
		assert(alist);
		
		stash_set_attr(alist, key_code, __value_int(1000 + i), 0);
		
		// now we want to set a bunch of records.
		assert(rowid > 0);
		reply = stash_set(stash, tid, rowid, alist);
		assert(reply);
		if (reply->resultcode != STASH_ERR_OK) {
			printf("Unable to updated row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
			sleep(1);
		}
		else if (stash_nextrow(reply)) {
			printf("row updated. rowid=%d\n", rowid);
		}
		stash_return_reply(reply);
		stash_free_alist(stash, alist);
		
	}
	
	
	// now query the table to return the rows we just created.
	cond = __cond_name(0, "multiset");
	reply = stash_query(stash, tid, 0, cond);
	if (reply->resultcode != STASH_ERR_OK) {
		printf("Unable to query row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
		sleep(1);
	}
	else {
		while (stash_nextrow(reply)) {
			printf("row retrieved %d, sid=%d, code=%d\n", stash_rowid(reply), stash_getint(reply, key_sid), stash_getint(reply, key_code));
		}
	}
	stash_cond_free(cond);
	stash_return_reply(reply);
}



static void test_delete(stash_t *stash, stash_tableid_t tid)
{
	stash_attrlist_t *alist;
	stash_reply_t *reply;
	stash_keyid_t key_name, key_code, key_sid;
	int i;
	stash_rowid_t rowid = 0;
	stash_cond_t *cond;
	
	assert(stash && tid > 0);
	
	printf("\n\nTesting delete\n");
	
	key_name  = stash_get_key_id(stash, tid, "name");
	key_code  = stash_get_key_id(stash, tid, "code");
	key_sid   = stash_get_key_id(stash, tid, "sid");
	assert(key_name > 0);
	assert(key_code > 0);
	assert(key_sid > 0);
	
	
	// set the initial attributes.
	alist = stash_init_alist(stash);
	assert(alist);
	
	stash_set_attr(alist, key_name, __value_str("peter possum"), 0);
	stash_set_attr(alist, key_sid,  __value_auto(), 0);
	stash_set_attr(alist, key_code, __value_int(1000 + i), 0);
	
	// now we want to set a record.
	rowid = 0;
	reply = stash_create_row(stash, tid, NULL_NAMEID, "delete", alist, 0);
	assert(reply);
	if (reply->resultcode != STASH_ERR_OK) {
		printf("Unable to create row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
		sleep(1);
	}
	else if (stash_nextrow(reply)) {
		rowid = stash_rowid(reply);
		printf("row created. rowid=%d, sid=%d\n", rowid, stash_getint(reply, key_sid));
	}
	stash_return_reply(reply);
	stash_free_alist(stash, alist);
	
	if (rowid > 0) {
		
		// now delete an attribute.
		reply = stash_delete(stash, tid, rowid, key_code);
		if (reply->resultcode != STASH_ERR_OK) {
			printf("Unable to delete attr, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
			sleep(1);
		}
		stash_return_reply(reply);
		
		
		cond = __cond_name(0, "delete");

		// now query the table to return the row we just created.
		printf("query #1 after deleting attribute\n");
		reply = stash_query(stash, tid, 0, cond);
		if (reply->resultcode != STASH_ERR_OK) {
			printf("Unable to query row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
			sleep(1);
		}
		else {
			while (stash_nextrow(reply)) {
				printf("row retrieved %d, sid=%d, code=%d\n", stash_rowid(reply), stash_getint(reply, key_sid), stash_getint(reply, key_code));
			}
		}
		stash_return_reply(reply);
		
		// now delete the entire row.
		reply = stash_delete(stash, tid, rowid, 0);
		if (reply->resultcode != STASH_ERR_OK) {
			printf("Unable to delete row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
			sleep(1);
		}
		stash_return_reply(reply);

		// now query the table to return the row we just created.
		printf("query #2 after deleting row\n");
		reply = stash_query(stash, tid, 0, cond);
		if (reply->resultcode != STASH_ERR_OK) {
			printf("Unable to query row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
			sleep(1);
		}
		else {
			if (stash_nextrow(reply)) {
				printf("row retrieved %d, sid=%d, code=%d\n", stash_rowid(reply), stash_getint(reply, key_sid), stash_getint(reply, key_code));
			}
			else {
				printf("row no longer exists.\n");
			}
		}
		stash_return_reply(reply);
		stash_cond_free(cond);
	}
}



static void test_blob(stash_t *stash, stash_tableid_t tid)
{
	stash_attrlist_t *alist;
	stash_reply_t *reply;
	stash_keyid_t key_name, key_sid, key_data;
	int i;
	stash_rowid_t rowid = 0;
	stash_cond_t *cond;
	char *data;
	struct timeval tv;
	int tm_set, tm_query;
	
	assert(stash && tid > 0);
	
	printf("\n\nTesting blob\n");
	
	key_name  = stash_get_key_id(stash, tid, "name");
	key_sid   = stash_get_key_id(stash, tid, "sid");
	key_data  = stash_get_key_id(stash, tid, "data");
	assert(key_name > 0);
	assert(key_sid > 0);
	assert(key_data > 0);
	
	// init the data that we want to store.
	data = malloc(1024*64);
	assert(data);
	for (i=0; i<(1024*64); i++) {
		data[i] = '#';
	}


	gettimeofday(&tv, NULL);
	tm_set = tv.tv_sec;

	for (i=0; i<50; i++) {
		
		// set the initial attributes.
		alist = stash_init_alist(stash);
		assert(alist);
		
		stash_set_attr(alist, key_name, __value_str("joe no go"), 0);
		stash_set_attr(alist, key_sid,  __value_auto(), 0);
		stash_set_attr(alist, key_data, __value_blob(data, (1024*64)), 0);
		
		// now we want to set a bunch of records.
		reply = stash_create_row(stash, tid, NULL_NAMEID, "blobber", alist, 0);
		assert(reply);
		if (reply->resultcode != STASH_ERR_OK) {
			printf("Unable to create row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
			sleep(1);
		}
		else if (stash_nextrow(reply)) {
			rowid = stash_rowid(reply);
			printf("row created. rowid=%d, sid=%d\n", rowid, stash_getint(reply, key_sid));
		}
		stash_return_reply(reply);
		stash_free_alist(stash, alist);
	}
	
	gettimeofday(&tv, NULL);
	printf("Time for Setting: %d\n", (int) (tv.tv_sec - tm_set));
	
	
	
	gettimeofday(&tv, NULL);
	tm_query = tv.tv_sec;
	
	// now query the table to return the rows we just created.
	cond = __cond_name(0, "blobber");
	reply = stash_query(stash, tid, 0, cond);
	if (reply->resultcode != STASH_ERR_OK) {
		printf("Unable to query row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
		sleep(1);
	}
	else {
		while (stash_nextrow(reply)) {
			printf("row retrieved %d, sid=%d, blob_len=%d\n", stash_rowid(reply), stash_getint(reply, key_sid), stash_getlength(reply, key_data));
		}
	}
	stash_cond_free(cond);

	gettimeofday(&tv, NULL);
	printf("Time for Query: %d\n", (int) (tv.tv_sec - tm_query));
	
	
	free(data);
}


static void test_sort(stash_t *stash, stash_tableid_t tid)
{
	stash_attrlist_t *alist;
	stash_reply_t *reply;
	stash_keyid_t key_name, key_code, key_sid;
	int i;
	stash_rowid_t rowid = 0;
	stash_cond_t *cond = NULL;
	char *names[5] = {"freddy", "zach", "peter", "bob", "andy"};
	
	assert(stash && tid > 0);
	
	printf("\n\nTesting sort\n");
	
	key_name  = stash_get_key_id(stash, tid, "name");
	key_code  = stash_get_key_id(stash, tid, "code");
	key_sid   = stash_get_key_id(stash, tid, "sid");
	assert(key_name > 0);
	assert(key_code > 0);
	assert(key_sid > 0);
	
	for (i=0; i<5; i++) {
		
		// set the initial attributes.
		alist = stash_init_alist(stash);
		assert(alist);
		
		stash_set_attr(alist, key_name, __value_str(names[i]), 0);
		stash_set_attr(alist, key_sid,  __value_auto(), 0);
		stash_set_attr(alist, key_code, __value_int(random() + i), 0);
		
		// now we want to set a record.
		rowid = 0;
		reply = stash_create_row(stash, tid, NULL_NAMEID, "sort", alist, 0);
		assert(reply);
		if (reply->resultcode != STASH_ERR_OK) {
			printf("Unable to create row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
			sleep(1);
		}
		else if (stash_nextrow(reply)) {
			rowid = stash_rowid(reply);
			printf("row created. name='%s', rowid=%d, sid=%d\n", names[i], rowid, stash_getint(reply, key_sid));
		}
		stash_return_reply(reply);
		stash_free_alist(stash, alist);
	}
	
	
	
	// now query the table to return the row we just created.
	cond = __cond_name(0, "sort");
	reply = stash_query(stash, tid, 0, cond);
	if (reply->resultcode != STASH_ERR_OK) {
		printf("Unable to query row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
		sleep(1);
	}
	else {
		
		printf("\n\ndisplay - unsorted.\n");
		while (stash_nextrow(reply)) {
			printf("row retrieved %d, name='%s', sid=%d, code=%d\n", stash_rowid(reply), stash_getstr(reply, key_name), stash_getint(reply, key_sid), stash_getint(reply, key_code));
		}
		printf("\n\n");
		
		printf("sorted on name.\n");
		stash_sort_onkey(reply, key_name);
		while (stash_nextrow(reply)) {
			printf("row retrieved %d, name='%s', sid=%d, code=%d\n", stash_rowid(reply), stash_getstr(reply, key_name), stash_getint(reply, key_sid), stash_getint(reply, key_code));
		}
		printf("\n\n");

		printf("sorted on code.\n");
		stash_sort_onkey(reply, key_code);
		while (stash_nextrow(reply)) {
			printf("row retrieved %d, name='%s', sid=%d, code=%d\n", stash_rowid(reply), stash_getstr(reply, key_name), stash_getint(reply, key_sid), stash_getint(reply, key_code));
		}
		printf("\n\n");
		
		
	}
	stash_return_reply(reply);
	stash_cond_free(cond);
}



// re-uses the 
static void test_sortquery(stash_t *stash, stash_tableid_t tid)
{
	stash_keyid_t key_name, key_code, key_sid;
	stash_cond_t *cond = NULL;
	stash_query_t *query;
	stash_reply_t *reply;
	
	assert(stash && tid > 0);
	
	printf("\n\nTesting sort query (client side)\n");
	
	key_name  = stash_get_key_id(stash, tid, "name");
	key_code  = stash_get_key_id(stash, tid, "code");
	key_sid   = stash_get_key_id(stash, tid, "sid");

	cond = __cond_name(0, "sort");
	assert(cond);
	
	query = stash_query_new(tid);
	assert(query);
	stash_query_condition(query, cond);
	
	// now query the table to return the row we just created.
	reply = stash_query_execute(stash, query);
	if (reply->resultcode != STASH_ERR_OK) {
		printf("Unable to query row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
		sleep(1);
	}
	else {
		
		printf("\n\ndisplay - unsorted.\n");
		while (stash_nextrow(reply)) {
			printf("row retrieved %d, code=%012d, name='%s', sid=%d\n", stash_rowid(reply), stash_getint(reply, key_code), stash_getstr(reply, key_name), stash_getint(reply, key_sid));
		}
		printf("\n\n");
	}
	stash_return_reply(reply);
	
	// add a sort critera to the query.   
	stash_query_sort(query, key_name, 0);
	
	// now query the table to return the row we just created.
	reply = stash_query_execute(stash, query);
	if (reply->resultcode != STASH_ERR_OK) {
		printf("Unable to query row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
		sleep(1);
	}
	else {
		
		printf("\n\ndisplay - sorted on name.\n");
		while (stash_nextrow(reply)) {
			printf("row retrieved %d, code=%012d, name='%s', sid=%d\n", stash_rowid(reply), stash_getint(reply, key_code), stash_getstr(reply, key_name), stash_getint(reply, key_sid));
		}
		printf("\n\n");
	}
	stash_return_reply(reply);

	// add a sort critera to the query.   
	stash_query_sort_clear(query);
	stash_query_sort(query, key_code, 0);
	
	// now query the table to return the row we just created.
	reply = stash_query_execute(stash, query);
	if (reply->resultcode != STASH_ERR_OK) {
		printf("Unable to query row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
		sleep(1);
	}
	else {
		
		printf("\n\ndisplay - sorted on code.\n");
		while (stash_nextrow(reply)) {
			printf("row retrieved %d, code=%012d, name='%s', sid=%d\n", stash_rowid(reply), stash_getint(reply, key_code), stash_getstr(reply, key_name), stash_getint(reply, key_sid));
		}
		printf("\n\n");
	}
	stash_return_reply(reply);
	
	stash_cond_free(cond);
	stash_query_free(query);
}


// re-uses the 
static void test_sortquerylimit(stash_t *stash, stash_tableid_t tid)
{
	stash_keyid_t key_name, key_code, key_sid;
	stash_cond_t *cond = NULL;
	stash_query_t *query;
	stash_reply_t *reply;
	int limit=3;
	
	assert(stash && tid > 0);
	
	printf("\n\nTesting sort query (server side)\n");
	
	key_name  = stash_get_key_id(stash, tid, "name");
	key_code  = stash_get_key_id(stash, tid, "code");
	key_sid   = stash_get_key_id(stash, tid, "sid");
	
	cond = __cond_name(0, "sort");
	assert(cond);
	
	query = stash_query_new(tid);
	assert(query);
	stash_query_condition(query, cond);
	
	// now query the table to return the row we just created.
	reply = stash_query_execute(stash, query);
	if (reply->resultcode != STASH_ERR_OK) {
		printf("Unable to query row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
		sleep(1);
	}
	else {
		
		printf("\n\ndisplay - unsorted.\n");
		while (stash_nextrow(reply)) {
			printf("row retrieved %d, code=%012d, name='%s', sid=%d\n", stash_rowid(reply), stash_getint(reply, key_code), stash_getstr(reply, key_name), stash_getint(reply, key_sid));
		}
		printf("\n\n");
	}
	stash_return_reply(reply);
	
	// add a sort critera to the query.   
	stash_query_sort(query, key_name, 0);
	stash_query_limit(query, limit);
	
	// now query the table to return the row we just created.
	reply = stash_query_execute(stash, query);
	if (reply->resultcode != STASH_ERR_OK) {
		printf("Unable to query row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
		sleep(1);
	}
	else {
		
		printf("\n\ndisplay - sorted on name (limit %d).\n", limit);
		while (stash_nextrow(reply)) {
			printf("row retrieved %d, code=%012d, name='%s', sid=%d\n", stash_rowid(reply), stash_getint(reply, key_code), stash_getstr(reply, key_name), stash_getint(reply, key_sid));
		}
		printf("\n\n");
	}
	stash_return_reply(reply);
	
	// add a sort critera to the query.   
	stash_query_sort_clear(query);
	stash_query_sort(query, key_code, 0);
	
	// now query the table to return the row we just created.
	reply = stash_query_execute(stash, query);
	if (reply->resultcode != STASH_ERR_OK) {
		printf("Unable to query row, %d:'%s'.\n", reply->resultcode, stash_err_text(reply->resultcode));
		sleep(1);
	}
	else {
		
		printf("\n\ndisplay - sorted on code (limit %d).\n", limit);
		while (stash_nextrow(reply)) {
			printf("row retrieved %d, code=%012d, name='%s', sid=%d\n", stash_rowid(reply), stash_getint(reply, key_code), stash_getstr(reply, key_name), stash_getint(reply, key_sid));
		}
		printf("\n\n");
	}
	stash_return_reply(reply);
	
	stash_cond_free(cond);
	stash_query_free(query);
}







//-----------------------------------------------------------------------------
// Main... process command line parameters, and if we have enough information, then create an empty stash.
int main(int argc, char **argv) 
{
	int c;
	stash_t *stash = NULL;
	int result;
	const char *host = NULL;
	const char *username = NULL;
	const char *password = NULL;
	stash_result_t res;
	stash_tableid_t tid;
	const char *newtable = "testtable";
	
	assert(argc >= 0);
	assert(argv);
	
	// process arguments
	/// Need to check the options in here, there're possibly ones that we dont need.
	while ((c = getopt(argc, argv, "hvH:U:P:")) != -1) {
		switch (c) {
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'v':
				verbose++;
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
	if (host == NULL) {
		fprintf(stderr, "missing required option, -H\n");
		exit(1);
	}
	
	result = 0;
	
	if (verbose > 0) printf("Initialising stash library.\n");
	stash = stash_init(NULL);
	assert(stash);
	
	// add our username and password to the authority... in future 
	// versions, private and public keys may be used instead.
	if (verbose > 0) printf("Adding stash authority. username='%s', password='%s'\n", username, password);
	assert(username);
	assert(password);
	stash_authority(stash, username, password);

	// add our known host to the server list.
	if (verbose > 0) printf("adding stash server. host='%s'\n", host);
	assert(host);
	stash_addserver(stash, host, 10);
	
	// connect to the database... check error code.
	// although it is not necessary to connect now, because if we dont, 
	// the first operation we do will attempt to connect if we are not 
	// already connected.  However, it is useful right now to attempt to 
	// connect so that we can report the error back to the user.  Easier 
	// to do it here and it doesn't cost anything.
	if (verbose > 0) printf("Connecting to stash services.\n");
	res = stash_connect(stash);
	if (res != 0) {
		fprintf(stderr, "Unable to connect: %04X:%s\n", res, stash_err_text(res));
	}
	else {

		res =  stash_set_namespace(stash, "test");
		if (res != STASH_ERR_OK) {
			printf("unable to find namespace ID\n");
		}
		else {
			// run through the tests.
			tid = test_createtable(stash, newtable);
			if (tid > 0) {
				test_insert(stash, tid);
// 				test_expiry(stash, tid);
				test_auto(stash, tid);
				test_set(stash, tid);
				test_delete(stash, tid);
				test_blob(stash, tid);
				test_sort(stash, tid);
				test_sortquery(stash, tid);
				test_sortquerylimit(stash, tid);
			}
		}
	}
	
	if (verbose > 0) printf("Shutting down.\n");
	
	
	// cleanup the storage 
	if (verbose > 0) printf("Cleaning up stash resources.\n");
	stash_free(stash);
	stash = NULL;		

	if (verbose > 0) printf("Goodbye.\n");
	
	return(result);
}



//-----------------------------------------------------------------------------
// stashd
//	Enhanced hash-map storage database.
//-----------------------------------------------------------------------------


// includes
#include <assert.h>
#include <errno.h>
#include <expbuf.h>
#include <rispbuf.h>
#include <stash.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


#define PACKAGE						"stash-create"
#define VERSION						"0.10"






//-----------------------------------------------------------------------------
// print some info to the user, so that they can know what the parameters do.
static void usage(void) {
	printf(PACKAGE " " VERSION "\n");
	printf("-d <path>          storage path\n");
	printf("\n");
	printf("-v                 verbose (print errors/warnings while in event loop)\n");
	printf("-h                 print this help and exit\n");
	return;
}





//-----------------------------------------------------------------------------
// Main... process command line parameters, and if we have enough information, then create an empty stash.
int main(int argc, char **argv) 
{
	int c;
	char *basedir = NULL;
	FILE *fp;
	char *fullpath;
	int verbose = 0;
	expbuf_t *buf;
	
	assert(argc >= 0);
	assert(argv);
	
	// process arguments
	/// Need to check the options in here, there're possibly ones that we dont need.
	while ((c = getopt(argc, argv, "hvd:")) != -1) {
		switch (c) {
			case 'h':
				usage();
				exit(0);
			case 'v':
				verbose++;
				break;
			case 'd':
				assert(basedir == NULL);
				basedir = optarg;
				break;
				
			default:
				fprintf(stderr, "Illegal argument \"%c\"\n", c);
				return 1;
				
		}
	}
	
	// make sure basedir parameter was supplied.
	if (basedir == NULL) {
		fprintf(stderr, "missing required option: -d\n");
		exit(1);
	}
	
	// create the filename path;
	fullpath = malloc(strlen(basedir)+32);
	sprintf(fullpath, "%s/%08d.stash", basedir, 0);
	if (verbose > 0) printf("path: %s\n", fullpath);
	
	// make sure file doesnt already exist.
	fp = fopen(fullpath, "r");
	if (fp) {
		fclose(fp);
		fprintf(stderr, "stash database file exists: %s\n", fullpath);
		exit(1);
	}
	
	// create an empty file.
	assert(fp == NULL);
	fp = fopen(fullpath, "w");
	if (fp == NULL) {
		
		fprintf(stderr, "Unable to create file: %s (errno: %d = '%s')\n", fullpath, errno, strerror(errno));
		exit(1);
	}
	
	// add FILE_SEQ entry.
	assert(fp);
	buf = malloc(sizeof(expbuf_t));
	expbuf_init(buf, 32);
	addCmd(buf, STASH_CMD_CLEAR);
	addCmdInt(buf, STASH_CMD_FILE_SEQ, 0);
	fwrite(BUF_DATA(buf), BUF_LENGTH(buf), 1, fp);
	expbuf_free(buf);
	free(buf);
	buf = NULL;
	
	// close file.
	assert(fp);
	fclose(fp);
	fp = NULL;
	
	// create the files directory.
	sprintf(fullpath, "%s/%08d", basedir, 0);
	if (mkdir(fullpath, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) != 0) {
		fprintf(stderr, "Unable to create datafile directory\n");
	}
	
	// free the memory for the path.
	free(fullpath);
	
	// exit.
	if (verbose > 0) printf("Done.\n");
	
	return 0;
}



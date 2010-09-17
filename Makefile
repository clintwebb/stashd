## make file for stashd.

all: stash-create stash-adduser stash-create-namespace \
     stashd stash-grant stash-dump stash-testplan \
     stash-setpassword stash-create-table

DEBUG_LIBS=
#DEBUG_LIBS=-lefence -lpthread

ARGS=-Wall -O2 -g $(DEBUG_LIBS)
# Libraries that the stash library uses.
STASH_LIBS=-lstash -llinklist -lexpbuf -lrispbuf -lrisp
STASHD_LIBS=-lexpbuf -lrisp -lrispbuf -levent
STASH_COMMON_LIBS=-lstash -llinklist -lexpbufpool -lrispbuf -lrisp -levent
LIBS=$(STASHD_LIBS) $(STASH_LIBS)

OBJS=stashd.o stash-common.o


 
H_rq=/usr/include/rq.h
H_linklist=/usr/include/linklist.h





stashd: $(OBJS) stash-common.h
	gcc -o $@ $(OBJS) $(LIBS) $(ARGS)

stash-create: stash-create.c
	gcc -o $@ stash-create.c -lexpbuf -lrispbuf $(ARGS)

stash-dump: stash-dump.c stash-common.h stash-common.o
	gcc -o $@ stash-dump.c stash-common.o $(STASH_COMMON_LIBS) -lexpbuf $(ARGS)

stash-adduser: stash-adduser.c stash-common.h stash-common.o
	gcc -o $@ stash-adduser.c stash-common.o $(STASH_COMMON_LIBS) -lexpbuf $(ARGS)

stash-setpassword: stash-setpassword.c stash-common.h stash-common.o
	gcc -o $@ stash-setpassword.c stash-common.o $(STASH_COMMON_LIBS) -lexpbuf $(ARGS)

stash-testplan: stash-testplan.c stash-common.h stash-common.o
	gcc -o $@ stash-testplan.c stash-common.o $(STASH_COMMON_LIBS) -lexpbuf $(ARGS)

stash-grant: stash-grant.c stash-common.h stash-common.o
	gcc -o $@ stash-grant.c stash-common.o $(STASH_COMMON_LIBS) -lexpbuf $(ARGS)

stash-create-namespace: stash-create-namespace.c stash-common.h stash-common.o
	gcc -o $@ stash-create-namespace.c stash-common.o $(STASH_COMMON_LIBS) -lexpbuf -lrispbuf -lrisp -lstash $(ARGS)


# network only tools

stash-create-table: stash-create-table.c 
	gcc -o $@ stash-create-table.c $(STASH_LIBS) $(ARGS)




# shared objects

stash-common.o: stash-common.c stash-common.h
	gcc -c -o $@ stash-common.c $(ARGS)

stashd.o: stashd.c stash-common.h
	gcc -c -o $@ stashd.c $(ARGS)



install: stashd stash-create stash-adduser stash-create-namespace stash-grant stash-dump stash-setpassword stash-create-table
	@cp stashd /usr/bin/
	@cp stash-create /usr/bin/
	@cp stash-adduser /usr/bin/
	@cp stash-create-namespace /usr/bin/
	@cp stash-grant /usr/bin/
	@cp stash-dump /usr/bin/
	@cp stash-setpassword /usr/bin/
	@cp stash-create-table /usr/bin/

clean:
	@-rm stashd 
	@-rm stashd.o
	@-rm stash-common.o
	@-rm stash-dump
	@-rm stash-create-namespace
	@-rm stash-create-table
	@-rm stash-adduser
	@-rm stash-create
	@-rm stash-grant
	@-rm stash-testplan
	@-rm stash-setpassword
	@-rm $(OBJS)


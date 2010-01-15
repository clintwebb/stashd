## make file for stashd.

all: stash-dump stash-create stash-adduser stash-create-namespace stashd stash-grant

DEBUG_LIBS=
# DEBUG_LIBS=-lefence -lpthread

ARGS=-Wall -O2 -g
# Libraries that the stash library uses.
STASH_LIBS=-lstash -llinklist -lexpbufpool
STASHD_LIBS=-lexpbuf
STASH_COMMON_LIBS=-llinklist -lexpbufpool -lrispbuf -lrisp
LIBS=$(STASHD_LIBS) $(STASH_LIBS)

OBJS=stashd.o


 
H_rq=/usr/include/rq.h
H_linklist=/usr/include/linklist.h





stashd: $(OBJS)
	gcc -o $@ $(OBJS) $(LIBS) $(ARGS)

stash-create: stash-create.c
	gcc -o $@ stash-create.c -lexpbuf -lrispbuf $(ARGS)

stash-dump: stash-dump.c stash-common.h stash-common.o
	gcc -o $@ stash-dump.c stash-common.o $(STASH_LIBS) -lexpbuf -lrispbuf -lrisp $(ARGS)

stash-adduser: stash-adduser.c stash-common.h stash-common.o
	gcc -o $@ stash-adduser.c stash-common.o $(STASH_COMMON_LIBS) -lexpbuf $(ARGS)

stash-grant: stash-grant.c stash-common.h stash-common.o
	gcc -o $@ stash-grant.c stash-common.o $(STASH_COMMON_LIBS) -lexpbuf $(ARGS)

stash-create-namespace: stash-create-namespace.c stash-common.h stash-common.o
	gcc -o $@ stash-create-namespace.c stash-common.o $(STASH_COMMON_LIBS) -lexpbuf -lrispbuf -lrisp -lstash $(ARGS)


stash-common.o: stash-common.c stash-common.h
	gcc -c -o $@ stash-common.c $(ARGS)

stashd.o: stashd.c  
	gcc -c -o $@ stashd.c $(ARGS)



install: stashd
	@cp stashd /usr/bin

clean:
	@-rm stashd stashd.o
	@-rm stash-common.o
	@-rm stash-dump
	@-rm stash-create-namespace
	@-rm stash-adduser
	@-rm stash-create
	@-rm $(OBJS)


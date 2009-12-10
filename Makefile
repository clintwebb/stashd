## make file for stashd.

all: stashd

DEBUG_LIBS=
# DEBUG_LIBS=-lefence -lpthread

ARGS=-Wall -O2
# Libraries that the stash library uses.
STASH_LIBS=
STASHD_LIBS=
LIBS=$(STASHD_LIBS) $(STASH_LIBS)

OBJS=stashd.o


 
H_rq=/usr/include/rq.h
H_linklist=/usr/include/linklist.h



stashd: $(OBJS)
	gcc -o $@ $(OBJS) $(LIBS) $(ARGS)


stashd.o: stashd.c  
	gcc -c -o $@ stashd.c $(ARGS)



install: stashd
	@cp stashd /usr/bin

clean:
	@-rm stashd
	@-rm $(OBJS)


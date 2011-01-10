#!/bin/sh

if [ "$1" == "-gdb" ] 
then 
  DEBUG=yes
  echo "*** DEBUG MODE ***"
fi

# determine temporary directory.
if [ ! -d testplan ]
then
	# create new directory
	mkdir testplan
fi

# if an existing database directory is there... delete it.
if [ -d testplan/db ]
then
	rm -r testplan/db
fi
mkdir testplan/db

# create empty database file.
./stash-create -d testplan/db
test $? -gt 0 && echo "Unable to create empty database file in 'testplan/db'" && exit 1

# create user 
./stash-adduser -d testplan/db -u testadmin -p testpass
test $? -gt 0 && echo "Unable to add 'testadmin' user" && exit 1

# create namespace
./stash-create-namespace -d testplan/db -n test
test $? -gt 0 && echo "Unable to create 'test' namespace" && exit 1

# grant rights to the user.
./stash-grant -d testplan/db -u testadmin -r ADDUSER 
test $? -gt 0 && echo "Unable to grant ADDUSER to 'testadmin' user" && exit 1

./stash-grant -d testplan/db -u testadmin -n test -r CREATE -r DROP
test $? -gt 0 && echo "Unable to grant CREATE,DROP to 'testadmin' user for namespace" && exit 1

test -e testplan/dump.txt && rm $_
test -e testplan/stashd.log && rm $_
test -e testplan/testplan.txt && rm $_


# start the daemon
if [ "$DEBUG" == "yes" ]
then
  echo "Start stash."
  echo "./stashd -m 1 -v -b testplan/db -l 127.0.0.1:13600"
  echo "Press Enter to continue"
  read
else
  ./stashd -v -b testplan/db -l 127.0.0.1:13600 -m 1 > testplan/stashd.log & 
  SDPID=$!
  echo "stashd pid = $SDPID"
  sleep 2
fi


# start the test-plan tool.
echo "Starting test plan"
time ./stash-testplan -v -H 127.0.0.1:13600 -U testadmin -P testpass > testplan/testplan.txt


# stop the daemon
if [ "$DEBUG" == "yes" ]
then
  echo "Stop the stashd daemon now"
  echo "Press ENTER to continue"
  read
else
  echo "kill the daemon"
  kill -s 2 $SDPID
  wait $SDPID
fi

# dump the database file.
./stash-dump -f testplan/db/00000000.stash > testplan/dump.txt

echo Test complete.  Will display results in 5 seconds.
sleep 5 || exit
less testplan/*.txt testplan/*.log

#exit.

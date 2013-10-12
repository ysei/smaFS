mp=/home/dsk/mntpnt

smaFS:	smaFS.c metadata.cpp translate.c restart.c versions.cpp reaper.cpp
	g++ -O2 -pedantic -std=gnu++0x `pkg-config fuse --cflags --libs` smaFS.c metadata.cpp restart.c translate.c hashlib/hashlib.c ziplib/ziplib.c ziplib/minilzo.c -o smaFS
	g++ -O2 -Wall -pedantic -std=gnu++0x -Dmetadata_DEBUG `pkg-config fuse --cflags --libs` restart.c metadata.cpp hashlib/hashlib.c ziplib/ziplib.c ziplib/minilzo.c -o metadata
	g++ -O2 -Wall -pedantic -std=gnu++0x versions.cpp -o versions
	g++ -O2 -Wall -g -pedantic -std=gnu++0x restart.c hashlib/hashlib.c ziplib/ziplib.c ziplib/minilzo.c reaper.cpp -o reaper
	sudo chown root:root versions reaper
	sudo chmod u+s versions reaper
clean:  
	rm -f *.o smaFS a.out cscope.out db fusexmp translate metadata versions
	rm -rf /tmp/test
	mkdir /tmp/test
test:  smaFS
	echo $(mp)
	exit
	
	mkdir -p /tmp/test
	mkdir -p $(mp)
	./smaFS -omodules=subdir,subdir=/tmp/test $(mp) -d -f -o default_permissions,allow_other &
	sleep 1
	cd $(mp); touch x y z; echo "test" > test.txt; echo "test test" > test.txt; cat test.txt#1
	sync
	sleep 1
	fusermount -u $(mp)

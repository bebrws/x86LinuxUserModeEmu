all: firstTest

# Run docker image
# docker run -v /Users/bbarrows/repos/x86UserModeEmu/emuTestResources:/home  -it  bradebarrows/x86linuxemu:1.0   /bin/bash


firstTest:
	as -static -arch i386 -o firstTest.o firstTest.s
	ld -static -arch i386 -o firstTest firstTest.o
	rm -rf firstTest.o
	chmod a+x firstTest
	cp firstTest $(CONFIGURATION_BUILD_DIR)/x86UserModeEmu.app/Contents/Resources/alpine/data/bin/  >/dev/null 2>&1 | true
	cp firstTest $(SRCROOT)/alpine/data/bin/  >/dev/null 2>&1 | true
	cp -r $(SRCROOT)/alpine  $(CONFIGURATION_BUILD_DIR)/alpine  >/dev/null 2>&1 | true


hworld32:
	docker run -v /Users/bbarrows/repos/x86UserModeEmu/emuTestResources:/home -it bradebarrows/x86linuxemu:1.0 /bin/bash -c "gcc -v -m32 /home/hworld.c /home/hworld"

as -static -arch i386 -o hworld.o hworld.s
ld -static -arch i386 -o hworld hworld.o

hworld32fa:
	docker run -v /Users/bbarrows/repos/x86UserModeEmu/emuTestResources:/home -it bradebarrows/x86linuxemu:1.0 /bin/bash -c "as --32 -o /home/hworldfa.o /home/hworldfa.s; ld -e main  -m elf_i386 -lc  /home/hworldfa.o -o /home/hworldfa"
clean:
	rm -rf *.o
	rm -rf firstTest

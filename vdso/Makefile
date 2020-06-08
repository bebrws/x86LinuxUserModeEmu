all: libvdso

vdso: libvdso

libvdso:
	C_INCLUDE_PATH=/usr/local/include CPLUS_INCLUDE_PATH=/usr/local/include /usr/local/opt/llvm/bin/clang -I../x86UserModeEmu -target i386-linux -fuse-ld=lld -o libvdso.so.elf.out vdso.S -nostdlib -Wl,-T,vdso.lds -Wl,--hash-style,sysv -shared -fPIC
	# C_INCLUDE_PATH=/usr/local/include CPLUS_INCLUDE_PATH=/usr/local/include /usr/local/opt/llvm/bin/clang -I../x86UserModeEmu -target i386-linux -fuse-ld=lld -o libvdso.so.elf.out vdso.c vdso.S -nostdlib -Wl,-T,vdso.lds -Wl,--hash-style,sysv -shared -fPIC
	# cp libvdso.so.elf.out libvdso.so.elf
	mv libvdso.so.elf.out ../libvdso.so.elf


clean:
	rm -rf libvdso.so.elf.out libvdso.so.elf ../libvdso.so.elf

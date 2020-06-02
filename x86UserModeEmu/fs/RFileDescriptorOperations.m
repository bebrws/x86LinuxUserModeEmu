//
//  FRFileDescriptorOperations.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/18/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#include <dirent.h>
#include <unistd.h>
#import "misc.h"
#import "FileDescriptor.h"
#import "Task.h"
#import "FileDescriptorOperations.h"
#import "RFileDescriptorOperations.h"
#import "errno.h"
#import "debug.h"

@implementation RFileDescriptorOperations

- (id)init {
    self = [super init];
    if (!self) {
        return nil;
    }

    return self;
}

- (void)opendir:(FileDescriptor *)fd {
    if (fd.dir == NULL) {
        int dirfd = dup(fd.realFD);
        fd.dir = fdopendir(dirfd);
        // this should never get called on a non-directory
        assert(fd.dir != NULL);
    }
}

- (void)seekdir:(FileDescriptor *)fd location:(int)location {
    [self opendir:fd];
    seekdir(fd.dir, location);
}

- (off_t_)lseek:(FileDescriptor *)fd off:(int)off whence:(int)whence {
    if (fd.dir != NULL && whence == LSEEK_SET) {
        [fd.fdOps seekdir:fd location:off];
        return off;
    }

    if (whence == LSEEK_SET)
        whence = SEEK_SET;
    else if (whence == LSEEK_CUR)
        whence = SEEK_CUR;
    else if (whence == LSEEK_END)
        whence = SEEK_END;
    else
        return _EINVAL;
    
    off_t res = lseek(fd.realFD, off, whence);
    if (res < 0)
        return errno_map();
    return res;
}

- (ssize_t)pread:(FileDescriptor *)fd buf:(char *)buf bufSize:(size_t)bufsize off:(off_t)off {
    ssize_t res = pread(fd.realFD, buf, bufsize, off);
    if (res < 0)
        return errno_map();
    return res;
}

- (ssize_t)read:(FileDescriptor *)fd buf:(char *)buf bufSize:(size_t)bufsize {
    ssize_t res = read(fd.realFD, buf, bufsize);
    if (res < 0)
        return errno_map();
    return res;
}

- (ssize_t)write:(FileDescriptor *)fd buf:(const char *)buf bufSize:(size_t)bufsize {
    ssize_t res = write(fd.realFD, buf, bufsize);
    if (res < 0)
        return errno_map();
    return res;
}

- (ssize_t)pwrite:(FileDescriptor *)fd buf:(const char *)buf bufSize:(size_t)bufsize off:(off_t)off {
    ssize_t res = pwrite(fd.realFD, buf, bufsize, off);
    if (res < 0)
        return errno_map();
    return res;
}


- (int)readdir:(FileDescriptor *)fd entry:(struct dir_entry *)entry {
    // TODO: Is this opendir necessary? A call to opendir should come through from the OS or a prcoess right?
    [self opendir:fd];
    
    // Read in a directory entry
    errno = 0;
    struct dirent *dirent = readdir(fd.dir);
    if (dirent == NULL) {
        if (errno != 0)
            return errno_map();
        else
            return 0;
    }
    
    // Setup our version of a directory entry which just is including the inode and name right now
    entry->inode = dirent->d_ino;
    strcpy(entry->name, dirent->d_name);
    return 1;
}

- (unsigned long)telldirL:(FileDescriptor *)fd {
    [self opendir:fd];
    return telldir(fd.dir);
}

- (void) seekdir:(FileDescriptor *)fd ptr:(unsigned long)ptr {
    [self opendir:fd];
    seekdir(fd.dir, ptr);
}

- (int)mmap:(FileDescriptor *)fd task:(Task *)task start:(page_t)start pages:(pages_t)pages offset:(off_t)offset prot:(int)prot flags:(int)flags {
    die("Not yet implemented!"); return 0;
}

- (int)poll:(FileDescriptor *)fd {
    die("Not yet implemented!"); return 0;
}

- (ssize_t)ioctl_size:(int) cmd {
    if (cmd == FIONREAD_)
        return sizeof(dword_t);
    return -1;
}

- (int)ioctl:(FileDescriptor *)fd cmd:(int)cmd arg:(void *)arg {
    die("Not yet implemented!"); return 0;
}

- (int)fsync:(FileDescriptor *)fd {
    die("Not yet implemented!"); return 0;
}
- (int)close:(FileDescriptor *)fd {
    if (fd.dir)
        closedir(fd.dir);
    int err = close(fd.realFD);
    if (err < 0)
        return errno_map();
    die("Not yet implemented!"); return 0;
}

- (int)getflags:(FileDescriptor *)fd {
    die("Not yet implemented!"); return 0;
}

- (int)setflags:(FileDescriptor *)fd arg:(dword_t)arg {
    die("Not yet implemented!"); return 0;
}


@end

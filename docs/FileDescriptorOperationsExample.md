
//
//  FRFileDescriptorOperations.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/18/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#include <dirent.h>
#import "misc.h"
#import "FileDescriptor.h"
#import "Task.h"
#import "FileDescriptorOperations.h"
#import "FRFileDescriptorOperations.h"
#import "errno.h"

@implementation FRFileDescriptorOperations

+ (void)opendir:(FileDescriptor *)fd {
    if (fd.dir == NULL) {
        int dirfd = dup(fd.realFD);
        fd.dir = fdopendir(dirfd);
        // this should never get called on a non-directory
        assert(fd.dir != NULL);
    }
}

+ (void)seekdir:(FileDescriptor *)fd location:(int)location {
    [FRFileDescriptorOperations opendir:fd];
    seekdir(fd.dir, location);
}

+ (off_t_)lseek:(FileDescriptor *)fd off:(int)off whence:(int)whence {
    if (fd.dir != NULL && whence == LSEEK_SET) {
        [FRFileDescriptorOperations seekdir:fd location:off];
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

+ (ssize_t)pread:(FileDescriptor *)fd buf:(char *)buf bufSize:(size_t)bufsize off:(off_t)off {
    ssize_t res = read(fd.realFD, buf, bufsize);
    if (res < 0)
        return errno_map();
    return res;
}

+ (ssize_t)read:(FileDescriptor *)fd buf:(char *)buf bufSize:(size_t)bufsize {
    return 0;
}

+ (ssize_t)write:(FileDescriptor *)fd buf:(const char *)buf bufSize:(size_t)bufsize {
    return 0;
}

+ (ssize_t)pwrite:(FileDescriptor *)fd buf:(const char *)buf bufSize:(size_t)bufsize off:(off_t)off {
    return 0;
}

+ (int)readdir:(FileDescriptor *)fd entry:(struct dir_entry *)entry {
    return 0;
}

+ (unsigned long)telldirL:(FileDescriptor *)fd {
    return 0;
}

+ (void) seekdir:(FileDescriptor *)fd ptr:(unsigned long)ptr {
    return;
}

+ (int)mmap:(FileDescriptor *)fd task:(Task *)task start:(page_t)start pages:(pages_t)pages offset:(off_t)offset prot:(int)prot flags:(int)flags {
    return 0;
}

+ (int)poll:(FileDescriptor *)fd {
    return 0;
}

+ (ssize_t)ioctl_size:(int) cmd {
    return 0;
}

+ (int)ioctl:(FileDescriptor *)fd cmd:(int)cmd arg:(void *)arg {
    return 0;
}

+ (int)fsync:(FileDescriptor *)fd {
    return 0;
}
+ (int)close:(FileDescriptor *)fd {
    return 0;
}

+ (int)getflags:(FileDescriptor *)fd {
    return 0;
}

+ (int)setflags:(FileDescriptor *)fd arg:(dword_t)arg {
    return 0;
}


@end

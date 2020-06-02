//
//  FileDescriptorOperations.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/18/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <dirent.h>
#import "misc.h"
#import "FileDescriptor.h"
#import "Task.h"

@class FileDescriptor;
@class Task;
@class FakeFSStore;

@protocol FileDescriptorOperations <NSObject>

- (id)initWith:(Task *)currentTask;
- (ssize_t)read:(FileDescriptor *)fd buf:(char *)buf bufSize:(size_t)bufsize;
- (ssize_t)write:(FileDescriptor *)fd buf:(const char *)buf bufSize:(size_t)bufsize;
- (ssize_t)pread:(FileDescriptor *)fd buf:(char *)buf bufSize:(size_t)bufsize off:(off_t)off;
- (ssize_t)pwrite:(FileDescriptor *)fd buf:(const char *)buf bufSize:(size_t)bufsize off:(off_t)off;
- (off_t_)lseek:(FileDescriptor *)fd off:(int)off whence:(int)whence;

// Reads a directory entry from the stream
// required for directories
- (int)readdir:(FileDescriptor *)fd entry:(struct dir_entry *)entry;
// Return an opaque value representing the current point in the directory stream
// optional fd->offset will be used instead
- (unsigned long)telldirL:(FileDescriptor *)fd;
// Seek to the location represented by a pointer returned from telldir
// optional fd->offset will be used instead
- (void) seekdir:(FileDescriptor *)fd location:(unsigned long)location;

// map the file
- (int)mmap:(FileDescriptor *)fd task:(Task *)task start:(page_t)start pages:(pages_t)pages offset:(off_t)offset prot:(int)prot flags:(int)flags;

// returns a bitmask of operations that won't block
- (int)poll:(FileDescriptor *)fd;

// returns the size needed for the output of ioctl 0 if the arg is not a
// pointer -1 for invalid command
- (ssize_t)ioctl_size:(int) cmd;
// if ioctl_size returns non-zero arg must point to ioctl_size valid bytes
- (int)ioctl:(FileDescriptor *)fd cmd:(int)cmd arg:(void *)arg;

- (int)fsync:(FileDescriptor *)fd;
- (int)close:(FileDescriptor *)fd;

// handle F_GETFL i.e. return open flags for this fd
- (int)getflags:(FileDescriptor *)fd;
// handle F_SETFL i.e. set O_NONBLOCK
- (int)setflags:(FileDescriptor *)fd arg:(dword_t)arg;
@end


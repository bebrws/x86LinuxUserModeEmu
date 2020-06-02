//
//  FileSystemOperations.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/18/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "FileSystem.h"
#import "FileDescriptor.h"
#import "Mount.h"
#import "misc.h"
#import "dev.h"

@class FileDescriptor;
@class Task;
@class Mount;

@protocol FileSystemOperations
- (id)initWith:(Task *)currentTask;
- (int)mount:(Mount *)mount;
- (int)umount:(Mount *)mount;
- (int)statfs:(Mount *)mount stat:(struct statfsbuf *)stat;

- (FileDescriptor *)open:(Mount *)mount path:(NSString *)path flags:(int)flags mode:(int)mode currentTask:(Task *)currentTask;
- (ssize_t)readlink:(Mount *)mount path:(NSString *)path buf:(char *)buf bufsize:(size_t)bufsize;

// These return _EPERM if not present
- (int)link:(Mount *)mount src:(NSString *)src dst:(NSString *)dst;
- (int)unlink:(Mount *)mount path:(NSString *)path;
- (int)rmdir:(Mount *)mount path:(NSString *)path;
- (int)rename:(Mount *)mount src:(NSString *)src dst:(NSString *)dst;
- (int)symlink:(Mount *)mount target:(NSString *)target link:(NSString *)link;
- (int)mknod:(Mount *)mount path:(NSString *)path mode:(mode_t_)mode dev:(dev_t_)dev;
- (int)mkdir:(Mount *)mount path:(NSString *)path mode:(mode_t_)mode;

// There's a close function in both the fs and fd to handle device files
// where for instance there's a real_fd needed for getpath and also a tty
// reference and both need to be released when the fd is closed.
// If they are the same function it will only be called once.
- (int)close:(FileDescriptor *)fd;

- (int)stat:(Mount *)mount path:(NSString *)path stat:(struct statbuf *)stat; // required
- (int)fstat:(FileDescriptor *)fd stat:(struct statbuf *)stat; // required
- (int)setattr:(Mount *)mount path:(NSString *)path attr:(struct attr)attr;
- (int)fsetattr:(FileDescriptor *)fd attr:(struct attr)attr;
- (int)utime:(Mount *)mount path:(NSString *)path atime:(struct timespec)atime mtime:(struct timespec)mtime;
// Returns the path of the file descriptor null terminated buf must be at least MAX_PATH+1
- (int)getpath:(FileDescriptor *)fd buf:(NSMutableString *)buf;
- (int)flock:(FileDescriptor *)fd operation:(int)operation;
// If present called when all references to an inode_data for this
// filesystem go away.
- (void)inode_orphaned:(Mount *)mount inode:(ino_t)inode;

@end

//
//  FileSystem.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <dirent.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sqlite3.h>
#import "FileSystem.h"
#import "Task.h"
#import "Globals.h"
#import "errno.h"
#import "Mount.h"
#import "MountLookup.h"
#import "FileDescriptor.h"
#import "FRFileSystemOperations.h"
#import "NSString+FileSystemEmu.h"
#import "debug.h"
#import "log.h"
#import "dev.h"
#import "errno.h"

@implementation FileSystem


- (FileDescriptor *)genericOpen:(NSString *)path flags:(int)flags mode:(int)mode currentTask:(Task *)currentTask {
    // AT_PWD is a FileDescriptor which represents no file descriptor.. Might as well be NULL?
    return [self genericOpenAt:AT_PWD path:path flags:flags mode:mode currentTask:currentTask];
}

- (FileDescriptor *) genericOpenAt:(FileDescriptor *)at path:(NSString *)pathRaw flags:(int)flags mode:(int)mode currentTask:(Task *)currentTask {
    if (flags & O_RDWR_ && flags & O_WRONLY_) {
        FileDescriptor *fd= [FileDescriptor new];
        fd.err = _EINVAL;
        
        FFLog(@"Error opening file descriptor not right flags: flags & O_RDWR_ && flags & O_WRONLY_ ");
        
        return fd;
    }

    NSMutableString *pathN = [@"" mutableCopy]; // [NSMutableString new];
    int err = [self pathNormalize:at path:pathRaw outString:pathN flags:N_SYMLINK_FOLLOW | (flags & O_CREAT_ ? N_PARENT_DIR_WRITE : 0) currentTask:currentTask];
//    if ([path isEqualToString:@""]) path = @"";
    
    if (err < 0) {
        FileDescriptor *fd=[FileDescriptor new];
        fd.err = err;
        FFLog(@"Error opening file descriptor - pathNormalize failed to return fd");
        
        return fd;
    }
    Mount *mount = [self findMountAndTrimPath:pathN];
//    lock(&inodes_lock); // TODO: don't do this
    FileDescriptor *fd = [self.fsOps open:mount path:pathN flags:flags mode:mode currentTask:currentTask];
    if (fd.err) {
        // unlock(&inodes_lock);
        [mount releaseMount];
        return fd;
    }
    fd.mount = mount;
    struct statbuf statResult;
    
    err = [self.fsOps fstat:fd stat:&statResult];
    if (err < 0) {
//        unlock(&inodes_lock);
        [fd close];
        fd.err = err;
        FFLog(@"Error opening file descriptor for fstat in genericOpenat");
        
        return fd;
    }
//    fd->inode = inode_get_unlocked(mount, stat.inode);
//    unlock(&inodes_lock);
    
    fd.type = statResult.mode & S_IFMT;
    fd.flags = flags;
//
    int accmode;
    if (flags & O_RDWR_) accmode = AC_R | AC_W;
    else if (flags & O_WRONLY_) accmode = AC_W;
    else accmode = AC_R;
    
    err = [self accessCheck:&statResult check:accmode currentTask:currentTask];
    if (err < 0) {
        // This is goto error
        [fd close];
        fd.err = err;
        FFLog(@"Access check failed");
        return fd;
    }

    // TODO: UNSURE: we should only have a fd that is for an absolute path without symlinks by now?
//    assert(!S_ISLNK(fd.type)); // would mean path_normalize didn't do its job
//
//    if (S_ISBLK(fd.type) || S_ISCHR(fd.type)) {
//        int type;
//        if (S_ISBLK(fd.type))
//            type = DEV_BLOCK;
//        else
//            type = DEV_CHAR;
//
//        err = dev_open(dev_major(statResult.rdev), dev_minor(statResult.rdev), type, fd);
//
//        if (err < 0) {
//            [fd close];
//            fd.err = _ENXIO;
//            return fd;
//        }
//    }
//
//    if ((S_ISSOCK(fd.type)) || (S_ISDIR(fd.type) && flags & (O_RDWR_ | O_WRONLY_)) || (!S_ISDIR(fd.type) && flags & O_DIRECTORY_)) {
//        [fd close];
//        fd.err = _ENXIO;
//        return fd;
//    }
    
#ifdef DEBUG
    if ([self.recentOpens length] > MAX_RECENT_OPENS_LENGTH) {
        [self.recentOpens setString:pathN];
    } else {
        [self.recentOpens appendFormat:@" %@ ", pathN];
    }
#endif
    
    fd.originalPath = pathN;

    return fd;
}





- (id)init {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    self.recentOpens = [@"" mutableCopy];
    self.rootMountPath = @"--";
    
    self.fsOps = [[FRFileSystemOperations alloc] init];
    self.mounts = [MountLookup new];
    
    return self;
}

- (int)mountRoot:(NSString *)path currentTask:(Task *)currentTask {
    char sourceRealpath[MAX_PATH + 1];
    if (realpath([path UTF8String], sourceRealpath) == NULL) {
        return errno_map();
    }
    NSString *realPath = [NSString stringWithCString:sourceRealpath encoding:NSUTF8StringEncoding];
    self.rootMountPath = realPath;
    int err = [self doMount:realPath point:@"" flags:0];
    if (err < 0) {
        return err;
    }
    
    self.root = [self genericOpen:@"/" flags:O_RDONLY_ mode:0 currentTask:currentTask];
    
    // TODO: IMPORTANT: Find a better way to pass up errors? Maybe throw an exception?r
    if (self.root.err) {
        return self.root.err;
    }
    
    self.pwd = self.root;
    [self.root incrementRefCount];
    
    return 0;
}

- (int)umount:(Mount *)mount {
    // TODO: Write anything to JSON FS here
    
    return 0;
}

- (int)doMount:(NSString *)source point:(NSString *)point flags:(int)flags {
    Mount *newMount = [[Mount alloc] initWithFS:self];
    newMount.point = [point copy];
    newMount.source = [source copy];
    newMount.flags = flags;
    newMount.data = NULL;
    newMount.refCount = 0;
    
    int err = [self.fsOps mount:newMount];
    if (err < 0) {
        return err;
    }

    [self.mounts.mountsByPoint setValue:newMount forKey:newMount.point];
    // [self.mounts.mountsByPoint objectForKey:newMount.point]
    
    return 0;
}


- (Mount *)findMountAndTrimPath:(NSMutableString *)path {
    FFLog(@"Looking for mount at path: %@", path);
    
    Mount *mount = [self.mounts findMount:path];
    
    FFLog(@"Found mount: %@", mount);
    
    if (!mount) {
        die("no mount found for path");
    }
    
    // Subtract the mount.path string from the path string
    if ([path length] && [mount.point length])
        [path setString:[path substringFromIndex:[mount.point length] - 1]];
    return mount;
}



- (int)accessCheck:(struct statbuf*)stat check:(int)check currentTask:(Task *)currentTask {
    if ([currentTask isSuperuser]) return 0;
    if (check == 0) return 0;
    // Align check with the correct bits in mode
    if (currentTask->euid == stat->uid) {
        check <<= 6;
    } else if (currentTask->egid == stat->gid) {
        check <<= 3;
    }
    if (!(stat->mode & check))
        return _EACCES;
    return 0;
}

- (int)pathNormalize:(FileDescriptor *)at path:(NSString *)path outString:(NSMutableString *)outString flags:(int)flags currentTask:(Task *)currentTask {
    if ([path isEqualToString:@""]) {
        return _ENOENT;
    }
    
    // start with root or cwd, depending on whether it starts with a slash
//    lock(&current->fs->lock);
    if ([path characterAtIndex:0] == '/') {
        at = self.root;
    } else if (at == AT_PWD) {
        at = self.root;
        // This was: at = self.pwd;
    }

//    unlock(&current->fs->lock);
//    NSMutableString *atPath=[NSMutableString init];
    if (at != NULL) {
        // TODO: Why not just use File Descrptor at.mount.source
        
#ifdef BDEBUG
            char tmpBuf[MAX_PATH];
            int derr = fcntl(at.realFD, F_GETPATH, tmpBuf);
            FFLog(@"BEB File path for realFD: %s", tmpBuf);
        
            derr = fcntl(at.mount.rootFD, F_GETPATH, tmpBuf);
            FFLog(@"BEB File path for rootFD: %s", tmpBuf);
#endif
        
        NSString *atPath=[self getPathAt:at];
        if (!atPath) {
            // TODO Some error code
            return -1;
        }
        // TODO: Implment NSString extension for pathIsNormalized
        // assert([at_path pathIsNormalized]);
        return [self pathNormalizeLevels:atPath path:path outString:outString flags:flags levels:0 currentTask:currentTask];
    }

    return [self pathNormalizeLevels:nil path:path outString:outString flags:flags levels:0 currentTask:currentTask];
}

- (NSString *)getPathAt:(FileDescriptor *)fd {
    NSMutableString *buf = [NSMutableString new];
    int err = [self.fsOps getpath:fd buf:buf];
    
    // Check if the combo of this path + the file descriptors mount path is
    // too long
    if (([buf length] + [fd.mount.point length]) >= MAX_PATH) {
        FFLog(@"Error: The path for the FD:%@ is too long");
        die("The path was too long in getPathAt");
        return nil;
        // return _ENAMETOOLONG;
    }
    
    // Copy the mount.point into the front of
     buf = [NSString stringWithFormat:@"%@%@", fd.mount.point, buf];
//    buf = [fd.mount.point stringByAppendingString:buf];
    
    return [buf isEqualToString:@""] ? @"/" : buf;
}

- (int)pathNormalizeLevels:(NSString *)atPath path:(NSString *)path outString:(NSMutableString *)outString flags:(int)flags levels:(int)levels currentTask:(Task *)currentTask {
    FFLog(@"PN: Entering normalizingLevels - path: %@  ---   Output path: %@", path, outString);
    // you must choose one
    if (flags & N_SYMLINK_FOLLOW)
        assert(!(flags & N_SYMLINK_NOFOLLOW));
    else
        assert(flags & N_SYMLINK_NOFOLLOW);

    [outString setString:@""];
    
    if ([path isEqualToString:@""]) {
        return _ENOENT;
    }
    
    if (atPath && ![atPath isEqualToString:@"/"]) {
        [outString setString:atPath];
    }

    NSArray<NSString *> *pathComponents = [path pathComponents];
    int pathIndex = 0;
    for (NSString *pathComponent in pathComponents) {
//        if (pathIndex == 1) {
//            continue;
//        }
        
        if (![pathComponent isEqualToString:@"/"]) {
            
            if ([pathComponent isEqualToString:@"."]) {
                // Ignore .
            } else if ([pathComponent isEqualToString:@".."]) {
                [outString setString:[outString stringByDeletingLastPathComponent]];
            } else {
                
//                if ((flags & N_SYMLINK_FOLLOW) || pathIndex < [pathComponents count]) {
//                    possibleSymlink = [[NSMutableString alloc] initWithString:outString];
//                }
                [outString appendString:@"/"];
                [outString appendString:pathComponent];
            }
            
            // If we are to follow symlinks that make up part of the path
            // (if symlinks make up part of the path)
            // Or if the path is done being resolved, then check to see if it is
            // a symlink
            if ((flags & N_SYMLINK_FOLLOW) || pathIndex == [pathComponents count] - 1) {
                //
                // In this if block we do 2 things
                // 1. Check if the path is to a symlink and handle that if so, restarting this parth normalizing process with the symlink path
                // or 2. Check if the path is a directory and if so check if we have exec perms on the dir. Otherwise fail
                // TODO: Does this only happen on the final dir? Could this if block because 1 if else instead of 1 if with 2 ifs in it?
                //
                NSMutableString *possibleSymlink;
                possibleSymlink = [[NSMutableString alloc] initWithString:outString];
                
                Mount *mount = [self findMountAndTrimPath:possibleSymlink];
    //            assert(path_is_normalized(possible_symlink));
                
                // TODO Is this a bug? Should possibleSymlink include the last path component that was copied into
                // outString too?
                char buf[MAX_PATH];
                int sizeOfStringRead = [self.fsOps readlink:mount path:possibleSymlink buf:buf bufsize:MAX_PATH];
                if (sizeOfStringRead >= 0) {
                    char *readFromReadlinkTerminated = malloc(sizeof(char) * (sizeOfStringRead+1)); // sizeof(char) should be unneccessary char is 1 byte..
                    memcpy(readFromReadlinkTerminated, buf, sizeOfStringRead);
                    readFromReadlinkTerminated[sizeOfStringRead] = '\0';
                    NSString *readFromReadlink = [NSString stringWithCString:readFromReadlinkTerminated encoding:NSUTF8StringEncoding];
                    free(readFromReadlinkTerminated);
                    FFLog(@"PN: Normalizing file using readlink. Contents are: %@", readFromReadlink);
                    [outString appendString:readFromReadlink];
                    
                    if (levels >= 5)
                        return _ELOOP;
                    
                    if ([readFromReadlink length] && [readFromReadlink characterAtIndex:0] == '/')
                        [outString setString:readFromReadlink];
                    
                    NSMutableString *expanded = [NSMutableString stringWithString:outString];
                    // If there are more path components left then add them all to the
                    // expanded path string
                    pathIndex++;
                    if (pathIndex < [pathComponents count]) {
                        for (int innerPathIndex=pathIndex; innerPathIndex < [pathComponents count]; innerPathIndex++) {
                            [expanded appendString:@"/"];
                            [expanded appendString:[pathComponents objectAtIndex:innerPathIndex]];
                        }
                    }
                    
                    FFLog(@"PN: Expanded file path: %@", expanded);
                    
                    // Decrement the refcount of the mount before normalizing path again recursively
                    // findMountAndTrimPath was what incremented the refcount before
                    [mount releaseMount];
                    return [self pathNormalizeLevels:nil path:expanded outString:outString flags:flags levels:(levels + 1) currentTask:currentTask];
                }

                
                // If this is just a directory and there is more path left then make sure we have execute permissions
                // on the dir
                if ([path characterAtIndex:[path length] - 1] == '/') {
                    struct statbuf statResult;
                    int err = [self.fsOps stat:mount path:possibleSymlink stat:&statResult];
                    [mount releaseMount];
                    if (err >= 0) {
                        if (!S_ISDIR(statResult.mode))
                            return _ENOTDIR;
                        err = [self accessCheck:&stat check:AC_X currentTask:currentTask];
                        if (err < 0)
                            return err;
                    }
                } else {
                    [mount releaseMount];
                }
            }
        }
        pathIndex += 1;
    }
    
    FFLog(@"PN: Finished normalizing path: %@     -- to --   Output path: %@", path, outString);
    
//    assert(path_is_normalized(out));
    return 0;
}


// Private?
+ (int)openFlagsRealFromFake:(int) flags {
    int realFlags = 0;
    if (flags & O_RDONLY_) realFlags |= O_RDONLY;
    if (flags & O_WRONLY_) realFlags |= O_WRONLY;
    if (flags & O_RDWR_) realFlags |= O_RDWR;
    if (flags & O_CREAT_) realFlags |= O_CREAT;
    if (flags & O_TRUNC_) realFlags |= O_TRUNC;
    if (flags & O_APPEND_) realFlags |= O_APPEND;
    if (flags & O_NONBLOCK_) realFlags |= O_NONBLOCK;
    return realFlags;
}

// Private?
+ (int)openFlagsFakeFromReal:(int) flags {
    int fakeFlags = 0;
    if (flags & O_RDONLY) fakeFlags |= O_RDONLY_;
    if (flags & O_WRONLY) fakeFlags |= O_WRONLY_;
    if (flags & O_RDWR) fakeFlags |= O_RDWR_;
    if (flags & O_CREAT) fakeFlags |= O_CREAT_;
    if (flags & O_TRUNC) fakeFlags |= O_TRUNC_;
    if (flags & O_APPEND) fakeFlags |= O_APPEND_;
    if (flags & O_NONBLOCK) fakeFlags |= O_NONBLOCK_;
    return fakeFlags;
}


-(NSString *)description {
    return [[NSString alloc] initWithFormat:@"MountPoints: %@", self.mounts, self.pwd, self.root];
}



@end



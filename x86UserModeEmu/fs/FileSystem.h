//
//  FileSystem.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//
//#ifndef FILESYSTEM_H
//#define FILESYSTEM_H

#import <Foundation/Foundation.h>
#include <dirent.h>
#include <stddef.h>
#include <stdarg.h>
#include <limits.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sqlite3.h>
#include "misc.h"
#import "FileSystemOperations.h"
//#import "MountLookup.h"
//#import "Mount.h"
//#import "Task.h"


#define MAX_RECENT_OPENS_LENGTH 500


// open flags
#define O_ACCMODE_ 3
#define O_RDONLY_ 0
#define O_WRONLY_ (1 << 0)
#define O_RDWR_ (1 << 1)
#define O_CREAT_ (1 << 6)
#define O_EXCL_ (1 << 7)
#define O_NOCTTY_ (1 << 8)
#define O_TRUNC_ (1 << 9)
#define O_APPEND_ (1 << 10)
#define O_NONBLOCK_ (1 << 11)
#define O_DIRECTORY_ (1 << 16)
#define O_CLOEXEC_ (1 << 19)

// generic ioctls
#define FIONREAD_ 0x541b
#define FIONBIO_ 0x5421

#define AC_R 4
#define AC_W 2
#define AC_X 1
#define AC_F 0

#define MAX_PATH 4096
#define MAX_NAME 256

struct attr {
    enum attr_type {
        attr_uid,
        attr_gid,
        attr_mode,
        attr_size,
    } type;
    union {
        uid_t_ uid;
        uid_t_ gid;
        mode_t_ mode;
        off_t_ size;
    };
};
#define make_attr(_type, thing) \
    ((struct attr) {.type = attr_##_type, ._type = thing})

#define AT_SYMLINK_NOFOLLOW_ 0x100



// This is the struct for the stat that is in the database
struct ish_stat {
    dword_t mode;
    dword_t uid;
    dword_t gid;
    dword_t rdev;
};

//TODO Try not to use?
struct statbuf {
    qword_t dev;
    qword_t inode;
    dword_t mode;
    dword_t nlink;
    dword_t uid;
    dword_t gid;
    qword_t rdev;
    qword_t size;
    dword_t blksize;
    qword_t blocks;
    dword_t atime;
    dword_t atime_nsec;
    dword_t mtime;
    dword_t mtime_nsec;
    dword_t ctime;
    dword_t ctime_nsec;
};

// TODO Use just this?
//struct newstat64 {
struct emustat64 {
    qword_t dev;
    dword_t _pad1;
    dword_t inode; 
    dword_t mode;
    dword_t nlink;
    dword_t uid;
    dword_t gid;
    qword_t rdev;
    dword_t _pad2;
    qword_t size;
    dword_t blksize;
    qword_t blocks;
    dword_t atime;
    dword_t atime_nsec;
    dword_t mtime;
    dword_t mtime_nsec;
    dword_t ctime;
    dword_t ctime_nsec;
    qword_t ino;
} __attribute__((packed));


struct statfsbuf {
    long type;
    long bsize;
    uint64_t blocks;
    uint64_t bfree;
    uint64_t bavail;
    uint64_t files;
    uint64_t ffree;
    uint64_t fsid;
    long namelen;
    long frsize;
    long flags;
    long spare[4];
};



struct statfs_ {
    uint_t type;
    uint_t bsize;
    uint_t blocks;
    uint_t bfree;
    uint_t bavail;
    uint_t files;
    uint_t ffree;
    uint64_t fsid;
    uint_t namelen;
    uint_t frsize;
    uint_t flags;
    uint_t spare[4];
};

struct statfs64_ {
    uint_t type;
    uint_t bsize;
    uint64_t blocks;
    uint64_t bfree;
    uint64_t bavail;
    uint64_t files;
    uint64_t ffree;
    uint64_t fsid;
    uint_t namelen;
    uint_t frsize;
    uint_t flags;
    uint_t pad[4];
} __attribute__((packed));



@class FileDescriptor;
@class Task;
@class Mount;
@class MountLookup;
@class FileSystem;

@protocol FileSystemOperations;

@interface FileSystem : NSObject
// DEBUG
@property (nonatomic, strong) NSMutableString *recentOpens;

@property (nonatomic, strong) id<FileSystemOperations> fsOps;
@property (nonatomic, strong) FileDescriptor *root;
@property (nonatomic, strong) FileDescriptor *pwd;
@property (nonatomic, strong) NSString *rootMountPath;
@property (nonatomic, strong) MountLookup *mounts;

//@property (nonatomic, assign) CPU *cpu;
//- (void)genericOpen: (NSString *)path, int flags, int mode;
- (id)init;
- (int)mountRoot:(NSString *)path currentTask:(Task *)currentTask;

- (int)umount:(Mount *)mount;
//- (int)readlink:(Mount *)mount path:(NSString *)possibleSymlink willBeAppendedTo:(NSMutableString *)into read:(NSMutableString *)readlinkResult;
- (Mount *)findMountAndTrimPath:(NSMutableString *)path;

- (int)accessCheck:(struct statbuf*)stat check:(int)check currentTask:(Task *)currentTask;
- (int)pathNormalize:(FileDescriptor *)at path:(NSString *)path outString:(NSMutableString *)outString flags:(int)flags currentTask:(Task *)currentTask;
- (int)pathNormalizeWithLevels:(NSString *)atPath path:(NSString *)path outString:(NSMutableString *)outString flags:(int)flags levels:(int)levels currentTask:(Task *)currentTask;

- (sqlite3_stmt *)dbPrepare:(Mount *)mount stmt:(const char *)stmt;

+ (int)openFlagsRealFromFake:(int)flags;
+ (int)openFlagsFakeFromReal:(int)flags;

- (FileDescriptor *)genericOpen:(NSString *)path flags:(int)flags mode:(int)mode currentTask:(Task *)currentTask;
- (FileDescriptor *)genericOpenAt:(FileDescriptor *)fd path:(NSString *)path flags:(int)flags mode:(int)mode currentTask:(Task *)currentTask;


@end

//#endif

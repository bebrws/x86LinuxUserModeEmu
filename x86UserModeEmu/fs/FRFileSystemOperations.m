//
//  FRFileSystemOperations.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/18/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <unistd.h>
#include <dirent.h>
#include <stddef.h>
#include <stdarg.h>
#include <limits.h>
#include <string.h>
#include <sqlite3.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#import "log.h"


#import "NSArray+Blocks.h"
#import "NSString+FileSystemEmu.h"
#import "NSSet+Intersection.h"
#import "NSSet+Blocks.h"
#import "FRFileSystemOperations.h"
#import "FileSystemOperations.h"
#import "FileDescriptor.h"
#import "FileSystem.h"
#import "FakeFSStore.h"
#import "Mount.h"
#import "misc.h"
#import "debug.h"
#import "errno.h"
#import "dev.h"




/*
 
 mount->stmt.begin = db_prepare(mount->db, "begin");
 mount->stmt.commit = db_prepare(mount->db, "commit");
 mount->stmt.rollback = db_prepare(mount->db, "rollback");
 mount->stmt.path_get_inode = db_prepare(mount->db, "select inode from paths where path = ?");
 mount->stmt.path_read_stat = db_prepare(mount->db, "select inode, stat from stats natural join paths where path = ?");
 mount->stmt.path_create_stat = db_prepare(mount->db, "insert into stats (stat) values (?)");
 mount->stmt.path_create_path = db_prepare(mount->db, "insert or replace into paths values (?, last_insert_rowid())");
 mount->stmt.inode_read_stat = db_prepare(mount->db, "select stat from stats where inode = ?");
 mount->stmt.inode_write_stat = db_prepare(mount->db, "update stats set stat = ? where inode = ?");
 mount->stmt.path_link = db_prepare(mount->db, "insert or replace into paths (path, inode) values (?, ?)");
 mount->stmt.path_unlink = db_prepare(mount->db, "delete from paths where path = ?");
 mount->stmt.path_rename = db_prepare(mount->db, "update or replace paths set path = change_prefix(path, ?, ?) "
         "where (path >= ? and path < ?) or path = ?");
 mount->stmt.path_from_inode = db_prepare(mount->db, "select path from paths where inode = ?");
 mount->stmt.try_cleanup_inode = db_prepare(mount->db, "delete from stats where inode = ? and not exists (select 1 from paths where inode = stats.inode)");

 
 */

@class FileDescriptor;
@class Task;
@class Mount;
@class FileSystem;
@class FakeFSStore;

@implementation FRFileSystemOperations

- (id)init {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    self.fakeFSStore = [FakeFSStore new];
    
    [self.fakeFSStore save];
    self->magic = 1717660517;
    
    return self;
}

- (int)rebuildDB:(Mount *)mount {
    
    NSMutableDictionary *lookupPathByInode = [NSMutableDictionary new];
    
    for (NSString *path in [self.fakeFSStore getPaths]) {
        NSNumber *inodeForPath = [self.fakeFSStore getInodeForPath:path];
        NSString *fixedPath = [path fixPath];
        const char *fixedPathCStr = [fixedPath UTF8String];
        
        struct stat fstatatResult;
        int err = fstatat(mount.rootFD, fixedPathCStr, &fstatatResult, 0);
        if (err < 0)
            continue;
        NSNumber *realInode = [NSNumber numberWithUnsignedLongLong:fstatatResult.st_ino];
        
        // If, the inode for this path has already been seen then lets link em together
        // This will link the first path with an inode seen to the 2nd, 3rd, etc path's inode
        // that is equal to it
        NSString *existingInodesPath = [lookupPathByInode valueForKey:[inodeForPath stringValue]];
        if (existingInodesPath) {
            unlinkat(mount.rootFD, fixedPathCStr, 0);
            linkat(mount.rootFD, [existingInodesPath UTF8String], mount.rootFD, fixedPathCStr, 0);
        } else {
            [lookupPathByInode setValue:fixedPath forKey:[inodeForPath stringValue]];
        }
        
        NSString *statString = [self.fakeFSStore getStatStringForInode:inodeForPath];
        if (!statString) {
            FFLog(@"Missing stat for inode: %@ path: %@", inodeForPath, path);
            die("A stat was missing for an inode");
        }
        
        // Keeping the path the same
        // Update that path's inode and that inode's stat to have the same stat
        [self.fakeFSStore updateInodeForPath:path inode:realInode];
        [self.fakeFSStore updateStatStringForInode:realInode stat:statString];
        
#ifdef FSDEBUG
        FFLog(@"UpdatingFakeFS Set --- path: %@ inode: %@ stat: %@", path, realInode, statString);
        // NSString *statStr = [[FakeFSStore inodeToStat] valueForKey:[realInode stringValue]];
        // FFLog(@"UpdatingFakeFS inode to stat = %@ - %@", realInode, statStr);
#endif
        
#ifdef BDEBUG

        if (![[self.fakeFSStore getStatStringForInode:realInode] isEqualToString:statString]) {
            die("FakeFSStore update failed - stat from inode");
        }
        if (![[self.fakeFSStore getStatStringForPath:path] isEqualToString:statString]) {
            die("FakeFSStore update failed - stat from path");
        }
        NSString *matchingPath = [[self.fakeFSStore getPathsForInode:realInode] first:^ (NSString *iPath) { return [path isEqualToString:iPath]; }];
        if (!matchingPath) {
            NSArray *allPaths = [[FakeFSStore pathToInode] allKeysForObject:realInode];
            FFLog(@"Path was missing from list: %@", allPaths);
            die("FakeFSStore update failed - path");
        }
        
#endif
        
    }
    
    // delete from stats where not exists (select 1 from paths where inode = stats.inode)
    //
    // Remove path/inode inodeToStat where no match of pathToInode.inode = inodeToStat.inode
    //
    // So iterate over all inodeToStat.inodes and if there is no corresponding inode in pathToInode then remove it from inodeToStat
    
    // First create a list of all inodes in inodeToStat.inodes that are not in pathToInode.inodes
    // NOTE That in the underlying NSMutableDictionairys in inodeToStat inodes are keys and are therefore NSStrings
    // In pathToInode the Inode is a value so I was able to use any NSObject type and went with NSNumber
    //
    // Will give me a list of inodes from inodeToStat.inodes that are not in  pathToInode.inodes

    
    //    NSArray *orphanedInodesUsingListComparisons = [[[FakeFSStore inodeToStat] allKeys] filter:^(NSString *statInode) {
////        FFLog(@"Checking statInode %@", statInode);
//        return (BOOL)([[[FakeFSStore pathToInode] allValues] first:^(NSNumber *pathInode) {
////            FFLog(@"Against pathInode %@", pathInode);
//            return [[pathInode stringValue] isEqualToString:statInode];
//        }] == nil ? YES : NO);
//    }];
//
//    NSArray * orphanedInodesUsingListComparisonsSorted = [orphanedInodesUsingListComparisons sortedArrayUsingDescriptors:@[highestToLowest]];
//    FFLog(@"First way %d", [orphanedInodesUsingListComparisons count]);

    
    NSSet *orphanedInodesFromSetLogicSet = [[NSSet setWithArray:[self.fakeFSStore getPathInodesAsNumbers]] difference:[NSSet setWithArray:[self.fakeFSStore getStatInodesAsNumbers]]];
//    NSArray *orphanedInodesFromSetLogic = [orphanedInodesFromSetLogicSet filter:^(NSNumber *orphanedInode) {
//        // return (BOOL)([FakeFSStore.inodeToStat valueForKey:[orphanedInode stringValue]] != nil ? YES : NO);
//        return (BOOL)([[FakeFSStore.pathToInode allValues] containsObject:orphanedInode] != nil ? YES : NO);
//    }];
    NSMutableArray *uniqueOrphanedInodesFromSetLogic = [NSMutableArray new];
    // Iterate over inodes that are not in both lists
    [orphanedInodesFromSetLogicSet each:^(NSNumber *orphanedInode) {
        if ([[FakeFSStore inodeToStat] valueForKey:[orphanedInode stringValue]] != nil) {
            // If inode is is inodeToStat.list then it is not in PathInodes
            // [self.fakeFSStore removeStatAndInodeForInode:orphanedInode];
            [uniqueOrphanedInodesFromSetLogic addObject:orphanedInode];
        }
    }];
    // uniqueOrphanedInodesFromSetLogic is empty becasue all the unique or orphaned inodes are the old ones in pathToInodes

//    FFLog(@"Second way %d", [uniqueOrphanedInodesFromSetLogic count]);
//    NSSortDescriptor *highestToLowest = [NSSortDescriptor sortDescriptorWithKey:@"self" ascending:NO];
//    NSArray * orphanedInodesFromSetLogicSorted = [uniqueOrphanedInodesFromSetLogic sortedArrayUsingDescriptors:@[highestToLowest]];
  
    // Instead of a for loop:
    // [FakeFSStore.inodeToStat removeObjectsForKeys:arrayOfInodesToRemove];
    


    return 0;
}

- (int)mount:(Mount *)mount {
    mount.rootFD = open([mount.source UTF8String], O_DIRECTORY);
    if (mount.rootFD < 0)
        return errno_map();

    [self rebuildDB: mount];
    return 0;
}
- (int)umount:(Mount *)mount {
    return 0;
}
- (int)statfs:(Mount *)mount stat:(struct statfsbuf *)stat {
    return 0;
}

- (FileDescriptor *)open:(Mount *)mount path:(NSString *)path flags:(int)flags mode:(int)mode currentTask:(Task *)currentTask {
    // 0666 is read and write permissions to everyone
    // S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH
    int realFlags = [FileSystem openFlagsRealFromFake:flags];
    int fd_no = openat(mount.rootFD, [[path fixPath] UTF8String], realFlags, 0666);

#ifdef BDEBUG
    char tmpBuf[MAX_PATH];
    int err = fcntl(fd_no, F_GETPATH, tmpBuf);
    FFLog(@"BEB File path for open: %s", tmpBuf);
    
    char tmpBufR[MAX_PATH];
    int err2 = fcntl(mount.rootFD, F_GETPATH, tmpBufR);
    FFLog(@"BEB Root path for open: %s", tmpBufR);
#endif
    
    if (fd_no < 0) {
        FileDescriptor *errFd = [FileDescriptor new];
        errFd->err = errno_map();
        FFLog(@"Error opening file descriptor - actual openat failed with: %d", fd_no);
        return errFd;
    }
    
    FileDescriptor *fd = [FileDescriptor new];
    // Be default the correct FileDescriptorOperations class is used in this case
    // fd.fdOps = [RFileDescriptorOperaitons new];
    fd->realFD = fd_no;
    fd->dir = NULL;

    NSNumber *inodeNumber = [self.fakeFSStore getInodeForPath:path];
    fd->fakeInode = [inodeNumber longValue];
    if (flags & O_CREAT_) {
        struct ish_stat ishstat;
        // Adding inode here?
        ishstat.mode = mode | S_IFREG;
        ishstat.uid = currentTask->euid;
        ishstat.gid = currentTask->egid;
        ishstat.rdev = 0;
        
        
        // If there was not inode found then create one and set the stat and path
        // by inserting into the stat and paths tables
        // The inodes are just ints and don't mean anything other than that they are
        // unique (unless hardlinked)
        if (fd->fakeInode == 0) {
            // TODO: Create a unique inode number and insert path and stat
            inodeNumber = [self.fakeFSStore getNewInodeNumber];
            [self.fakeFSStore updateInodeForPath:path inode:inodeNumber];
            [self.fakeFSStore updateStatDataForInode:inodeNumber stat:[NSData dataWithBytes:&ishstat length:16]];
            FFLog(@"BEB Setup path: %@ inode: %@", path, inodeNumber);
//            [self createPathAndStatForInode:mount path:path stat:&ishstat];
            fd->fakeInode = [inodeNumber longValue];
        }
    }
    
    if (fd->fakeInode == 0) {
        // metadata for this file is missing
        // TODO unlink the real file
        [fd close];
        fd->err = _ENOENT;
        FFLog(@"Error opening file descriptor - there is no inode for this path: %@", path);
        return fd;
    }
    
    return fd;
}

// These return _EPERM if not present
- (int)link:(Mount *)mount src:(NSString *)src dst:(NSString *)dst {
    return 0;
}
- (int)unlink:(Mount *)mount path:(NSString *)path {
    return 0;
}
- (int)rmdir:(Mount *)mount path:(NSString *)path {
    return 0;
}
- (int)rename:(Mount *)mount src:(NSString *)src dst:(NSString *)dst {
    return 0;
}
- (int)symlink:(Mount *)mount target:(NSString *)target link:(NSString *)link {
    return 0;
}
- (int)mknod:(Mount *)mount path:(NSString *)path mode:(mode_t_)mode dev:(dev_t_)dev {
    return 0;
}
- (int)mkdir:(Mount *)mount path:(NSString *)path mode:(mode_t_)mode {
    return 0;
}

// There's a close function in both the fs and fd to handle device files
// where for instance there's a real_fd needed for getpath and also a tty
// reference and both need to be released when the fd is closed.
// If they are the same function it will only be called once.
- (int)close:(FileDescriptor *)fd {
    return 0;
}

- (int)stat:(Mount *)mount path:(NSString *)path stat:(struct statbuf *)stat {
    // Lookup stat by path
    NSData *ishStatData = [self.fakeFSStore getStatDataForPath:path];
    const struct ish_stat *ishstat = ishStatData.bytes;
    // Get inode by path
    NSNumber *inodeNumber = [self.fakeFSStore getInodeForPath:path];
    ino_t inode = [inodeNumber longValue];

    int err = 0;
    struct stat tmpStat;
    if (fstatat(mount.rootFD, [[path fixPath] UTF8String], &tmpStat, AT_SYMLINK_NOFOLLOW) < 0)
        err = errno_map();
    [self copyStat:stat real:&tmpStat];
    
    if (err < 0)
        return err;
    
    // And update our stat struct with the values we care about from the DB's stat
    stat->inode = inode;
    stat->mode = ishstat->mode;
    stat->uid = ishstat->uid;
    stat->gid = ishstat->gid;
    stat->rdev = ishstat->rdev;
    return 0;
}


- (int)fstat:(FileDescriptor *)fd stat:(struct statbuf*)stat {
    // Get the real fstat
    struct stat real;
    int err = fstat(fd->realFD, &real);
    
    if (err < 0)
        err = errno_map();
    
    // Move the values into our version of the stat struct
    [self copyStat:stat real:&real];
    
    // Query for the stat in the DB by the inode number
    NSNumber *inodeNumber = [NSNumber numberWithLong:fd->fakeInode];
    NSData *ishStatData = [self.fakeFSStore getStatDataForInode:inodeNumber];
    if (!ishStatData) {
        // NSString *statStr = [[FakeFSStore inodeToStat] valueForKey:[inodeNumber stringValue]];
        FFLog(@"BEB Missing stat for inode: %@", inodeNumber);
        die("Unable to find stat for inode");
    }
    const struct ish_stat *ishstat = [ishStatData bytes];
    
    // And update our stat struct with the values we care about from the DB's stat
    stat->inode = fd->fakeInode;
    stat->mode = ishstat->mode;
    stat->uid = ishstat->uid;
    stat->gid = ishstat->gid;
    stat->rdev = ishstat->rdev;
    return 0;
}

- (int)setattr:(Mount *)mount path:(NSString *)path attr:(struct attr)attr {
    return 0;
}
- (int)fsetattr:(FileDescriptor *)fd attr:(struct attr)attr {
    return 0;
}
- (int)utime:(Mount *)mount path:(NSString *)path atime:(struct timespec)atime mtime:(struct timespec)mtime {
    return 0;
}
// Returns the path of the file descriptor null terminated buf must be at least MAX_PATH+1
- (int)getpath:(FileDescriptor *)fd buf:(NSMutableString *)buf {
    char tmpBuf[MAX_PATH];
    // TODO How does this work
    int err = fcntl(fd->realFD, F_GETPATH, tmpBuf);
    [buf setString:[NSString stringWithCString:tmpBuf encoding:NSUTF8StringEncoding]];
    if (err < 0)
        return err;
    if (![fd.mount.source isEqualToString:@"/"] || [buf isEqualToString:@"/"]) {
        // Then remove fd.mount.source number of characters from the front of buf
        NSString *bufWithoutMountSource = [buf substringFromIndex:[fd.mount.source length]];
        [buf setString:bufWithoutMountSource];
    }
    
    return 0;
}

- (int)flock:(FileDescriptor *)fd operation:(int)operation {
    return 0;
}

// If present called when all references to an inode_data for this
// filesystem go away.
- (void)inode_orphaned:(Mount *)mount inode:(ino_t)inode {
    return;
}


//#if __APPLE__
//#define TIMESPEC(x) st_##x##timespec
//#elif __linux__
//#define TIMESPEC(x) st_##x##tim
//#endif
- (void) copyStat:(struct statbuf *)fake real:(struct stat*)real {
    fake->dev = dev_fake_from_real(real->st_dev);
    fake->inode = real->st_ino;
    fake->mode = real->st_mode;
    fake->nlink = real->st_nlink;
    fake->uid = real->st_uid;
    fake->gid = real->st_gid;
    fake->rdev = dev_fake_from_real(real->st_rdev);
    fake->size = real->st_size;
    fake->blksize = real->st_blksize;
    fake->blocks = real->st_blocks;
    fake->atime = real->st_atime; // The real is a long being jammed into the fake int variable
    fake->mtime = real->st_mtime; // same
    fake->ctime = real->st_ctime; // same
    fake->atime_nsec = real->st_atimespec.tv_nsec;
    fake->mtime_nsec = real->st_mtimespec.tv_nsec;
    fake->ctime_nsec = real->st_ctimespec.tv_nsec;
//    fake->atime_nsec = real->TIMESPEC(a).tv_nsec; // same
//    fake->mtime_nsec = real->TIMESPEC(m).tv_nsec; // same
//    fake->ctime_nsec = real->TIMESPEC(c).tv_nsec; // same
}
//#undef TIMESPEC


- (ssize_t)readlink:(Mount *)mount path:(NSString *)path buf:(char *)buf bufsize:(size_t)bufsize {
     // Query the db on the table that links path -> inode and stat columns
     // Just query for the stat column though
     NSData *ishStatData = [self.fakeFSStore getStatDataForPath:path];
     const struct ish_stat *ishstat = ishStatData.bytes;
     if (!ishStatData) {
         return _ENOENT;
     }
     
     // We queried the DB for the stat just for this check:
     if (!S_ISLNK(ishstat->mode)) {
         return _EINVAL;
     }

     // Do a real readlink to get the actual file contents which is where the symlink data is
     ssize_t sizeOrErr = readlinkat(mount.rootFD, [[path fixPath] UTF8String], buf, bufsize);

    // If the path was invalid then this must be a path relative to the file descriptor of the mount. readlink is really just reading the contents of the file. A symlink's data is actually the location it is pointing to. Just read the location instead of calling readlink
    if (sizeOrErr == _EINVAL) {
        int fd = openat(mount.rootFD, [[path fixPath] UTF8String], O_RDONLY);
        if (fd < 0)
            return errno_map();
        sizeOrErr = read(fd, buf, bufsize);
        close(fd);
        if (sizeOrErr < 0)
            sizeOrErr = errno_map();
    }
    return sizeOrErr;
 }


@end

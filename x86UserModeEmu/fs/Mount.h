//
//  Mount.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//
#import <Foundation/Foundation.h>
#include <sqlite3.h>
#include <stdatomic.h>

#import "FileSystem.h"

#ifndef MOUNT_H
#define MOUNT_H

@class Mount;
typedef struct {
    sqlite3_stmt *begin;
    sqlite3_stmt *commit;
    sqlite3_stmt *rollback;
    sqlite3_stmt *path_get_inode;
    sqlite3_stmt *path_read_stat;
    sqlite3_stmt *path_create_stat;
    sqlite3_stmt *path_create_path;
    sqlite3_stmt *inode_read_stat;
    sqlite3_stmt *inode_write_stat;
    sqlite3_stmt *path_link;
    sqlite3_stmt *path_unlink;
    sqlite3_stmt *path_rename;
    sqlite3_stmt *path_from_inode;
    sqlite3_stmt *try_cleanup_inode;
} sqlite_stmts;

@class FileSystem;

@interface Mount : NSObject {
    @public sqlite_stmts stmt;
    @public sqlite3 *db;
    @public lock_t lock;
}

// Debug
// @property (nonatomic, strong) NSString *path;

@property (nonatomic, assign) NSString *point;
@property (nonatomic, assign) NSString *source;
@property (nonatomic, assign) int flags;
@property (nonatomic, assign) atomic_uint refCount;
@property (nonatomic, assign) void *data;

@property (nonatomic, assign) int rootFD;

@property (nonatomic, strong) FileSystem *fs;
//@property (nonatomic, assign) int refcount;
//- (void)genericOpen: (NSString *)path, int flags, int mode;
- (id)initWithFS:(FileSystem *)fs;
- (void)releaseMount;
- (int)remove;

- (void)incrementRefCount;
- (void)decrementRefCount;

@end

#endif

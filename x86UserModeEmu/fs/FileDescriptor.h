//
//  Fd.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//
#import <Foundation/Foundation.h>
#include <dirent.h>
#include <stdatomic.h>
// #import "Mount.h"
#import "misc.h"
#import "FileDescriptorOperations.h"

#define NAME_MAX 255

struct dir_entry {
    qword_t inode;
    char name[NAME_MAX + 1];
};

#define LSEEK_SET 0
#define LSEEK_CUR 1
#define LSEEK_END 2

typedef sdword_t fd_t;

@class Mount;

@class FileDescriptor;

@interface FileDescriptor : NSObject
@property (nonatomic, strong) id<FileDescriptorOperations> fdOps;
@property (nonatomic, assign) bool closeOnExec;

@property (nonatomic, assign) ino_t fakeInode;

@property (nonatomic, assign) int err;
@property (nonatomic, assign) int realFD;
@property (nonatomic, assign) DIR *dir; // a pointer to the directory stream

@property (nonatomic, assign) atomic_uint refCount;
@property (nonatomic, assign) int flags;
@property (nonatomic, assign) int type;
@property (nonatomic, assign) int offset;

// Was weak??
@property (nonatomic, strong) Mount *mount;
@property (nonatomic, strong) NSString *originalPath;

//@property (nonatomic, assign) CPU *cpu;
//- (void)genericOpen: (NSString *)path, int flags, int mode;
- (id)init;
- (int)close;
- (void)incrementRefCount;
- (void)decrementRefCount;
@end


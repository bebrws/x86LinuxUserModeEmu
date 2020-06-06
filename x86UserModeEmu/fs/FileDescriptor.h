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

#define FD_ALLOWED_FLAGS (O_APPEND_ | O_NONBLOCK_)

@class Mount;

@class FileDescriptor;

@interface FileDescriptor : NSObject {
    @public bool closeOnExec;
    @public ino_t fakeInode;
    @public int err;
    @public int realFD;
    @public DIR *dir; // a pointer to the directory stream
    @public int flags;
    @public int type;
    @public int offset;
}
@property (nonatomic, strong) id<FileDescriptorOperations> fdOps;

// Was weak??
@property (nonatomic, strong) Mount *mount;
@property (nonatomic, strong) NSString *originalPath;

//@property (nonatomic, assign) CPU *cpu;
//- (void)genericOpen: (NSString *)path, int flags, int mode;
- (int)setFlags:(dword_t)flags;
- (id)init;
- (int)close;
- (void)incrementRefCount;
- (void)decrementRefCount;
@end


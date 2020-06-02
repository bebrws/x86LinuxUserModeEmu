//
//  FRFileSystemOperations.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/18/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

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
#import "FileSystemOperations.h"
#import "Task.h"
#import "FakeFSStore.h"

@class Task;
@class FakeFSStore;

@interface FRFileSystemOperations : NSObject <FileSystemOperations> {
    @public int magic;
}

@property (nonatomic, strong) FakeFSStore *fakeFSStore;
@property (nonatomic, strong) Task *currentTask;

@end

//
//  MappedMemory.h
//  x86UserModeEmu
//
//  Created by bradbarrows on 2/15/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <stdatomic.h>
#include <unistd.h>
#include "misc.h"

#ifndef MappedMemory_h
#define MappedMemory_h

@class FileDescriptor;


@class MappedMemory;

// In ish MappedMemory was the struct data
@interface MappedMemory : NSObject


// For debug

@property (nonatomic, assign) page_t pageStart;
@property (nonatomic, assign) page_t numPages;
@property (nonatomic, strong) NSString *debugString;

// end debug

@property (nonatomic, strong) FileDescriptor *fd;

// This is a pointer to the memory that is being mapped over page tables
// This is emulating a pointer to what would be physical memory
@property (nonatomic, assign) char *data;
// the size of the memory being mapped
@property (nonatomic, assign) size_t sizeMappedData;
@property (nonatomic, assign) bool isVdso;

// for display in /proc/pid/maps
@property (nonatomic, assign) size_t fileOffset;
@property (nonatomic, assign) NSString *name;

// debug
@property (nonatomic, assign) int pid;
@property (nonatomic, assign) addr_t destVAddress;

@end



#endif /* MappedMemory_h */

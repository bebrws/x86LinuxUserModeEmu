//
//  PageTableEntry.h
//  x86UserModeEmu
//
//  Created by bradbarrows on 2/15/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#ifndef PageTableEntry_h
#define PageTableEntry_h

#import <Foundation/Foundation.h>
#include <stddef.h>
#include "misc.h"
#include "MappedMemory.h"

// In ish this was pt_entry

@class FileDescriptor;
@class PageTableEntry;

@interface PageTableEntry : NSObject
//@interface PageTableEntry : NSObject {
//    bool isInUse;
//}
@property (nonatomic, assign) addr_t pageIndex;
@property (nonatomic, assign) bool isInUse;
// mappedMemory is an object that represents that memory that was mapped over multiple page tables
// including this one
// In ish mappedMemory was of type data and named data
@property (nonatomic, strong) MappedMemory *mappedMemory;
// flags are describing the page table entry like the direction in which memory grows
// which is bit mask 1<<3 or 8
@property (nonatomic, assign) uint32_t flags;
// this is an offset into self.mappedMemory.memory
@property (nonatomic, assign) size_t offsetIntoMappedMemory;

- (id)init;
- (id)initWithPageIndex:(page_t)pageIndex;

- (void)mapMemory:(MappedMemory *)mappedMemory flags:(unsigned int)flags offsetIntoMappedMemory:(size_t)offsetIntoMappedMemory;

@end


#endif /* PageTableEntry_h */

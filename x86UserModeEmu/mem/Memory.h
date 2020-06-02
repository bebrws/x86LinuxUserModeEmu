#import <Foundation/Foundation.h>
#import <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#import "misc.h"


#ifndef MEMORY_H
#define MEMORY_H

// Used by mmap
#define MEM_READ 0
#define MEM_WRITE 1

#define MMAP_SHARED 0x1
#define MMAP_PRIVATE 0x2
#define MMAP_FIXED 0x10
#define MMAP_ANONYMOUS 0x20


#define PAGE_BITS 12
#undef PAGE_SIZE // defined in system headers somewhere
#define PAGE_SIZE (1 << PAGE_BITS)
#define PAGE(addr) ((addr) >> PAGE_BITS)
#define PGOFFSET(addr) ((addr) & (PAGE_SIZE - 1))
typedef dword_t pages_t;
#define PAGE_ROUND_UP(bytes) (((bytes - 1) / PAGE_SIZE) + 1)

#define BYTES_ROUND_DOWN(bytes) (PAGE(bytes) << PAGE_BITS)
#define BYTES_ROUND_UP(bytes) (PAGE_ROUND_UP(bytes) << PAGE_BITS)


// This was MEM_PAGES
#define NUM_PAGE_TABLE_ENTRIES (1 << 20) // at least on 32-bit
#define PGDIR_SIZE (1 << 10)

// page flags
// P_READ and P_EXEC are ignored for now
#define P_READ (1 << 0)
#define P_WRITE (1 << 1)
#undef P_EXEC // defined in sys/proc.h on darwin
#define P_EXEC (1 << 2)
#define P_RWX (P_READ | P_WRITE | P_EXEC)
#define P_GROWSDOWN (1 << 3)
#define P_COW (1 << 4)
#define P_WRITABLE(flags) (flags & P_WRITE && !(flags & P_COW))
#define P_COMPILED (1 << 5)

// mapping was created with pt_map_nothing
#define P_ANONYMOUS (1 << 6)
// mapping was created with MAP_SHARED, should not CoW
#define P_SHARED (1 << 7)

#define PAGES_FROM_ADDRESS(addr) (addr >> 12)
// Represents the struct in emu/memory.h mem

@class PageTableEntry;
@class Task;

@class Memory;

// Represent the mem struct from memory.h
//`
@interface Memory : NSObject {
    @public pthread_rwlock_t lock;
}

// changes is used to see if memory changed over a period of time like during an interrupt
@property (nonatomic, assign) int changesToMemory;

//@property (nonatomic, assign) NSInteger pgDirsUsed;

// pages is an attempt to replace the page dir collection AND the page table collection
// by using just one array
@property (nonatomic, strong) NSMutableArray *pages;

@property (nonatomic, strong) Task *task;

// @property (nonatomic, strong) NSLock *lock;

// Todo maybe add an array of page table entries here to for faster iteration?

//- (void)mem_init(struct mem *mem);
//- (void)mem_destroy(struct mem *mem);
- (PageTableEntry *)getPageTableEntry:(page_t)page;
//- (PageTableEntry *)getPageTableEntry:(page_t)page findNew:(bool)findNew;
    //static struct pt_entry *mem_pt_new(struct mem *mem, page_t page);
    //struct pt_entry *mem_pt(struct mem *mem, page_t page);

- (PageTableEntry *)nextNextPageTableEnry:(page_t)page;
    //void mem_next_page(struct mem *mem, page_t *page);

- (PageTableEntry *)findNextPageTableEntryHole:(pages_t)size;
    //page_t pt_find_hole(struct mem *mem, pages_t size);

//static void mem_pt_del(struct mem *mem, page_t page);

- (bool)isPageTableEntryHole:(page_t)start size:(pages_t)size;
    //bool pt_is_hole(struct mem *mem, page_t start, pages_t pages);

- (int)mapMemory:(page_t)pageStart numPages:(pages_t)numPages memory:(const char *)memory offset:(size_t)offset flags:(unsigned)flags;
- (int)mapMemory:(page_t)pageStart numPages:(pages_t)numPages memory:(const char *)memory offset:(size_t)offset flags:(unsigned)flags debugString:(NSString *)debugString;
    //int pt_map(struct mem *mem, page_t start, pages_t pages, void *memory, size_t offset, unsigned flags);

- (void)unmapMemory:(page_t)pageStart numPages:(pages_t)numPages;
    //int pt_unmap(struct mem *mem, page_t start, pages_t pages);

- (void *)getPointer:(addr_t)addr type:(int)type;

- (int)mapEmptyMemory:(page_t)pageStart numPages:(pages_t)numPages flags:(unsigned)flags;
- (int)mapEmptyMemory:(page_t)pageStart numPages:(pages_t)numPages flags:(unsigned)flags debugString:(NSString *)debugString;

- (void *)copyPageTableEntryOnWriteTo:(Memory *)dest pageStart:(page_t)pageStart pageCount:(page_t)pageCount;

//int pt_set_flags(struct mem *mem, page_t start, pages_t pages, int flags);
//int pt_copy_on_write(struct mem *src, struct mem *dst, page_t start, page_t pages) {
//__attribute__((constructor)) static void get_real_page_size();
@end

#endif

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>

#import "Memory.h"
#import "PageTableEntry.h"
#import "MappedMemory.h"
#import "FileDescriptor.h"
#import "debug.h"
#import "misc.h"
#import "errno.h"
#import "Globals.h"
#import "FLLog.h"
#import "Task.h"

#import "vdso.h"

#import "log.h"

#include <sys/mman.h>

@implementation Memory

- (int)setPageTableEntryFlags:(page_t)start len:(pages_t)len flags:(uint32_t)flags {
    for(int page = start; page <= start + len; page++) {
        PageTableEntry *ptentry = [self.pages objectAtIndex:page];
        if (!ptentry.isInUse) {
            return _ENOMEM;
        }
        
        uint32_t oldFlags = ptentry.flags;
        ptentry.flags = flags;
        
        // Check if the level of protections is increasing:
        if ((flags & ~oldFlags) & (P_READ|P_WRITE)) {
            // If so then make the actual mprotect syscall to give the actual protections specified
            void *data = (char *) ptentry.mappedMemory.data + ptentry.mappedMemory.fileOffset;
            // force to be page aligned
            data = (void *) ((uintptr_t) data & ~(get_real_page_size() - 1));
            
            int actualProtFlags = PROT_READ;
            if (flags & P_WRITE) {
                actualProtFlags |= PROT_WRITE;
            }
            if (mprotect(data, get_real_page_size(), actualProtFlags) < 0) {
                return errno_map();
            }
        }
    }
    self.changesToMemory++; // mem_changed(mem);
    return 0;
}

- (PageTableEntry *)findNextPageTableEntryHole:(pages_t)size {
    bool inHole = false;
    pages_t pagesNeededForHole = 0;
    
    /*
    for(int page = 0xf7ffd; page >= 0x40000; page--) { PageTableEntry *ptentry = [self.pages objectAtIndex:page]; if (ptentry.isInUse) { printf("Page 0x%x is mapped\n", page); } }
     */
    
    // TODO: IMPORTANT Why these magic numbers? Why is this a valid virtual address range?
    for(int page = 0xf7ffd; page >= 0x40000; page--) {
        PageTableEntry *ptentry = [self.pages objectAtIndex:page];
        
        if (ptentry.isInUse) {
            inHole = false;
            pagesNeededForHole = size;
        } else {
            if (!inHole) {
                // pagesNeededForHole = size - 1 because this first empty page counts as one
                pagesNeededForHole = size - 1;
                inHole = true;
            } else {
                pagesNeededForHole--;
            }
        }
        
        if (pagesNeededForHole == 0) {
            return ptentry; // should be 1015660
        }
         
         
    }
    return nil;
}

//- (PageTableEntry *)getNextInUsePageTableEnry:(page_t)page {
//    return [self getPageTableEntry:(page+1) findNew:false];
//}
//
//- (PageTableEntry *)getPageTableEntry:(page_t)page {
//    return [self getPageTableEntry:page findNew:false];
//}
    
- (PageTableEntry *)getPageTableEntry:(page_t)page { // findNew:(bool)findNew {
    if (page > NUM_PAGE_TABLE_ENTRIES) {
        die("attempted to get a page table entry outside of the pages collection size");
    }
    
    PageTableEntry *ptentry = [self.pages objectAtIndex:page];
  
    return ptentry;
//    if (findNew) {
//        if (ptentry.isInUse) {
//            // TODO Throw exception?
//            die("Attempting to configure a new page table entry when it is already in use");
//        } else {
//            return ptentry;
//        }
//    } else {
//        return ptentry;
////        if (ptentry.isInUse) {
////            return ptentry;
////        } else {
////            return nil;
////        }
//    }
}

- (bool)isPageTableEntryHole:(page_t)start size:(pages_t)size {
    // TODO: Should this be >= ?
    if (start > NUM_PAGE_TABLE_ENTRIES || (start + size - 1) > NUM_PAGE_TABLE_ENTRIES) {
        die("attempted to get a page table entry outside of the pages collection size");
    }
    
    for(int page = start; page < (start+size); page++) {
        PageTableEntry *ptentry = [self.pages objectAtIndex:page];
        if (ptentry.isInUse) {
            return false;
        }
    }
    
    return true;
}

//- (int)mapMemory:(page_t)start memory:(void *)memory memorySize:(size_t)memorySize addr:(addr_t)addr offset:(size_t)offset flags:(unsigned)flags {
//    // PAGE_ROUND_UP will get the total number of pages for the bytes passed as an argument
//    // PGOFFSET(addr) will get the number of bytes the address is into a page (just ANDnig by the first 12 bits)
//    // This + filesize will / PAGE_SIZE is basically the number of pages needed (but this number is rounded up)
//    size_t size = PAGE_ROUND_UP(memorySize + PGOFFSET(addr));
//    
//    return [self mapMemory:start size:size memory:memory offset:offset flags:flags];
//}
- (void)unmapMemory:(page_t)page {
    [self unmapMemory:page numPages:1];
}

- (void)unmapMemory:(page_t)pageStart numPages:(pages_t)numPages {
    for (page_t page = pageStart; page < pageStart + numPages; page++) {
        //PageTableEntry *ptentry = [self.pages objectAtIndex:page];
        PageTableEntry *ptentry = [self getPageTableEntry:page];
        if (ptentry.isInUse) {
            [ptentry.mappedMemory decrementRefCount];
            
            // If there arent anymore pageTableEntries using this mappedMemory then unmap/free it
            if (ptentry.mappedMemory.refCount == 0) {
                // vdso wasn't allocated with mmap, it's just in our data segment
                if (ptentry.mappedMemory.isVdso) {
                    // TODO This could be in dealloc for MappedMemory
                    // This is where the memory is actually freed
                    int err = munmap(ptentry.mappedMemory.data, ptentry.mappedMemory.sizeMappedData);
                    if (err != 0)
                        // TODO Make variable list argument die
                        die("munmap(%p, %lu) failed: %s", ptentry.mappedMemory.data, ptentry.mappedMemory.sizeMappedData, strerror(errno));
                }
                if (ptentry.mappedMemory.fd) {
                    [ptentry.mappedMemory.fd close];
                }
                // TODO Verify this is happening:
                // free(data);
                // By logging on
                // dealloc
                ptentry.mappedMemory = nil;
            }
        }
    }
}


- (int)mapEmptyMemory:(page_t)pageStart numPages:(pages_t)numPages flags:(unsigned)flags {
    return [self mapEmptyMemory:pageStart numPages:numPages flags:flags debugString:@"map empty mem"];
}

- (int)mapEmptyMemory:(page_t)pageStart numPages:(pages_t)numPages flags:(unsigned)flags debugString:(NSString *)debugString {
    // MAP_ANONYMOUS will zero out memory allocated
    // https://stackoverflow.com/questions/34042915/what-is-the-purpose-of-map-anonymous-flag-in-mmap-system-call
    void *emptyMemory = mmap(NULL, numPages * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    return [self mapMemory:pageStart numPages:numPages memory:emptyMemory offset:0 flags:flags debugString:debugString];
}

//- (int)mapMemory:(page_t)pageStart numPages:(pages_t)numPages memory:(const char *)memory offset:(size_t)offset flags:(unsigned)flags {
//
//    return [self mapMemory:pageStart numPages:numPages memory:memory offset:offset flags:flags debugString:@""];
//}

- (int)mapMemory:(page_t)pageStart numPages:(pages_t)numPages memory:(const char *)memory offset:(size_t)offset flags:(unsigned)flags debugString:(NSString *)debugString {
    if (memory == MAP_FAILED)
        return errno_map();
    
    assert((addr_t)memory % 4096 == 0 || memory == vdso_data);
    
    MappedMemory *mappedMemory = [[MappedMemory alloc] init];
    
    // For Debug TODO: Remove
    mappedMemory.pageStart = pageStart;
    mappedMemory.numPages = numPages;
    mappedMemory.debugString = debugString;
    
    mappedMemory.data = memory;
    mappedMemory.sizeMappedData = numPages * PAGE_SIZE + offset;
    // TODO:
    // mm.pid = currentTast.pid;
    mappedMemory.destVAddress = pageStart << PAGE_BITS;
        
    for (page_t page = pageStart; page < pageStart + numPages; page++) {
        //PageTableEntry *ptentry = [self.pages objectAtIndex:page];
        PageTableEntry *curPTEntry = [self getPageTableEntry:page];
        
        // TODO I bet I can remove this
        if (curPTEntry.isInUse) {
            FLLog(@"Mapping memory to page table entries and ran into in use page table entry");
            [self unmapMemory:page];
        }
        
        [mappedMemory incrementRefCount];
        
        curPTEntry.isInUse = true;
        curPTEntry.mappedMemory = mappedMemory;
        // This offset is going to let us know where to start indexing into the mappedMemory buffer
        // by giving us the pageIndexInMemoryMapPages * pageSize + theOriginalOffsetIntoTheMemoryWeAreMapping
        curPTEntry.offsetIntoMappedMemory = ((page - pageStart) << PAGE_BITS) + offset;
        curPTEntry.flags = flags;
    }
    
    // changes is used to see if memory changed over a period of time like during an interrupt
    self.changesToMemory++;
    return 0;
}

- (void *)getPointer:(addr_t)addr type:(int)type {
    page_t page = PAGE(addr);
    
    if (page >= NUM_PAGE_TABLE_ENTRIES) {
        die("Attempting to get pointer for page outside of the page table\n");
    }
    PageTableEntry *entry = [self getPageTableEntry:page];

    // This (a pagefault) should only happen when the stack needs to grow
    if (!entry.isInUse) {
        // page does not exist
        // look to see if the next VM region is willing to grow down
        // Do this by incrementing the page entry index until we hit a page that
        // is being used and then check if it has the GROWSDOWN flag AKA is stack
        
        // Go up and up through all the pages until we find one that is in use
        page_t curPageNumber = page + 1;
        if (curPageNumber >= NUM_PAGE_TABLE_ENTRIES) {
            return NULL;
        }
        PageTableEntry *curPage = [self getPageTableEntry:curPageNumber];
        
        while(curPageNumber < NUM_PAGE_TABLE_ENTRIES && !curPage.isInUse) {
            curPageNumber += 1;
            curPage = [self getPageTableEntry:curPageNumber];
        }
        
        // If we made it all the way to the top of the list without finding an in use page table entry
        // then return null
        if (curPageNumber >= NUM_PAGE_TABLE_ENTRIES) {
            // die("Process reached total number of page table entries");
            return NULL;
        }
        
        // If the next page up that was taken wasnt marked GROWSDOWN then return NULL
        if (!(curPage.flags & P_GROWSDOWN)) {
            // TODO Remove and let the os handle?
            // die("Process stack faulted by using a vaddress that lead to an unallocated page table entry and the next entry does not grow down");
            return NULL;
        }
        
        // If we reached this point then the next page above the one we tried to access
        // and page faulted on is marked as P_GROWSDOWN
        // So then we are going to map the page that was page faulted on as empty
        
        // Changing memory maps must be done with the write lock. But this is
        // called with the read lock, e.g. by tlb_handle_miss.
        // This locking stuff is copy/pasted for all the code in this function
        // which changes memory maps.
        // TODO: factor the lock/unlock code here into a new function. Do this
        // next time you touch this function.
//        read_wrunlock(&self->lock);
//        write_wrlock(&self->lock);
        [self mapEmptyMemory:page numPages:1 flags:P_WRITE | P_GROWSDOWN debugString:@"map empty memory from ptr request with page fault"];
//        write_wrunlock(&self->lock);
//        read_wrlock(&self->lock);
    }
    
    if (entry != NULL && type == MEM_WRITE) {
        // if page is unwritable, well tough luck
        if (!(entry.flags & P_WRITE)) {
            die("Attempting to write to memory with allocated table entry but entry is missing write permissions");
            return NULL;
        }
        // if page is cow, ~~milk~~ copy it
        // copy on write means that if a write is attempted on the page
        // then instead of modifying the original memory buffer mapped by the page table entries a new memory buffer
        // should be created with a copy of the page's data
        //
        // https://en.wikipedia.org/wiki/Copy-on-write
        // Copy-on-write can be implemented efficiently using the page table by marking certain pages of memory
        // as read-only and keeping a count of the number of references to the page.
        // When data is written to these pages, the kernel intercepts the write attempt and allocates a new physical
        // page, initialized with the copy-on-write data, although the allocation can be skipped if there is only one
        // reference. The kernel then updates the page table with the new (writable) page, decrements the number of
        // references, and performs the write. The new allocation ensures that a change in the memory of one process
        // is not visible in another's.
        //
        //
        if (entry.flags & P_COW) {
            // data will point to the beginning of the mappedMemory for the page we langed on
            // in the group pages allocated for the memory mapping (VS just using entry.mappedMemory.data)
            // which would point to the beginning of the memory that was mapped over possibly numerous pages
            void *data = (char *) entry.mappedMemory.data + entry.offsetIntoMappedMemory;
            // copy this copy on write page into a new buffer
            void *copy = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
            memcpy(copy, data, PAGE_SIZE);

            // copy/paste from above
//            read_wrunlock(&self->lock);
//            write_wrlock(&self->lock);
            // Then map a copy of the copy on write page and turn off the copy on write flag
            [self mapMemory:page numPages:1 memory:copy offset:0 flags:entry.flags &~ P_COW debugString:@"mem mapped for COW"];
//            write_wrunlock(&self->lock);
//            read_wrlock(&self->lock);
        }
    }

    // TODO REMOVE this shouldnt ever happen
    if (!entry.isInUse) {
        // TODO Let os handle?
        die("General page fault occured. Virtual address provided uses an unallocated page table entry");
        return NULL;
    }
    
    // This is getting a pointer into the memory mapped by the page table entry
    // Adding the base of the mapped memory + the offset into that memory + the address offset
    // bits from the virtual address we are getting a pointer to in the first place
    // PGOFFSET is just masking these first 12 bits for the address offset
    
//    if (debugFl)
//    FFLog(@"Getting point  to %x  with   mappedMenory %x  +  offset  %x  +  addr offset  %x", addr, entry.mappedMemory.data, entry.offsetIntoMappedMemory, PGOFFSET(addr));
    
    return entry.mappedMemory.data + entry.offsetIntoMappedMemory + PGOFFSET(addr);
}


- (void *)setPageTableEntryFlagsFromPage:(page_t)pageStart pageCount:(page_t)pageCount flags:(int)flags {
//    int pt_set_flags(struct mem *mem, page_t start, pages_t pages, int flags) {
    
    for (page_t page = pageStart; page < pageStart + pageCount; pageStart++) {
        PageTableEntry *entry = [self getPageTableEntry:page];
        // If we try to copy a page that is not being used then return ENOMEM
        if (!entry.isInUse) {
            return _ENOMEM;
        }
    }
    
    // Looks like all pages are being used so go ahead with the copy
    for (page_t page = pageStart; page < pageStart + pageCount; pageStart++) {
        PageTableEntry *entry = [self getPageTableEntry:page];
        int old_flags = entry.flags;
        entry.flags = flags;
        // check if protection is increasing
        if ((flags & ~old_flags) & (P_READ|P_WRITE)) {
            void *data = (char *) entry.mappedMemory.data + entry.offsetIntoMappedMemory;
            
            // force to be page aligned
            // This is masking or ANDing by the inverse of the page size or the first 12 bits
            // dataAddress AND 0xfffffffffffff000 I believe
            // This ignores any address offset so the data buffer starts at the beginning of the page
            // mprotect requires page alignment
            // http://man7.org/linux/man-pages/man2/mprotect.2.html
            // TODO: Maybe just replace get_real_page_size() with PAGE_SIZE define
            data = (void *) ((uintptr_t) data & ~(get_real_page_size() - 1));
            
            int protectFlags = PROT_READ;
            if (flags & P_WRITE) protectFlags |= PROT_WRITE;
            
            if (mprotect(data, get_real_page_size(), protectFlags) < 0)
                return errno_map();
        }
    }
    self.changesToMemory++;
    return 0;
}
- (void *)copyPageTableEntryOnWriteTo:(Memory *)dest pageStart:(page_t)pageStart pageCount:(page_t)pageCount {
    //int pt_copy_on_write(struct mem *src, struct mem *dst, page_t start, page_t pages) {
    for (page_t curPage = pageStart; curPage < pageStart + pageCount; curPage++) {
        PageTableEntry *entry = [self getPageTableEntry:curPage];
        if (!entry.isInUse) {
            return NULL;
        }
        // Have to do this one at a time because we coult be copying over an entire tasks virtual memory
        [self unmapMemory:curPage numPages:1];

        // A shared page is one that multiple processes can have mapped and read and write from/to
        // Kind of the opposite of copy on write for write operations.
        // Check to see if this is a shared page and if not mark is as copy on write
        // Other wise we will just be creating a new page table entry that maps the same memory buffer
        // so reads and writes from different proccesses will effect the same physical memory
        if (!(entry.flags & P_SHARED))
            entry.flags |= P_COW;
        
        // TODO What does this do? It looks like it is never used
        entry.flags &= ~P_COMPILED;
        
        [entry.mappedMemory incrementRefCount];
        PageTableEntry *dstEntry = [dest getPageTableEntry:curPage];
        dstEntry.mappedMemory = entry.mappedMemory;
        dstEntry.offsetIntoMappedMemory = entry.offsetIntoMappedMemory;
        dstEntry.flags = entry.flags;
    }
    self.changesToMemory++;
    dest.changesToMemory++;
    return 0;
}

- (id)init {
    self = [super init];
    if (self) {
        self.pages = [NSMutableArray new];
        // TODO : Just make this < NUM_PAGE_TABLE_ENTRIES
        for(int pageIndex = 0; pageIndex <= NUM_PAGE_TABLE_ENTRIES; pageIndex++) {
            [self.pages addObject:[[PageTableEntry alloc] initWithPageIndex:pageIndex]];
        }
        
        self.changesToMemory = 0;
        
        lock_init(&self->lock);
    }
    return self;
}

-(NSString *)description {
    NSMutableString *ms = [@"\n" mutableCopy];
    
    for(PageTableEntry *pe in self.pages) {
        if (pe.mappedMemory.pageStart == pe.pageIndex && pe.mappedMemory) {
            [ms appendFormat:@"  MM:%@\n", pe.mappedMemory];
        }
    }
    return ms;
}

@end

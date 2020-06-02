#import "PageTableEntry.h"

@implementation PageTableEntry

- (id)init {
    self = [super init];
    if (self) {
        // self->isInUse = false;
        self.isInUse = false;
        self.pageIndex = 0;
    }
    return self;
}

- (id)initWithPageIndex:(page_t)pageIndex {
    self = [self init];
    if (self) {
        self.pageIndex = pageIndex;
    }
    return self;
}

- (void)mapMemory:(MappedMemory *)mappedMemory flags:(unsigned int)flags offsetIntoMappedMemory:(size_t)offsetIntoMappedMemory {
    self.mappedMemory = mappedMemory;
    self.flags = flags;
    self.offsetIntoMappedMemory = offsetIntoMappedMemory;
}



@end

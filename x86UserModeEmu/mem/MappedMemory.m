#import "MappedMemory.h"
#import "FileDescriptor.h"
#import "log.h"


@implementation MappedMemory

- (id)init {
    self = [super init];
    if (self) {
        
    }
    return self;
}

-(void)dealloc
{
    FFLog(@"In MappedMemory dealloc %@ destVA:0x%x size:0x%x dbg:%@", self.name, self.destVAddress, self.sizeMappedData, self.debugString);
    if (self.isVdso) {
        // TODO This could be in dealloc for MappedMemory
        // This is where the memory is actually freed
        int err = munmap(self.data, self.sizeMappedData);
        if (err != 0)
            // TODO Make variable list argument die
            die("munmap(%p, %lu) failed: %s", self.data, self.sizeMappedData, strerror(errno));
    }
    if (self.fd) {
        [self.fd close];
    }
}


-(NSString *)description {
    return [NSString stringWithFormat:@"dva:0x%x-0x%x size:0x%x pg:%d pgs:%d dbg:%@", self.destVAddress, self.destVAddress + self.sizeMappedData, self.sizeMappedData, self.pageStart, self.numPages, self.debugString];
}

@end

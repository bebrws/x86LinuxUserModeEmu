#import "MappedMemory.h"
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
    FFLog(@"In MappedMemory dealloc %@ destVA:0x%x size:0x%x rc:%d, dbg:%@", self.name, self.destVAddress, self.sizeMappedData, self.refCount, self.debugString);
}

- (void)incrementRefCount {
    self.refCount++;
}

- (void)decrementRefCount {
    self.refCount--;
}


-(NSString *)description {
    return [NSString stringWithFormat:@"dva:0x%x-0x%x size:0x%x pg:%d pgs:%d rc:%d, dbg:%@", self.destVAddress, self.destVAddress + self.sizeMappedData, self.sizeMappedData, self.pageStart, self.numPages, self.refCount, self.debugString];
}

@end

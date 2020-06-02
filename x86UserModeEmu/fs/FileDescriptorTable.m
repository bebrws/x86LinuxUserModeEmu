//
//  FileDescriptorTable.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/17/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import "FileDescriptorTable.h"
#import "FileDescriptor.h"

// https://www.kernel.org/doc/Documentation/filesystems/files.txt
// How linux manages files in the kernel - related to locking and threads
//
@implementation FileDescriptorTable

- (id)init {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    self.tbl = [NSMutableDictionary new];
    return self;
}

- (FileDescriptor *)getFD:(fd_t)f {
    NSString *key = [@(f) stringValue];
    FileDescriptor *fd = [self.tbl objectForKey:key];
    return fd;
}

- (void)setFD:(fd_t)f fd:(FileDescriptor *)fd {
    NSString *key = [@(f) stringValue];
    [self.tbl setValue:fd forKey:key];
}

- (void)closeCloExecFDs {
    for (NSString *fStrKey in self.tbl) {
        FileDescriptor *fd = [self.tbl objectForKey:fStrKey];
        if (fd.closeOnExec) {
            [fd close];
            [self.tbl removeObjectForKey:fStrKey];
        }
    }
}

-(NSString *)description {
    NSMutableString *ms = [@"" mutableCopy];
    for (NSString *fdkey in self.tbl) {
        [ms appendFormat:@"Fd:%@ - %@ ", fdkey, self.tbl[fdkey]];
    }
    return ms;
}

@end

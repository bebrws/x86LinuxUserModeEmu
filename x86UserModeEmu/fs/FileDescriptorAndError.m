//
//  FD.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <stddef.h>
#import "FileDescriptorAndError.h"
#import "FileDescriptor.h"

@implementation FileDescriptorAndError
- (id)init {
    self = [super init];
    if (!self) {
        return nil;
    }
    return self;
}

- (id)initWithFD:(FileDescriptor *)fileDescriptor {
    self = [self init];
    
    self.fileDescriptor = fileDescriptor;
    self.err = 0;
    return self;
}

- (id)initWithError:(int)err {
    self = [self init];
    
    self.fileDescriptor = nil;
    self.err = err;
    return self;
}
@end


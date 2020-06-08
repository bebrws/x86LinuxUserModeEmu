//
//  Mount.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <stddef.h>
#include "Mount.h"
#import "MountLookup.h"
#import "Globals.h"
#import "FileSystem.h"
#import "errno.h"

@implementation Mount

-(NSString *)description {
    return [NSString stringWithFormat:@"rootFD:%d flgs:%d point:%@ source:%@", self.rootFD, self.flags, self.point, self.source];
}

- (id)initWithFS:(FileSystem *)fs {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    self.fs = fs;
    
    self.data = NULL;
    self.rootFD = 0;
    
    lock_init(&self->lock);
    
    return self;
}

- (int)remove {
    return [self.fs umount:self];
}

- (void)releaseMount {
    
}

@end



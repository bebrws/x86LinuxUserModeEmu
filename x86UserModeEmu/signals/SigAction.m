//
//  SigAction.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/29/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import "SigAction.h"

@implementation SigAction
- (id)init {
    self = [super init];
    if (self) {
        
    }
    return self;
}


-(NSString *)description {
    switch (self->handler) {
        case SIG_DFL_: {
            return @"DFL";
            break;
        }
        case SIG_IGN_: {
            return @"IGN";
            break;
        }
        case SIG_ERR_: {
            return @"ERR";
            break;
        }
        default: {
            return [NSString stringWithFormat:@"0x%x", self->handler];
            break;
        }
        
    }
}

@end

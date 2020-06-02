//
//  SigSet.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 4/2/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import "SigSet.h"
#import "Task.h"
#import "misc.h"
#import "NSString+BinaryRepresentation.h"

@implementation SigSet
- (id)init {
    self = [super init];
    if (self) {
        self->mask = 0;
    }
    return self;
}

+ (sigset_t_) maskForSignal:(int)sig {
    assert(sig >= 1 && sig < NUM_SIGS);
    return 1l << (sig - 1);
}

- (bool) empty {
    return self->mask;
}

- (bool) has:(int)sig {
    return !!(self->mask & sig_mask(sig));
}
- (void) del:(int)sig {
    self->mask &= ~sig_mask(sig);
}
- (void) add:(int)sig {
    self->mask |= sig_mask(sig);
}

- (void) clear {
    self->mask = 0;
}

- (id)initWithSigSet:(sigset_t_)mask {
    self = [self init];
    if (self) {
        self->mask = mask;
    }
    return self;
}

- (sigset_t_)getMask {
    return self->mask;
}

-(NSString *)description {
    return [NSString stringWithFormat:@"%@", [NSString binaryStringRepresentationOfInt:self->mask]];
}

@end

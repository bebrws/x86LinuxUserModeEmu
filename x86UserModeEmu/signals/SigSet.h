//
//  SigSet.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 4/2/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "misc.h"

// https://www.gnu.org/software/libc/manual/html_node/Signal-Sets.html
// A data structure called a signal set to specify what signals are affected
// Internally represented here as a bitmask

typedef uint64_t sigset_t_;

static inline sigset_t_ sig_mask(int sig) {
    assert(sig >= 1 && sig < NUM_SIGS);
    return 1l << (sig - 1);
}

@interface SigSet : NSObject {
@public sigset_t_ mask;
}

+ (sigset_t_) maskForSignal:(int)sig;
- (bool) empty;
- (bool) has:(int)sig;
- (void) del:(int)sig;
- (void) add:(int)sig;
- (void) clear;
- (id)initWithSigSet:(sigset_t_)mask;
- (id)init;
- (sigset_t_)getMask;
@end

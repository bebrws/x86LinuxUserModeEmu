//
//  SigInfo.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/29/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

// See signal.h from ish

#import <Foundation/Foundation.h>

#import "misc.h"

// Note that siginfo normally is a much larger data structure:
// http://man7.org/linux/man-pages/man2/sigaction.2.html
// and in the future
// TODO: Add more information to siginfo struct to help with debugging and better signal introspection
@interface SigInfo : NSObject {
    @public siginfo_ info;
}

@end

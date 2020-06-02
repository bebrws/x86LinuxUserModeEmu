//
//  AnyArgs.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/17/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>

struct exec_args {
    // number of arguments
    size_t count;
    // series of count null-terminated strings, plus an extra null for good measure
    const char *args;
};

@protocol AnyArgs <NSObject>
+ (void)test;
- (void)writeExecArgs:(struct exec_args *)ea;
- (int)getArgStringLength;
- (int)count;
@end

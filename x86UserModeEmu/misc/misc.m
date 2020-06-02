//
//  misc.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/9/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <stdio.h>
#include "misc.h"

void formatNSString(NSString *__strong *dest, void *format, ...) {
    va_list args;
    va_start(args, format);
    
    *dest = [[NSString alloc] initWithFormat:(__bridge NSString *)format arguments:args];
    
    va_end(args);
}

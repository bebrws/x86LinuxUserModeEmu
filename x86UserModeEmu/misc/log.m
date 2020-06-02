//
//  log.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/9/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <stdio.h>
#include "debug.h"

// https://stackoverflow.com/questions/3487226/is-it-possible-to-nslog-without-the-time-and-date-stamps-and-the-automatic-ne/3487232
void CleanLog (NSString *format, ...) {
    va_list args;
    va_start(args, format);
    
    //fputs([[[NSString alloc] initWithFormat:format arguments:args] UTF8String], stdout);
    fprintf(stderr, [[[NSString alloc] initWithFormat:format arguments:args] UTF8String]);
    
    va_end(args);
}

//
//  NSObject+FLLog.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/13/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import "FLLog.h"

#import <AppKit/AppKit.h>


@implementation FLL
    void _FLL(NSString *prefix, const char *file, int lineNumber, const char *funcName, NSString *format,...) {
        va_list ap;
        va_start (ap, format);
        format = [format stringByAppendingString:@"\n"];
        NSString *msg = [[NSString alloc] initWithFormat:[NSString stringWithFormat:@"%@",format] arguments:ap];
        va_end (ap);
        fprintf(stderr,"%s%50s:%3d - %s",[prefix UTF8String], funcName, lineNumber, [msg UTF8String]);
        // [msg release];
    }
@end

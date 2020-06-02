//
//  NSString+FileSystemEmu.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/19/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import "NSString+FileSystemEmu.h"

#import <AppKit/AppKit.h>


// https://stackoverflow.com/questions/1286425/nsstring-to-print-in-in-binary-format
@implementation NSString (BinaryRepresentation)

+ (NSString *)binaryStringRepresentationOfInt:(long)value
{
    const unsigned long chunkLength = 4;
    unsigned long numberOfDigits = 30;
    return [self binaryStringRepresentationOfInt:value numberOfDigits:numberOfDigits chunkLength:4];
}

+ (NSString *)binaryStringRepresentationOfInt:(long)value numberOfDigits:(unsigned long)length chunkLength:(unsigned long)chunkLength
{
    NSMutableString *string = [NSMutableString new];
    
    for(int i = 0; i < length; i ++) {
        NSString *divider = i % chunkLength == chunkLength-1 ? @" " : @"";
        NSString *part = [NSString stringWithFormat:@"%@%i", divider, value & (1 << i) ? 1 : 0];
        [string insertString:part atIndex:0];
    }
    
    return string;
}

@end

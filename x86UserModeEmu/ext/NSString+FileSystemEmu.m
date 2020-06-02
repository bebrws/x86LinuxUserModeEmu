//
//  NSString+FileSystemEmu.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/19/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import "NSString+FileSystemEmu.h"

#import <AppKit/AppKit.h>


@implementation NSString (FileSystemEmu)
- (NSString *)fixPath {
    if ([self isEqualToString:@""]) {
        return @".";
    }
    
    if ([self characterAtIndex:0] == '/') {
        return [self substringFromIndex:1];
    }
        
    return self;
}
@end

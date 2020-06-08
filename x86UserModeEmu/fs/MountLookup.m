//
//  MountLookup.m
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <stddef.h>
#import "MountLookup.h"
#import "Mount.h"
#import "log.h"

@implementation MountLookup
- (id)init {
    self = [super init];
    if (!self) {
        return nil;
    }
    
    self.mountsByPoint = [NSMutableDictionary new];
    return self;
}

- (Mount *)findMount:(NSString *)path {
    // assert(path_is_normalized(path));
    // lock on mounts
    NSArray<NSString *> *points = [self pointsInDescLength];
    
    Mount *mountFound;
    for (NSString *point in points) {
//        int pointLength = [point length];
//        
//        if ([path compare:point options:nil range:NSMakeRange(0, [point length] - 1)] && ([path characterAtIndex:pointLength] == '/' || [path characterAtIndex:pointLength] == '\0')) {
//            pointFound = point;
//            break;
//        }
        
        mountFound = [self.mountsByPoint objectForKey:point];
       
        if ([path isEqualToString:point]) {
            break;
        }
        
//        const char *utf8Path = [path UTF8String];
//        if (strncmp(utf8Path, [point UTF8String], pointLength) == 0 && (utf8Path[pointLength] == '/' || utf8Path[pointLength] == '\0')) {
//            pointFound = point;
//            break;
//        }
    }
    
    if (mountFound != nil) {
        // unlock on mounts
        return mountFound;
    } else {
        // This shouldn't happen since the root mount will always exist
        die("No mount found!");
        FFLog("No mount found while looking for path:$@. Mount list length: $@", path, [points count]);
        
        if (![points count])
            die("No root mount to default to?");
        // unlock on mounts
        return nil;
    }
}

- (NSArray<NSString *> *)pointsInDescLength {
    NSArray<NSString *> *points;
    // the list must be in descending order of mount point length
    points = [self.mountsByPoint keysSortedByValueUsingComparator: ^(NSString *obj1, NSString *obj2) {

         if ([obj1 length] > [obj2 length]) {

              return (NSComparisonResult)NSOrderedDescending;
         }
         if ([obj1 length] < [obj2 length]) {

              return (NSComparisonResult)NSOrderedAscending;
         }

         return (NSComparisonResult)NSOrderedSame;
    }];
    
    return points;
}

-(NSString *)description {
    NSMutableString *ms = [@"" mutableCopy];
    for (NSString *pk in self.mountsByPoint) {
        [ms appendFormat:@"pt:%@ - %@", pk, self.mountsByPoint[pk]];
    }
    return ms;
}

@end



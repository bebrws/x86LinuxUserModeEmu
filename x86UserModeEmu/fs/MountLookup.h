//
//  MountLookup.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//
#import <Foundation/Foundation.h>
#import "Mount.h"

#ifndef MOUNT_LOOKUP_H
#define MOUNT_LOOKUP_H

@class MountLookup;

@interface MountLookup : NSObject
@property (nonatomic, strong) NSMutableDictionary *mountsByPoint;

- (id)init;
- (Mount *)findMount:(NSString *)path;
- (NSArray<NSString *> *)pointsInDescLength;
@end

#endif

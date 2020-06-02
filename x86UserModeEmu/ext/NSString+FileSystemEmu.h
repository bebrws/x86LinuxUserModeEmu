//
//  NSString+FileSystemEmu.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/19/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <AppKit/AppKit.h>


#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSString (FileSystemEmu)
- (NSString *)fixPath;
@end

NS_ASSUME_NONNULL_END

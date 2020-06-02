//
//  SigQueue.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/29/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SigInfo.h"

@class SigInfo;

// TODO: Implement NSFastEnumaeration
// https://www.mikeash.com/pyblog/friday-qa-2010-04-16-implementing-fast-enumeration.html
// https://nshipster.com/enumerators/
@interface SigQueue : NSObject
@property (nonatomic, strong) NSMutableArray *queue; //This is an array of SigInfos

- (void)add:(SigInfo *)sigInfo;
- (void)remove:(SigInfo *)sigInfo;
- (void)removeAtIndex:(int)index;
@end

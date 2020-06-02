//
//  FRFileDescriptorOperations.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/18/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "FileDescriptorOperations.h"
#import "FileDescriptor.h"


@interface RFileDescriptorOperations : NSObject <FileDescriptorOperations>

@property (nonatomic, strong) Task *currentTask;

@end


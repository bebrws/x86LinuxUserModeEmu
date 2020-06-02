//
//  FileDescriptorAndError.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/3/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//
#import <Foundation/Foundation.h>
#import "FileDescriptor.h"

@class FileDescriptorAndError;

@interface FileDescriptorAndError : NSObject
@property(nonatomic) FileDescriptor *fileDescriptor;
@property(nonatomic, assign) int err;

- (id)init;
//- (id) initWithFD:(FileDescriptor *)fileDescriptor;
- (id)initWithError:(int)err;
@end


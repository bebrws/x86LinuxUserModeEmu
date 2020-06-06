//
//  FileDescriptorTable.h
//  x86UserModeEmu
//
//  Created by Brad Barrows on 3/17/20.
//  Copyright © 2020 bbarrows. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "FileDescriptor.h"

@interface FileDescriptorTable : NSObject {
    @public lock_t lock;
    @public bits_t *cloexec;
}

@property (nonatomic, strong) NSMutableDictionary *tbl;

- (FileDescriptor *)getFD:(fd_t)f;
- (void)setFD:(fd_t)f fd:(FileDescriptor *)fd;
- (void)closeCloExecFDs;

@end
